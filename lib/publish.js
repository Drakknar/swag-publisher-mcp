const fs = require("fs");
const path = require("path");
const { config, StepError } = require("./config");
const nginx = require("./nginx");
const authentik = require("./authentik");
const cloudflare = require("./cloudflare");
const ddns = require("./ddns");
const adguard = require("./adguard");
const access = require("./access");
const match = require("./match");
const litellm = require("./litellm");
const openwebui = require("./openwebui");
const homeassistant = require("./homeassistant");
const leftovers = require("./leftovers");

function normalizeUpstream(u) {
  if (u === undefined || u === null || u === "") {
    return null;
  }

  const s = String(u).trim();

  // The value goes into "proxy_pass <upstream>;" as is: ";", braces, quotes, "#", "$" or whitespace would let
  // it end the directive and add others (another location, root /, ...), which nginx -t happily accepts.
  if (/[\s;{}#'"`$\\]/.test(s)) {
    throw new StepError(`Upstream "${s}" contains characters that can't go into an nginx proxy_pass`);
  }

  if (/^\d+$/.test(s)) {
    if (Number(s) < 1 || Number(s) > 65535) {
      throw new StepError(`Upstream port ${s} is out of range`);
    }

    return `http://${config.lanHost}:${s}`;
  }

  if (/^https?:\/\//i.test(s)) {
    let url;

    try {
      url = new URL(s);
    } catch {
      throw new StepError(`Upstream "${s}" isn't a valid URL`);
    }

    if (!url.hostname || url.username || url.password) {
      throw new StepError(`Upstream "${s}" needs a host and no user:password`);
    }

    return s.replace(/\/+$/, "");
  }

  if (/^[\w.-]+:\d+$/.test(s)) {
    return `http://${s}`;
  }

  throw new StepError(`Upstream "${s}" isn't a port, host:port or http(s) URL`);
}

// Authentik's duration syntax: "hours=24", "days=7", "days=1;hours=12". undefined = leave as it is.
const DURATION = /^(weeks|days|hours|minutes|seconds)=\d+(;(weeks|days|hours|minutes|seconds)=\d+)*$/;

function duration(value, name) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  const s = String(value).replace(/\s+/g, "").toLowerCase();

  if (!DURATION.test(s) || !/[1-9]/.test(s)) {
    throw new StepError(`${name} "${value}" isn't an Authentik duration like "hours=24", "days=7" or "days=1;hours=12"`);
  }

  return s;
}

// OIDC callback URLs: absolute URLs without whitespace (a newline would add another redirect URI on providers
// that store them as one newline-separated string).
function redirectUrisOf(list) {
  return (list || []).map((u) => {
    const s = String(u).trim();
    let ok = !/\s/.test(s);

    try {
      ok = ok && Boolean(new URL(s).protocol);
    } catch {
      ok = false;
    }

    if (!ok) {
      throw new StepError(`redirect_uri "${s}" isn't a single absolute URL`);
    }

    return s;
  });
}

// Basic-auth passthrough with the LAN bypass: LAN visitors never get the credentials, so it's confirmed twice.
const basicWithBypass = (ctx) => Boolean(ctx.basicAuth && ctx.lanBypass);

function lineDiff(before, after) {
  const a = before.split("\n");
  const b = after.split("\n");
  const removed = a.filter((l) => !b.includes(l)).map((l) => `- ${l}`);
  const added = b.filter((l) => !a.includes(l)).map((l) => `+ ${l}`);
  return [...removed, ...added].join("\n");
}

async function step(fn) {
  try {
    return await fn();
  } catch (e) {
    if (!(e instanceof StepError)) {
      console.error(e);
    }

    return { error: e.message };
  }
}

// The app's Basic-auth login to store in Authentik: always on BASIC_AUTH_USERS, plus any named users/groups.
function credentialsOf(input) {
  const { basic_auth_username: username, basic_auth_password: password } = input;

  if (!username && !password) {
    return null;
  }

  if (!username || !password) {
    throw new StepError("Give both basic_auth_username and basic_auth_password");
  }

  const names = (list) => [...new Set((list || []).map((x) => String(x).trim()).filter(Boolean))];
  return {
    username,
    password,
    users: names([...config.basicAuthUsers, ...(input.basic_auth_users || [])]),
    groups: names(input.basic_auth_groups),
  };
}

async function buildPlan(input) {
  const sub = String(input.subdomain || "").trim().toLowerCase();

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sub)) {
    throw new StepError(`"${input.subdomain}" isn't a valid subdomain label (e.g. "spnewapp")`);
  }

  const domain = input.domain || config.domains[0];

  if (!config.domains.includes(domain)) {
    throw new StepError(`Domain must be one of: ${config.domains.join(", ")}`);
  }

  const fqdn = `${sub}.${domain}`;
  const upstream = normalizeUpstream(input.upstream);
  if (!["public", "private"].includes(input.visibility)) {
    throw new StepError("visibility must be public or private");
  }

  const attributePrefix = (s) =>
    String(s)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, "_");

  const ctx = {
    sub,
    domain,
    fqdn,
    upstream,
    auth: input.auth,
    visibility: input.visibility,
    // Only meaningful for public sites behind the Authentik proxy; private sites are LAN-only anyway.
    lanBypass: Boolean(input.lan_bypass) && input.visibility === "public" && input.auth === "authentik_proxy",
    redirectUris: redirectUrisOf(input.redirect_uris),
    // undefined = leave an existing site's setting as it is (new sites: off).
    basicAuth: input.auth === "authentik_proxy" && typeof input.basic_auth === "boolean" ? input.basic_auth : undefined,
    basicAuthPrefix: input.basic_auth_attribute_prefix ? attributePrefix(input.basic_auth_attribute_prefix) : null,
    basicAuthDefaultPrefix: attributePrefix(sub.replace(/^sp(?=.)/, "")),
    credentials: credentialsOf(input),
    appName: input.app_name ? String(input.app_name).trim() : undefined,
    // Provider token lifetimes; refresh tokens exist only for OpenID apps.
    tokenValidity: {
      access_token_validity: duration(input.access_token_validity, "access_token_validity"),
      refresh_token_validity: input.auth === "openid" ? duration(input.refresh_token_validity, "refresh_token_validity") : undefined,
    },
    // Who may use the Authentik app: undefined = leave as it is; both lists empty = every Authentik user.
    access:
      input.allowed_users !== undefined || input.allowed_groups !== undefined
        ? { users: input.allowed_users || [], groups: input.allowed_groups || [] }
        : undefined,
  };

  const notes = [
    ...(input.lan_bypass && !ctx.lanBypass ? ["lan_bypass ignored: it only applies to public sites with auth=authentik_proxy"] : []),
    ...(input.basic_auth && input.auth !== "authentik_proxy" ? ["basic_auth ignored: it only applies with auth=authentik_proxy"] : []),
    ...(ctx.access && ctx.auth === "none" ? ["allowed_users/allowed_groups ignored: auth=none has no Authentik application"] : []),
    ...(input.access_token_validity && ctx.auth === "none" ? ["access_token_validity ignored: auth=none has no Authentik provider"] : []),
    ...(input.refresh_token_validity && ctx.auth !== "openid" ? ["refresh_token_validity ignored: it only applies with auth=openid"] : []),
    ...(basicWithBypass(ctx)
      ? [
          "With lan_bypass, visitors from the home network/Tailscale skip Authentik and the conf sends an empty Authorization header, which drops the browser's own: an app that logs in with HTTP Basic can't be logged into from there at all (form/cookie logins still work).",
        ]
      : []),
  ];

  const swag = await step(async () => {
    const site = nginx.findSite(sub);

    if (!site) {
      if (!upstream) {
        throw new StepError("New site: upstream is required (port, host:port or URL)");
      }

      const text = nginx.render(ctx);
      return { action: "create", file: `${sub}.conf`, text, conf: text };
    }

    // A conf written for one domain only ("app.example.com") doesn't serve the other: DNS would point
    // at SWAG's default server.
    if (!site.hosts.some((h) => h === `${sub}.*` || h === fqdn)) {
      throw new StepError(`${site.file} serves ${site.hosts.join(" ")}, not ${fqdn}; add it to its server_name by hand first`);
    }

    const before = fs.readFileSync(path.join(config.swagConfDir, site.file), "utf-8");
    const after = nginx.edit(before, ctx);
    // The upstream, Authentik and access lines are shared by every name the conf serves.
    const others = site.hosts.filter((h) => h !== `${sub}.*` && !h.startsWith(`${sub}.`));

    if (after !== before && others.length) {
      throw new StepError(`${site.file} also serves ${others.join(", ")}, which this change would affect too; split or edit the conf by hand`);
    }

    return after === before
      ? { action: "unchanged", file: site.file, auth: site.auth, access: site.access, upstreams: site.upstreams, on_apply: "nginx -t, then reload (picks up hand edits)" }
      : { action: "update", file: site.file, text: after, diff: lineDiff(before, after) };
  });

  const plan = {
    fqdn,
    visibility: ctx.visibility,
    auth: ctx.auth,
    lan_bypass: ctx.lanBypass,
    ...(ctx.basicAuth !== undefined ? { basic_auth: ctx.basicAuth } : {}),
    ...(notes.length ? { note: notes.join(" ") } : {}),
    swag,
    authentik: await step(() => authentik.plan(ctx)),
    ...(ctx.access && ctx.auth !== "none" ? { access: await step(() => access.plan(ctx, { creating: true })) } : {}),
    cloudflare: await step(() => cloudflare.plan(fqdn, domain, ctx.visibility)),
    ddns_updater: await step(() => ddns.plan(sub, domain, ctx.visibility)),
    adguard: await step(() => adguard.plan(fqdn, domain)),
  };

  // The conf as it will be (new, edited or left alone) against the hardening rules.
  const confText = swag.text ?? (swag.file ? fs.readFileSync(path.join(config.swagConfDir, swag.file), "utf-8") : null);
  const hardening = [
    ...(confText ? nginx.hardening(confText) : []),
    ...(ctx.visibility === "public" && ctx.auth === "none"
      ? ["Public without Authentik: anyone on the internet (in the allowed countries) reaches the app's own login. Keep this for apps that can't work behind it (Plex/Emby clients); otherwise use auth=authentik_proxy or openid."]
      : []),
  ];

  if (hardening.length) {
    plan.hardening = hardening;
  }

  if (!ctx.access && plan.authentik?.action === "create") {
    plan.access_warning = "No allowed_users/allowed_groups given: every Authentik user will be able to use this app. Ask the user who should have access.";
  }

  return { ctx, plan };
}

let queue = Promise.resolve();

// One publish or removal at a time.
function serial(run) {
  const p = queue.then(run, run);
  queue = p.catch(() => {});
  return p;
}

const errorsOf = (plan) => Object.entries(plan).filter(([, v]) => v && typeof v === "object" && v.error);
// Plans are shown to the user (and the model): leave out conf bodies, ids and credentials such as the ddns entry's token.
const HIDDEN = new Set(["text", "zone", "id", "token", "password", "body", "object_permission", "source"]);
const hide = (plan) => JSON.parse(JSON.stringify(plan, (k, v) => (HIDDEN.has(k) ? undefined : v)));

// Plans, and with apply=true carries the plan out.
function publish(input) {
  return serial(async () => {
    const { ctx, plan } = await buildPlan(input);
    const errors = errorsOf(plan);
    const view = hide(plan);

    if (!input.apply) {
      return {
        applied: false,
        plan: view,
        ...(errors.length ? { blocked_by: errors.map(([k, v]) => `${k}: ${v.error}`) } : {}),
        next: errors.length
          ? "Fix the errors above before applying."
          : basicWithBypass(ctx)
            ? "Show this plan to the user and ask explicitly whether they really want lan_bypass with basic_auth (see note; lan_bypass=false is usually more convenient). Only after they confirm both, call publish_site again with the same arguments and apply=true."
            : "Show this plan to the user (point out any hardening warnings and offer to fix them first). Only after they confirm, call publish_site again with the same arguments and apply=true.",
      };
    }

    if (errors.length) {
      throw new StepError(`Not applied, the plan has errors: ${errors.map(([k, v]) => `${k}: ${v.error}`).join(" | ")}`);
    }

    const result = { fqdn: ctx.fqdn, applied: true };
    // Authentik first, so the outpost knows the host before nginx starts sending it there. Turning Basic
    // auth off goes the other way: the provider stops sending credentials only once nginx no longer
    // forwards them, so a rejected conf leaves both as they were.
    const basicOff = plan.authentik?.action === "update" && plan.authentik.basic_auth?.basic_auth_enabled === false;

    // Access right after Authentik, so a new application is never open to everyone while the rest runs.
    const applyAuthentik = async () => {
      result.authentik = await step(() => authentik.apply(plan.authentik, ctx));

      if (plan.access) {
        result.access = result.authentik.error ? { skipped: "Authentik step failed" } : await step(() => access.apply(plan.access, ctx));
      }
    };

    if (!basicOff) {
      await applyAuthentik();
    }

    result.swag = await step(async () =>
      plan.swag.action === "unchanged"
        ? { ...plan.swag, ...(await nginx.reload()) }
        : { action: plan.swag.action, ...(await nginx.apply(plan.swag.file, plan.swag.text)) },
    );

    if (result.swag.error) {
      result.stopped = `SWAG config failed, ${basicOff ? "Authentik and " : ""}DNS steps skipped.`;
      return result;
    }

    if (basicOff) {
      await applyAuthentik();
    }

    // Going private: drop the ddns entry first, or its restart would put the public IP back.
    if (ctx.visibility === "private") {
      result.ddns_updater = await step(() => ddns.apply(plan.ddns_updater));
      result.cloudflare = await step(() => cloudflare.apply(plan.cloudflare));
    } else {
      result.cloudflare = await step(() => cloudflare.apply(plan.cloudflare));
      result.ddns_updater = await step(() => ddns.apply(plan.ddns_updater));
    }

    result.adguard = await step(() => adguard.apply(plan.adguard));
    result.url = `https://${ctx.fqdn}`;
    return result;
  });
}

// Undoes a site everywhere: nginx conf, Cloudflare records, ddns entries and exact AdGuard rewrites in
// every configured domain (the conf answers "<sub>.*" on all of them), its Authentik app/provider (plus
// Basic-auth attributes and users/groups that only existed for it), LiteLLM MCP servers/models/keys and
// Open WebUI connections pointing at it. Container, template, appdata and Home Assistant are only reported.
// The upstreams of a conf that is already gone (a re-run after a partial failure), from its newest backup.
function upstreamsFromBackup(sub) {
  try {
    // Newest first by the timestamp suffix, whatever the conf file was called.
    const stamp = (f) => f.match(/\.conf\.(\d{4}-.*)$/)[1];
    const files = fs
      .readdirSync(config.backupDir)
      .filter((f) => /\.conf\.\d{4}-/.test(f))
      .sort((a, b) => stamp(b).localeCompare(stamp(a)));

    for (const f of files) {
      const info = nginx.describe(f, fs.readFileSync(path.join(config.backupDir, f), "utf-8"));

      if (info.hosts.some((h) => h === `${sub}.*` || h.startsWith(`${sub}.`))) {
        return { file: f, upstreams: info.upstreams };
      }
    }
  } catch {
    // No backup folder yet.
  }

  return null;
}

function removeSite(input) {
  return serial(async () => {
    const sub = String(input.subdomain || "").trim().toLowerCase();

    // Same rule as publish_site: a bare label. "*" would match wildcard DNS records and rewrites.
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sub)) {
      throw new StepError(`"${input.subdomain}" isn't a valid subdomain (letters, digits and inner hyphens only)`);
    }

    const site = nginx.findSite(sub);
    const keep = (input.keep || []).map(String);
    const integrations = input.remove_integrations === true;
    const plan = { subdomain: sub };
    const fromBackup = site || input.upstream ? null : upstreamsFromBackup(sub);
    const upstreams = [
      ...new Set([...(site?.upstreams || []), ...(fromBackup?.upstreams || []), ...(input.upstream ? [normalizeUpstream(input.upstream)] : [])]),
    ];

    plan.swag = await step(async () => {
      if (!site) {
        return { action: "none" };
      }

      const others = site.hosts.filter((h) => h !== `${sub}.*` && !h.startsWith(`${sub}.`));

      if (others.length) {
        throw new StepError(`${site.file} also serves ${others.join(", ")}; remove those names by hand first`);
      }

      return { action: "remove", file: site.file, upstreams: site.upstreams };
    });

    for (const domain of config.domains) {
      const fqdn = `${sub}.${domain}`;
      plan[fqdn] = {
        authentik: await step(() => authentik.planRemove({ sub, domain, fqdn })),
        cloudflare: await step(() => cloudflare.planRemove(fqdn, domain)),
        ddns_updater: await step(() => ddns.planRemove(sub, domain)),
        adguard: await step(() => adguard.planRemove(fqdn)),
      };
    }

    // Both domains can lead to the same Authentik app or provider; each is removed (with its orphans) only once.
    const seenApps = new Set();
    const seenProviders = new Set();

    for (const d of config.domains) {
      const a = plan[`${sub}.${d}`].authentik;

      if (a?.action !== "remove") {
        continue;
      }

      if (seenApps.has(a.application)) {
        a.application = null;
        delete a.orphans;
      }

      a.providers = a.providers.filter((pk) => !seenProviders.has(pk));
      a.providers.forEach((pk) => seenProviders.add(pk));
      if (a.application) {
        seenApps.add(a.application);
      }

      if (!a.application && !a.providers.length) {
        plan[`${sub}.${d}`].authentik = { action: "none", note: "same application as the other domain" };
      }
    }

    // Basic-auth attributes once, for every provider being removed on any domain.
    const firstAuth = config.domains.map((d) => plan[`${sub}.${d}`].authentik).find((a) => a?.action === "remove");

    if (firstAuth && seenProviders.size) {
      const basicAuth = await step(() => authentik.planBasicAuthRemove([...seenProviders]));

      if (basicAuth?.error) {
        plan.authentik_basic_auth = basicAuth;
      } else if (basicAuth) {
        firstAuth.basic_auth = basicAuth;
      }
    }

    // "spopencode" -> "opencode": the app's own name, used for LiteLLM key aliases and container names.
    const bare = sub.replace(/^sp(?=.{3})/, "");
    const appNames = config.domains.map((d) => plan[`${sub}.${d}`].authentik?.name).filter(Boolean);
    const m = match.matcher({
      upstreams,
      fqdns: config.domains.map((d) => `${sub}.${d}`),
      names: [sub, bare, ...appNames],
    });
    plan.matching = { ...m.describe, ...(fromBackup ? { upstreams_from_backup: fromBackup.file } : {}) };
    const lite = await step(() => litellm.planRemove(m, keep));
    const owui = await step(() => openwebui.planRemove(m, lite.mcp_servers || []));
    // Report only: never blocks or changes anything.
    plan.check_by_hand = {
      leftovers: await step(() => leftovers.scan({ site, upstreams, containerNames: [bare] })),
      home_assistant: await step(() => homeassistant.scan(m)),
    };

    // Unpublishing a site doesn't mean the app is gone (HA, LiteLLM itself, Nextcloud keep running), so its
    // LiteLLM/Open WebUI integrations are only listed unless the caller says the app itself was removed.
    if (integrations) {
      plan.litellm = lite;
      plan.openwebui = owui;
    } else {
      plan.litellm = { action: "none" };
      plan.openwebui = { action: "none" };

      if (lite.action === "remove" || owui.action === "remove" || lite.warnings) {
        plan.check_by_hand.integrations = {
          litellm: lite,
          openwebui: owui,
          note: "Not removed: only pass remove_integrations=true if the app itself is gone (container removed), not just its reverse-proxy site.",
        };
      }
    }

    const errors = [...errorsOf(plan), ...config.domains.flatMap((d) => errorsOf(plan[`${sub}.${d}`]).map(([k, v]) => [`${sub}.${d} ${k}`, v]))];

    if (!input.apply) {
      return {
        applied: false,
        plan: hide(plan),
        ...(errors.length ? { blocked_by: errors.map(([k, v]) => `${k}: ${v.error}`) } : {}),
        next: errors.length
          ? "Fix the errors above before applying."
          : "Show this plan to the user, including check_by_hand. If check_by_hand.integrations lists LiteLLM/Open WebUI entries, ask whether the app itself is gone (then plan again with remove_integrations=true) or only its site. Only after they confirm, call remove_site again with the same arguments plus apply=true (and keep=[labels] for anything they want to leave).",
      };
    }

    if (errors.length) {
      throw new StepError(`Not applied, the plan has errors: ${errors.map(([k, v]) => `${k}: ${v.error}`).join(" | ")}`);
    }

    const result = { subdomain: sub, applied: true };
    // nginx first: once the conf is gone nothing routes to the app, whatever happens to DNS later.
    result.swag = await step(async () => (plan.swag.action === "remove" ? { action: "removed", ...(await nginx.remove(plan.swag.file)) } : plan.swag));

    if (result.swag.error) {
      result.stopped = "SWAG step failed, nothing else removed.";
      return result;
    }

    for (const domain of config.domains) {
      const fqdn = `${sub}.${domain}`;
      const p = plan[fqdn];
      result[fqdn] = {
        ddns_updater: await step(() => ddns.apply(p.ddns_updater)),
        cloudflare: await step(() => cloudflare.applyRemove(p.cloudflare)),
        adguard: await step(() => adguard.applyRemove(p.adguard)),
        authentik: await step(() => authentik.applyRemove(p.authentik, keep)),
      };
    }

    // Open WebUI before LiteLLM: its connections point at LiteLLM's per-server URLs.
    result.openwebui = await step(() => openwebui.applyRemove(plan.openwebui, keep));
    result.litellm = await step(() => litellm.applyRemove(plan.litellm, keep));
    result.check_by_hand = hide(plan.check_by_hand);

    const failed = JSON.stringify(result).includes('"error":');

    if (failed) {
      result.rerun = "Some steps failed (see error). Fix the cause and call remove_site again with the same arguments: done steps are skipped, and the upstream is recovered from the conf backup.";
    }

    return result;
  });
}

module.exports = { publish, removeSite, normalizeUpstream, serial };
