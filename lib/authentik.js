const { config, StepError } = require("./config");
const { request } = require("./http");

async function ak(path, opts = {}) {
  if (!config.authentikToken) {
    throw new StepError("AUTHENTIK_TOKEN is not set on the container");
  }

  return request("Authentik", `${config.authentikUrl}/api/v3${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${config.authentikToken}` },
  });
}

// Every page: a truncated list would hide bindings, users or providers (and make users look like orphans).
async function all(path) {
  const out = [];

  for (let page = 1; page <= 200; page++) {
    const data = await ak(`${path}${path.includes("?") ? "&" : "?"}page_size=500&page=${page}`);
    out.push(...(data?.results || []));
    const next = Number(data?.pagination?.next || 0);

    if (!next || next <= page) {
      break;
    }
  }

  return out;
}
// Authentik's ?search= doesn't look at external_host, so proxy providers are matched on it here.
const proxyProvidersFor = async (fqdn) =>
  (await all("/providers/proxy/")).filter((p) => p.external_host?.replace(/\/+$/, "") === `https://${fqdn}`);
// Slug of the applications this tool made before v0.4 ("<sub>-<tld>"); still used to find them.
const slugOf = (sub, domain) => `${sub}-${domain.split(".").pop()}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
// Naming like the applications set up by hand: application and provider share the display name
// ("AdGuard Home", "Paperless-ngx", "SPMusic"), the slug is that name in lowercase with hyphens.
const slugify = (name) =>
  String(name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
// Without a name, own services get "SP<Name>" like SPGT/SPHome/SPMusic: "spopencode" -> "SPOpencode".
const defaultName = (sub) => (/^sp[a-z0-9]/.test(sub) ? `SP${sub[2].toUpperCase()}${sub.slice(3)}` : `${sub[0].toUpperCase()}${sub.slice(1)}`);

const IMPLICIT_CONSENT = "default-provider-authorization-implicit-consent";

// The invalidation flow, mappings and signing key are copied from an existing provider of the same kind, so new
// apps behave like the ones already set up; Authentik's defaults are the fallback.
async function defaults(kind) {
  // /providers/oauth2/ also lists the proxy providers (a kind of OAuth2 provider in Authentik): never copy
  // those into an OIDC app (no signing key = HS256 tokens, proxy-only mappings). Prefer one with a signing key.
  const proxies = kind === "oauth2" ? new Set((await all("/providers/proxy/")).map((p) => p.pk)) : null;
  const [tpl] = (await all(`/providers/${kind}/`))
    .filter((p) => (kind === "proxy" ? p.mode === "forward_single" : !proxies.has(p.pk)))
    .sort((a, b) => (kind === "oauth2" ? Number(Boolean(b.signing_key)) - Number(Boolean(a.signing_key)) : 0));
  const flow = async (slug) => (await all(`/flows/instances/?slug=${slug}`))[0]?.pk;
  const d = {
    // Always implicit consent (no "allow this app?" screen), like every provider set up so far.
    authorization_flow: await flow(IMPLICIT_CONSENT),
    invalidation_flow: tpl?.invalidation_flow || (await flow("default-provider-invalidation-flow")),
    property_mappings: tpl?.property_mappings,
    template: tpl?.name || null,
  };

  if (kind === "oauth2") {
    if (!d.property_mappings?.length) {
      const wanted = ["openid", "email", "profile"].map((s) => `goauthentik.io/providers/oauth2/scope-${s}`);
      d.property_mappings = (await all("/propertymappings/provider/scope/")).filter((m) => wanted.includes(m.managed)).map((m) => m.pk);
    }

    d.signing_key = tpl?.signing_key || (await all("/crypto/certificatekeypairs/?has_key=true"))[0]?.pk;
    d.redirectShape = tpl ? (typeof tpl.redirect_uris === "string" ? "string" : "list") : "list";
  }

  if (!d.authorization_flow) {
    throw new StepError(`Authentik flow "${IMPLICIT_CONSENT}" not found; new providers must use implicit consent`);
  }

  return d;
}

const hostOf = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
};

// The site's application: "<sub>-<tld>" for ones this tool made, else the proxy provider's application,
// else one whose launch URL is the site (apps set up by hand, e.g. "nextcloud" for spnc).
async function findApplication({ sub, domain, fqdn, application }) {
  if (application) {
    const app = await findApp(application);

    if (!app) {
      throw new StepError(`Authentik application "${application}" not found`);
    }

    return app;
  }

  const bySlug = await findApp(slugOf(sub, domain));

  if (bySlug) {
    return bySlug;
  }

  const [proxy] = await proxyProvidersFor(fqdn);

  if (proxy?.assigned_application_slug) {
    return findApp(proxy.assigned_application_slug);
  }

  // OpenID apps set up by hand have no launch URL, but their redirect URIs name the site.
  const redirectsTo = (p) =>
    (typeof p.redirect_uris === "string" ? p.redirect_uris.split("\n") : (p.redirect_uris || []).map((r) => r.url)).some((u) => hostOf(u) === fqdn);
  const oidc = (await all("/providers/oauth2/")).find((p) => p.assigned_application_slug && redirectsTo(p));

  if (oidc) {
    return findApp(oidc.assigned_application_slug);
  }

  return (await all(APPS)).find((a) => hostOf(a.meta_launch_url) === fqdn) || null;
}

const providerKind = (app) => {
  const model = app?.provider_obj?.meta_model_name || "";
  return model.includes("proxy") ? "proxy" : model.includes("oauth2") ? "oauth2" : model || null;
};

const SUBJECT = {
  hashed_user_id: "hashed user ID, not the username: let the app match existing users by preferred_username or email",
  user_id: "Authentik user ID (number)",
  user_uuid: "Authentik user UUID",
  user_username: "username",
  user_email: "email address",
  user_upn: "UPN attribute (falls back to the hashed user ID)",
};

// Only what a web login needs (user rule, 2026-10-14). Newer Authentik creates providers with no grant types at
// all and then rejects every login with "invalid_request: The request is otherwise malformed"; the others
// (password, client_credentials, implicit, hybrid, device_code) would let tokens be had without the login flow.
const OIDC_GRANTS = ["authorization_code", "refresh_token"];
const sameGrants = (g) => (g || []).length === OIDC_GRANTS.length && OIDC_GRANTS.every((x) => g.includes(x));

// Everything an app's SSO settings may ask for. URLs follow Authentik's per-provider issuer layout.
async function oidcInfo(provider, appSlug, { secret = false } = {}) {
  const base = config.authentikPublicUrl;
  const issuer = provider.issuer_mode === "global" ? `${base}/` : `${base}/application/o/${appSlug}/`;
  const scopeOf = new Map((await all("/propertymappings/provider/scope/")).map((m) => [m.pk, m.scope_name]));
  const scopes = [...new Set((provider.property_mappings || []).map((pk) => scopeOf.get(pk)).filter(Boolean))];
  const redirects =
    typeof provider.redirect_uris === "string" ? provider.redirect_uris.split("\n").filter(Boolean) : (provider.redirect_uris || []).map((r) => r.url);

  return {
    client_id: provider.client_id,
    ...(secret ? { client_secret: provider.client_secret } : {}),
    issuer,
    discovery_url: `${base}/application/o/${appSlug}/.well-known/openid-configuration`,
    authorization_endpoint: `${base}/application/o/authorize/`,
    token_endpoint: `${base}/application/o/token/`,
    userinfo_endpoint: `${base}/application/o/userinfo/`,
    end_session_endpoint: `${base}/application/o/${appSlug}/end-session/`,
    jwks_uri: `${base}/application/o/${appSlug}/jwks/`,
    redirect_uris: redirects,
    scopes: (scopes.includes("openid") ? scopes : ["openid", ...scopes]).join(" "),
    username_claim: "preferred_username",
    email_claim: "email",
    groups_claim: scopes.includes("profile") ? "groups (in the profile scope)" : "none",
    subject: `${provider.sub_mode}: ${SUBJECT[provider.sub_mode] || "see Authentik"}`,
    id_token_signing_alg: provider.signing_key ? "RS256" : "HS256 (signed with the client secret; no signing key set)",
    client_authentication: "client_secret_basic or client_secret_post",
    client_type: provider.client_type,
    pkce: "supported (S256), optional",
    access_token_validity: provider.access_token_validity,
    refresh_token_validity: provider.refresh_token_validity,
    grant_types: provider.grant_types || [],
    ...(sameGrants(provider.grant_types)
      ? {}
      : {
          grant_types_warning: `should be exactly ${OIDC_GRANTS.join(", ")}; publish_site for this site (its current visibility, auth=openid) plans the fix`,
        }),
  };
}

// superuser_full_list: without it Authentik lists only the applications the API user may use itself,
// so apps restricted to other groups would look missing.
const APPS = "/core/applications/?superuser_full_list=true";

async function findApp(slug) {
  return (await all(`${APPS}&slug=${encodeURIComponent(slug)}`)).find((a) => a.slug === slug) || null;
}

// The provider's "Send HTTP-Basic Authentication" fields, or null when the caller didn't ask for a change.
// Credentials come from the user/group attributes "<prefix>_username" and "<prefix>_password",
// the same scheme as the AdGuard (adguard_*) and Resilio (resilio_*) providers. Without an explicit
// prefix, a provider that already names its attributes keeps them.
function basicAuthFields({ basicAuth, basicAuthPrefix, basicAuthDefaultPrefix }, provider) {
  if (basicAuth === undefined) {
    return null;
  }

  if (!basicAuth) {
    return { basic_auth_enabled: false };
  }

  if (!basicAuthPrefix && provider?.basic_auth_user_attribute && provider?.basic_auth_password_attribute) {
    return {
      basic_auth_enabled: true,
      basic_auth_user_attribute: provider.basic_auth_user_attribute,
      basic_auth_password_attribute: provider.basic_auth_password_attribute,
    };
  }

  const prefix = basicAuthPrefix || basicAuthDefaultPrefix;
  return {
    basic_auth_enabled: true,
    basic_auth_user_attribute: `${prefix}_username`,
    basic_auth_password_attribute: `${prefix}_password`,
  };
}

const basicAuthDiffers = (provider, fields) => fields && Object.entries(fields).some(([k, v]) => provider[k] !== v);

// Token lifetimes, in Authentik's duration syntax ("hours=24", "days=7;hours=12"). On a proxy provider
// access_token_validity is how long the Authentik login lasts before it's asked again; long WebSocket sessions
// (Foundry) drop when it runs out. OpenID apps also use refresh_token_validity (how long the app stays signed in).
const VALIDITY_FIELDS = { proxy: ["access_token_validity"], oauth2: ["access_token_validity", "refresh_token_validity"] };

// The requested lifetimes that differ from the provider's, as { field: { from, to } }; null when none.
function validityPlan(ctx, kind, provider) {
  const entries = VALIDITY_FIELDS[kind]
    .filter((k) => ctx.tokenValidity?.[k] !== undefined && provider?.[k] !== ctx.tokenValidity[k])
    .map((k) => [k, { from: provider?.[k] ?? "Authentik default", to: ctx.tokenValidity[k] }]);
  return entries.length ? Object.fromEntries(entries) : null;
}

const validityBody = (tv) => Object.fromEntries(Object.entries(tv || {}).map(([k, v]) => [k, v.to]));
// The provider fields a plan changes: Basic auth, grant types, token lifetimes.
const providerChanges = (p) => ({ ...(p.basic_auth || {}), ...(p.grant_types ? { grant_types: p.grant_types.to } : {}), ...validityBody(p.token_validity) });

// Authentik validates a proxy PATCH as if mode were the default (proxy, which needs internal_host) unless mode is sent,
// so the provider's current mode goes along with every change.
async function patchProvider(kind, pk, body) {
  const extra = kind === "proxy" ? { mode: (await ak(`/providers/proxy/${pk}/`)).mode } : {};
  return ak(`/providers/${kind}/${pk}/`, { method: "PATCH", body: { ...extra, ...body } });
}

function basicAuthNote(fields) {
  return fields?.basic_auth_enabled
    ? `Set the attributes "${fields.basic_auth_user_attribute}" and "${fields.basic_auth_password_attribute}" (the app's login) on the users or group allowed in, in Authentik.`
    : undefined;
}

// Where the app's login is stored: the attribute names the provider reads, on each named user and group.
// The password itself never goes into the plan; apply takes it from the call's arguments.
async function credentialsPlan(ctx, fields, provider) {
  const c = ctx.credentials;

  if (!c) {
    return null;
  }

  const enabled = fields ? fields.basic_auth_enabled : provider?.basic_auth_enabled;

  if (!enabled) {
    throw new StepError("basic_auth_username/password need Basic auth on this site: pass basic_auth=true");
  }

  const userAttribute = fields?.basic_auth_user_attribute || provider.basic_auth_user_attribute;
  const passwordAttribute = fields?.basic_auth_password_attribute || provider.basic_auth_password_attribute;
  const users = [];
  const groups = [];

  for (const name of c.users) {
    const u = (await all(`/core/users/?username=${encodeURIComponent(name)}`)).find((x) => x.username === name);

    if (!u) {
      throw new StepError(`Authentik user "${name}" not found`);
    }

    users.push({ pk: u.pk, username: u.username });
  }

  for (const name of c.groups) {
    const g = (await all(`/core/groups/?name=${encodeURIComponent(name)}`)).find((x) => x.name === name);

    if (!g) {
      throw new StepError(`Authentik group "${name}" not found`);
    }

    groups.push({ pk: g.pk, name: g.name });
  }

  return { username: c.username, user_attribute: userAttribute, password_attribute: passwordAttribute, users, groups };
}

// Merges the two attributes into each user's/group's existing attributes (PATCH replaces the whole dict).
async function writeCredentials(p, password) {
  const values = { [p.user_attribute]: p.username, [p.password_attribute]: password };
  const targets = [...p.users.map((u) => ["users", u.pk, `user ${u.username}`]), ...p.groups.map((g) => ["groups", g.pk, `group ${g.name}`])];

  for (const [kind, pk] of targets) {
    const current = await ak(`/core/${kind}/${pk}/`);
    await ak(`/core/${kind}/${pk}/`, { method: "PATCH", body: { attributes: { ...(current.attributes || {}), ...values } } });
  }

  return {
    set: [p.user_attribute, p.password_attribute],
    on: targets.map((t) => t[2]),
    next_step: "Users already logged in must sign out of Authentik once (…/outpost.goauthentik.io/sign_out) to pick up the new login.",
  };
}

async function plan(ctx) {
  const { credentials, ...p } = await planApp(ctx);

  if (credentials) {
    return { ...p, credentials };
  }

  // auth=none/openid: credentials can't apply, and credentialsPlan says why.
  return ctx.credentials && credentials === undefined ? { ...p, credentials: await credentialsPlan(ctx, null, null) } : p;
}

// A new application's name and slug; the slug must not belong to another application.
async function newName(ctx) {
  const name = ctx.appName || defaultName(ctx.sub);
  const slug = slugify(name);

  if (!slug) {
    throw new StepError(`app_name "${name}" gives an empty slug`);
  }

  if (await findApp(slug)) {
    throw new StepError(`An Authentik application with slug "${slug}" already exists for another site; choose another app_name`);
  }

  return { name, slug };
}

async function planApp(ctx) {
  const { fqdn, auth, redirectUris } = ctx;

  if (auth === "none") {
    // Switching protection off leaves Authentik's objects alone; say so, so they can be cleaned up.
    const app = config.authentikToken ? await findApplication(ctx) : null;
    return app ? { action: "none", note: `Authentik application "${app.slug}" still exists and is left unchanged.` } : { action: "none" };
  }

  const app = await findApplication(ctx);

  if (auth === "authentik_proxy") {
    if (app && providerKind(app) !== "proxy") {
      throw new StepError(`This site already has the Authentik application "${app.name}" (${providerKind(app) || "no"} provider); switch it to the proxy by hand, or use auth=openid.`);
    }

    const [provider] = await proxyProvidersFor(fqdn);

    // The application's own provider must be the one for this host; otherwise apply would create (or update and
    // attach) a provider the application doesn't use.
    if (app && (!provider || provider.pk !== app.provider)) {
      throw new StepError(
        provider
          ? `Authentik application "${app.slug}" uses provider ${app.provider}, but the proxy provider for https://${fqdn} is "${provider.name}" (${provider.assigned_application_slug || "no application"}); fix it in Authentik by hand.`
          : `Authentik application "${app.slug}" has a proxy provider whose external host isn't https://${fqdn}; fix the external host in Authentik by hand.`,
      );
    }

    const outpost = await embeddedOutpost();
    const attached = provider ? outpost.providers.includes(provider.pk) : false;
    const basic = basicAuthFields(ctx, provider);
    const credentials = await credentialsPlan(ctx, basic, provider);
    // With credentials given, the tool sets the attributes itself.
    const note = credentials ? undefined : basicAuthNote(basic);
    const validity = validityPlan(ctx, "proxy", provider);

    if (provider && app && attached) {
      const basicChange = basicAuthDiffers(provider, basic);
      return basicChange || validity
        ? {
            action: "update",
            kind: "proxy",
            provider: provider.pk,
            provider_name: provider.name,
            application: app.slug,
            ...(basicChange ? { basic_auth: basic } : {}),
            ...(validity ? { token_validity: validity } : {}),
            ...(note ? { note } : {}),
            credentials,
          }
        : {
            action: "exists",
            kind: "proxy",
            provider: provider.name,
            application: app.slug,
            basic_auth: provider.basic_auth_enabled,
            access_token_validity: provider.access_token_validity,
            credentials,
          };
    }

    return {
      action: "create",
      kind: "proxy",
      ...(app ? { slug: app.slug, name: app.name } : await newName(ctx)),
      provider: provider?.pk || null,
      application: app?.slug || null,
      outpost: outpost.name,
      ...(basic ? { basic_auth: basic } : {}),
      ...(validity ? { token_validity: validity } : {}),
      ...(note ? { note } : {}),
      credentials,
    };
  }

  const existing = app;

  if (existing) {
    if (providerKind(existing) !== "oauth2") {
      throw new StepError(`Authentik application "${existing.slug}" uses a ${providerKind(existing) || "missing"} provider, not OpenID; change it in Authentik by hand.`);
    }

    const provider = await ak(`/providers/oauth2/${existing.provider}/`);
    const oidc = await oidcInfo(provider, existing.slug);
    const missing = (redirectUris || []).filter((u) => !oidc.redirect_uris.includes(u));
    const redirectNote = missing.length
      ? ` These redirect_uris are NOT on the provider and were not added: ${missing.join(", ")}; add them in Authentik if the app needs them.`
      : "";

    const grants = sameGrants(provider.grant_types) ? null : { from: provider.grant_types || [], to: OIDC_GRANTS };
    const validity = validityPlan(ctx, "oauth2", provider);

    if (grants || validity) {
      return {
        action: "update",
        kind: "oauth2",
        provider: provider.pk,
        provider_name: provider.name,
        application: existing.slug,
        ...(grants ? { grant_types: grants } : {}),
        ...(validity ? { token_validity: validity } : {}),
        oidc,
        note: "Only the settings listed here change on the provider; everything else is left as it is." + redirectNote,
      };
    }

    return {
      action: "exists",
      kind: "oauth2",
      application: existing.slug,
      oidc,
      note:
        "Application already exists; its provider was left unchanged. The client secret is shown by get_site with show_secret=true." + redirectNote,
    };
  }

  if (!redirectUris?.length) {
    throw new StepError("auth=openid needs redirect_uris: the callback URL(s) from the app's OIDC setup docs");
  }

  const validity = validityPlan(ctx, "oauth2", null);
  return { action: "create", kind: "oauth2", ...(await newName(ctx)), redirectUris, ...(validity ? { token_validity: validity } : {}) };
}

async function embeddedOutpost() {
  const outposts = await all("/outposts/instances/");
  const o = outposts.find((x) => x.managed === "goauthentik.io/outposts/embedded") || outposts.find((x) => x.type === "proxy");

  if (!o) {
    throw new StepError("No Authentik proxy outpost found");
  }

  return o;
}

async function apply(p, ctx) {
  const result = await applyApp(p, ctx);

  if (!p.credentials) {
    return result;
  }

  return { ...result, credentials: await writeCredentials(p.credentials, ctx.credentials.password) };
}

async function applyApp(p, { sub, fqdn }) {
  // Proxy or OpenID: only the fields the plan lists.
  if (p.action === "update") {
    await patchProvider(p.kind, p.provider, providerChanges(p));
    const { action, provider, provider_name, oidc, credentials, ...changed } = p;
    return { ...changed, action: "updated", provider: provider_name };
  }

  if (p.action !== "create") {
    return p;
  }

  if (p.kind === "proxy") {
    const d = await defaults("proxy");
    let pk = p.provider;

    if (!pk) {
      const created = await ak("/providers/proxy/", {
        method: "POST",
        body: {
          name: p.name,
          authorization_flow: d.authorization_flow,
          ...(d.invalidation_flow ? { invalidation_flow: d.invalidation_flow } : {}),
          ...(d.property_mappings ? { property_mappings: d.property_mappings } : {}),
          external_host: `https://${fqdn}`,
          mode: "forward_single",
          ...providerChanges(p),
        },
      });
      pk = created.pk;
    } else if (p.basic_auth || p.token_validity) {
      await patchProvider("proxy", pk, providerChanges(p));
    }

    if (!p.application) {
      await ak("/core/applications/", { method: "POST", body: { name: p.name, slug: p.slug, provider: pk, meta_launch_url: `https://${fqdn}` } });
    }

    const outpost = await embeddedOutpost();

    if (!outpost.providers.includes(pk)) {
      await ak(`/outposts/instances/${outpost.pk}/`, { method: "PATCH", body: { providers: [...outpost.providers, pk] } });
    }

    return {
      action: "created",
      kind: "proxy",
      application: p.application || p.slug,
      copied_settings_from: d.template,
      outpost: outpost.name,
      ...(p.basic_auth ? { basic_auth: p.basic_auth } : {}),
      ...(p.token_validity ? { token_validity: p.token_validity } : {}),
      ...(p.note ? { note: p.note } : {}),
    };
  }

  const d = await defaults("oauth2");
  const redirect_uris =
    d.redirectShape === "string" ? p.redirectUris.join("\n") : p.redirectUris.map((url) => ({ matching_mode: "strict", url }));
  const provider = await ak("/providers/oauth2/", {
    method: "POST",
    body: {
      name: p.name,
      authorization_flow: d.authorization_flow,
      ...(d.invalidation_flow ? { invalidation_flow: d.invalidation_flow } : {}),
      client_type: "confidential",
      grant_types: OIDC_GRANTS,
      redirect_uris,
      property_mappings: d.property_mappings,
      ...(d.signing_key ? { signing_key: d.signing_key } : {}),
      ...validityBody(p.token_validity),
    },
  });
  await ak("/core/applications/", { method: "POST", body: { name: p.name, slug: p.slug, provider: provider.pk, meta_launch_url: `https://${fqdn}` } });

  return {
    action: "created",
    kind: "oauth2",
    application: p.slug,
    copied_settings_from: d.template,
    oidc: await oidcInfo(provider, p.slug, { secret: true }),
    next_step:
      "Enter client_id, client_secret and the discovery URL (or the single endpoints, for apps without discovery) in the app's OIDC settings; request the listed scopes and use preferred_username as the username claim.",
  };
}

// The application (slug "<sub>-<tld>") and its provider, plus any proxy provider for the host.
async function planRemove({ sub, domain, fqdn }) {
  if (!config.authentikToken) {
    return { action: "skipped", reason: "AUTHENTIK_TOKEN not set" };
  }

  const app = await findApplication({ sub, domain, fqdn });
  const proxies = await proxyProvidersFor(fqdn);
  const providers = [...new Set([...(app?.provider ? [app.provider] : []), ...proxies.map((p) => p.pk)])];

  if (!app && !providers.length) {
    return { action: "none" };
  }

  // Basic-auth attributes are planned once for all domains by removeSite (planBasicAuthRemove): another
  // domain's provider that is being removed too must not count as still using them.
  const byHand = app && app.slug !== slugOf(sub, domain) && !app.meta_launch_url;
  const orphans = app ? await planOrphans(app) : null;
  return {
    action: "remove",
    application: app?.slug || null,
    ...(app ? { name: app.name } : {}),
    providers,
    ...(orphans ? { orphans } : {}),
    ...(byHand ? { warning: `"${app.name}" was set up by hand in Authentik; removing the site deletes it and its provider too (the app loses its SSO login). Make sure the user wants that.` } : {}),
  };
}

const basicAuthKeys = (p) => (p.basic_auth_enabled ? [p.basic_auth_user_attribute, p.basic_auth_password_attribute].filter(Boolean) : []);

// The Basic-auth login attributes of the providers being removed, and the users/groups holding them.
// Attribute names another remaining provider still sends are kept.
async function planBasicAuthRemove(removing) {
  const proxies = await all("/providers/proxy/");
  const kept = new Set(proxies.filter((p) => !removing.includes(p.pk)).flatMap(basicAuthKeys));
  const attributes = [...new Set(proxies.filter((p) => removing.includes(p.pk)).flatMap(basicAuthKeys))].filter((k) => !kept.has(k));

  if (!attributes.length) {
    return null;
  }

  const holders = [];

  for (const [kind, label, nameOf] of [["users", "user", (o) => o.username], ["groups", "group", (o) => o.name]]) {
    for (const o of await all(`/core/${kind}/`)) {
      if (attributes.some((k) => k in (o.attributes || {}))) {
        holders.push({ kind, pk: o.pk, label: `${label} ${nameOf(o)}` });
      }
    }
  }

  return holders.length ? { attributes, from: holders } : null;
}

// Deletes the attributes from each holder (re-read first: PATCH replaces the whole dict).
async function applyBasicAuthRemove(p) {
  for (const h of p.from) {
    const current = { ...((await ak(`/core/${h.kind}/${h.pk}/`)).attributes || {}) };
    p.attributes.forEach((k) => delete current[k]);
    await ak(`/core/${h.kind}/${h.pk}/`, { method: "PATCH", body: { attributes: current } });
  }

  return { removed: p.attributes, from: p.from.map((h) => h.label) };
}

// Users and groups that only existed for this app (add_user gives people exactly one app): nothing but this
// app's bindings refers to them. Superusers, service accounts, users/groups with roles, BASIC_AUTH_USERS,
// groups with parents or children (members may get access through them) and notification-rule groups are never touched.
async function planOrphans(app) {
  const bindings = await all("/policies/bindings/");
  const mine = bindings.filter((b) => b.target === app.pk);

  if (!mine.some((b) => b.user || b.group)) {
    return null;
  }

  const others = bindings.filter((b) => b.target !== app.pk);
  const groups = await all("/core/groups/");
  const byPk = new Map(groups.map((g) => [g.pk, g]));
  const rules = await all("/events/rules/");
  // Authentik versions differ: one "parent" or a "parents" list.
  const parentsOf = (g) => [...(g?.parents || []), ...(g?.parent ? [g.parent] : [])];

  // A group binding also matches members of its child groups, so a user counts every ancestor group.
  const withAncestors = (pks) => {
    const out = new Set();
    const walk = (pk) => {
      if (!out.has(pk)) {
        out.add(pk);
        parentsOf(byPk.get(pk)).forEach(walk);
      }
    };
    pks.forEach(walk);
    return out;
  };

  const orphanGroups = mine
    .filter((b) => b.group)
    .map((b) => byPk.get(b.group))
    .filter((g) => g && !g.is_superuser && !(g.roles || []).length && !(g.children || []).length && !parentsOf(g).length)
    .filter((g) => !others.some((b) => b.group === g.pk) && !rules.some((r) => r.destination_group === g.pk));

  // Only users bound to this app by name (as add_user makes them): someone who only gets in through a group
  // wasn't made for this app and may still use apps open to everyone; dropping the group is enough for them.
  const orphanUsers = (await all("/core/users/"))
    .filter((u) => !u.is_superuser && ["internal", "external"].includes(u.type) && !(u.roles || []).length && !config.basicAuthUsers.includes(u.username))
    .filter((u) => {
      const gs = withAncestors(u.groups || []);
      const here = mine.some((b) => b.user === u.pk);
      const elsewhere = others.some((b) => b.user === u.pk || (b.group && gs.has(b.group)));
      return here && !elsewhere;
    });

  if (!orphanUsers.length && !orphanGroups.length) {
    return null;
  }

  return {
    users: orphanUsers.map((u) => ({ pk: u.pk, label: `authentik user ${u.username}`, email: u.email })),
    groups: orphanGroups.map((g) => ({ pk: g.pk, label: `authentik group ${g.name}` })),
    note: "Only this app's bindings refer to them, so they are deleted with it. Pass their labels in keep to leave them.",
  };
}

async function applyOrphans(p, keep) {
  const done = [];

  for (const u of p.users) {
    if (!keep.includes(u.label)) {
      await ak(`/core/users/${u.pk}/`, { method: "DELETE" });
      done.push(u.label);
    }
  }

  for (const g of p.groups) {
    if (!keep.includes(g.label)) {
      await ak(`/core/groups/${g.pk}/`, { method: "DELETE" });
      done.push(g.label);
    }
  }

  return done;
}

async function applyRemove(p, keep = []) {
  if (p.action !== "remove") {
    return p;
  }

  // The application goes last: a re-run after a failure finds the orphans and the Basic-auth
  // provider through it, so everything that depends on it is cleaned up first.
  const done = { action: "removed", application: p.application, providers: p.providers };

  if (p.basic_auth) {
    done.basic_auth = await applyBasicAuthRemove(p.basic_auth);
  }

  if (p.orphans) {
    done.deleted = await applyOrphans(p.orphans, keep);
  }

  // Deleting a provider also detaches it from the outpost.
  for (const pk of p.providers) {
    await ak(`/providers/all/${pk}/`, { method: "DELETE" });
  }

  if (p.application) {
    await ak(`/core/applications/${encodeURIComponent(p.application)}/`, { method: "DELETE" });
  }

  return done;
}

module.exports = { plan, apply, slugOf, planRemove, planBasicAuthRemove, applyRemove, ak, all, findApplication, providerKind, oidcInfo };
