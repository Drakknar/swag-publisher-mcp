const { config, StepError } = require("./config");
const { ak, all, findApplication, providerKind, oidcInfo } = require("./authentik");

// Who may use a site's Authentik application: its user and group policy bindings. An application
// without bindings lets every Authentik user in. Other policy bindings (expressions etc.) are left alone.

async function resolve({ users = [], groups = [] }) {
  const out = { users: [], groups: [] };

  for (const name of users) {
    const u = (await all(`/core/users/?username=${encodeURIComponent(name)}`)).find((x) => x.username === name);

    if (!u) {
      throw new StepError(`Authentik user "${name}" not found`);
    }

    out.users.push({ pk: u.pk, username: u.username });
  }

  for (const name of groups) {
    const g = (await all(`/core/groups/?name=${encodeURIComponent(name)}`)).find((x) => x.name === name);

    if (!g) {
      throw new StepError(`Authentik group "${name}" not found`);
    }

    out.groups.push({ pk: g.pk, name: g.name });
  }

  return out;
}

// Filtered here too: if the API ever ignored ?target=, other applications' bindings would end up in "remove".
const bindingsOf = async (app) => (app ? (await all(`/policies/bindings/?target=${encodeURIComponent(app.pk)}`)).filter((b) => b.target === app.pk) : []);

function describe(app, bindings) {
  const users = bindings.filter((b) => b.user).map((b) => b.user_obj?.username || String(b.user));
  const groups = bindings.filter((b) => b.group).map((b) => b.group_obj?.name || b.group);
  const policies = bindings.filter((b) => b.policy).map((b) => b.policy_obj?.name || b.policy);
  return {
    application: app?.slug || null,
    open_to_everyone: !bindings.length,
    users,
    groups,
    ...(policies.length ? { other_policies: policies } : {}),
    ...(app && bindings.length > 1 ? { mode: app.policy_engine_mode === "all" ? "all must match" : "any match is enough" } : {}),
  };
}

async function current(ctx) {
  const app = await findApplication(ctx);
  return describe(app, await bindingsOf(app));
}

// ctx.access = { users: [...], groups: [...] }: the complete list of who may use the app; both empty = everyone.
async function plan(ctx, { creating = false } = {}) {
  const wanted = await resolve(ctx.access);
  const app = await findApplication(ctx);

  if (!app && !creating) {
    throw new StepError(`No Authentik application found for ${ctx.fqdn}; pass "application" with its slug`);
  }

  const bindings = await bindingsOf(app);
  const add = [
    ...wanted.users.filter((u) => !bindings.some((b) => b.user === u.pk)).map((u) => ({ user: u.pk, label: `user ${u.username}` })),
    ...wanted.groups.filter((g) => !bindings.some((b) => b.group === g.pk)).map((g) => ({ group: g.pk, label: `group ${g.name}` })),
  ];
  const remove = bindings
    .filter((b) => (b.user && !wanted.users.some((u) => u.pk === b.user)) || (b.group && !wanted.groups.some((g) => g.pk === b.group)))
    .map((b) => ({ binding: b.pk, label: b.user ? `user ${b.user_obj?.username || b.user}` : `group ${b.group_obj?.name || b.group}` }));
  const remaining = wanted.users.length + wanted.groups.length + bindings.filter((b) => b.policy).length;
  // With "all", someone would need to match every binding (be every listed user, in every group).
  const fixMode = Boolean(app) && app.policy_engine_mode === "all" && wanted.users.length + wanted.groups.length > 1;

  return {
    action: add.length || remove.length || fixMode ? "update" : "unchanged",
    application: app?.slug || "(created with the site)",
    current: describe(app, bindings),
    allowed_after: remaining ? { users: wanted.users.map((u) => u.username), groups: wanted.groups.map((g) => g.name) } : "every Authentik user",
    add,
    remove,
    ...(fixMode ? { policy_engine_mode: "any" } : {}),
    ...(!remaining ? { note: "No restrictions: every Authentik user will be able to use this app." } : {}),
  };
}

async function apply(p, ctx) {
  if (p.action !== "update") {
    return { action: p.action, allowed: p.allowed_after };
  }

  const app = await findApplication(ctx);

  if (!app) {
    throw new StepError(`Authentik application for ${ctx.fqdn} not found`);
  }

  let order = Math.max(-1, ...(await bindingsOf(app)).map((b) => b.order)) + 1;

  for (const b of p.add) {
    await ak("/policies/bindings/", {
      method: "POST",
      body: { target: app.pk, ...(b.user ? { user: b.user } : { group: b.group }), order: order++, enabled: true, negate: false, timeout: 30 },
    });
  }

  for (const b of p.remove) {
    await ak(`/policies/bindings/${b.binding}/`, { method: "DELETE" });
  }

  if (p.policy_engine_mode) {
    await ak(`/core/applications/${encodeURIComponent(app.slug)}/`, { method: "PATCH", body: { policy_engine_mode: p.policy_engine_mode } });
  }

  return {
    action: "updated",
    application: app.slug,
    added: p.add.map((b) => b.label),
    removed: p.remove.map((b) => b.label),
    allowed: p.allowed_after,
    next_step: "Already logged-in users keep their session until it expires or they sign out.",
  };
}

// The site's Authentik side for get_site: application, who may use it, and the SSO settings of an OpenID app.
async function siteInfo(ctx, { showSecret = false } = {}) {
  const app = await findApplication(ctx);

  if (!app) {
    return { application: null };
  }

  const kind = providerKind(app);
  const info = { application: app.slug, name: app.name, provider: app.provider_obj?.name || null, kind, access: describe(app, await bindingsOf(app)) };

  if (kind === "oauth2") {
    info.oidc = await oidcInfo(await ak(`/providers/oauth2/${app.provider}/`), app.slug, { secret: showSecret });
  } else if (kind === "proxy") {
    const provider = await ak(`/providers/proxy/${app.provider}/`);
    info.basic_auth = provider.basic_auth_enabled
      ? { attributes: [provider.basic_auth_user_attribute, provider.basic_auth_password_attribute] }
      : false;
    info.access_token_validity = provider.access_token_validity;
  }

  return info;
}

// site_access: without users/groups shows who may use the app; with them, plans (or applies) that exact list.
async function manage(input) {
  const sub = String(input.subdomain || "").trim().toLowerCase();
  const domain = input.domain || config.domains[0];

  if (!config.domains.includes(domain)) {
    throw new StepError(`Domain must be one of: ${config.domains.join(", ")}`);
  }

  if (!input.application && !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sub)) {
    throw new StepError(`"${input.subdomain}" isn't a valid subdomain label; or pass application (its Authentik slug)`);
  }

  const ctx = { sub, domain, fqdn: `${sub}.${domain}`, application: input.application };

  if (input.users === undefined && input.groups === undefined) {
    return current(ctx);
  }

  ctx.access = { users: input.users || [], groups: input.groups || [] };
  const p = await plan(ctx);

  if (!input.apply) {
    return {
      applied: false,
      plan: p,
      next:
        "Show this plan to the user. Only after they confirm, call site_access again with the same arguments and apply=true." +
        (p.allowed_after === "every Authentik user" ? " This removes every restriction: anyone with an Authentik account gets in." : ""),
    };
  }

  return { applied: true, ...(await apply(p, ctx)) };
}

module.exports = { current, plan, apply, siteInfo, manage };
