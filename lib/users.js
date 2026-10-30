const { config, StepError } = require("./config");
const { ak, all, findApplication } = require("./authentik");

// New Authentik users for people outside the household: never admins, and allowed into exactly one application.
// Like the accounts made by hand : type external, path "users", no groups, no roles.
// Superuser rights in Authentik come only from groups (authentik Admins), so a user with no groups and no roles
// can't reach the admin interface. Every application with no bindings lets every user in, so the plan lists those.
// No password is handled here: the user sets it with "Forgot password?" on the login page (Authentik's recovery
// flow, which emails them), so every user needs an email (user rule, 2026-10-15).

const USER_TYPE = "external";
const USER_PATH = "users";
const APPS = "/core/applications/?superuser_full_list=true";

const bindingsOf = async (app) => (await all(`/policies/bindings/?target=${encodeURIComponent(app.pk)}`)).filter((b) => b.target === app.pk);
const lower = (s) => String(s || "").toLowerCase();

function checkInput({ username, name, email }) {
  if (!/^[A-Za-z0-9._@+-]{1,150}$/.test(username || "")) {
    throw new StepError(`Invalid username "${username}": letters, digits and . _ @ + - only`);
  }

  if (!String(name || "").trim()) {
    throw new StepError("name (the display name) is required");
  }

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email || "")) {
    throw new StepError(email ? `Invalid email "${email}"` : "email is required");
  }
}

async function planAdd(input) {
  checkInput(input);

  // The login matches usernames and emails ignoring case, so clashes are checked the same way.
  const users = await all("/core/users/");

  if (users.some((u) => lower(u.username) === lower(input.username))) {
    throw new StepError(`Authentik user "${input.username}" already exists; use site_access to change which apps it may use`);
  }

  const sameEmail = users.find((u) => lower(u.email) === lower(input.email));

  if (sameEmail) {
    throw new StepError(`${input.email} already belongs to Authentik user "${sameEmail.username}"`);
  }

  const sub = String(input.subdomain || "").trim().toLowerCase();

  if (!sub && !input.application) {
    throw new StepError("Name the app: subdomain of its site, or application (Authentik slug)");
  }

  const domain = input.domain || config.domains[0];
  const app = await findApplication({ sub, domain, fqdn: `${sub}.${domain}`, application: input.application });

  if (!app) {
    throw new StepError(`No Authentik application found for ${sub}.${domain}; pass "application" with its slug`);
  }

  const bindings = await bindingsOf(app);

  // Binding the first user would lock out everyone who uses it today.
  if (!bindings.length) {
    throw new StepError(`Application "${app.slug}" is open to every Authentik user; restrict it with site_access first, then add the user`);
  }

  if (!(await all("/core/brands/")).some((b) => b.default && b.flow_recovery)) {
    throw new StepError("The default Authentik brand has no recovery flow, so the user couldn't set a password (System → Brands → Recovery flow)");
  }

  // With "all", the new user would have to match every binding (be every listed user), as site_access fixes too.
  const fixMode = app.policy_engine_mode === "all";
  const bound = new Set((await all("/policies/bindings/")).map((b) => b.target));
  const openApps = (await all(APPS)).filter((a) => a.pk !== app.pk && !bound.has(a.pk)).map((a) => a.slug);

  return {
    action: "create",
    user: { username: input.username, name: input.name.trim(), email: input.email, type: USER_TYPE, path: USER_PATH, groups: "none", roles: "none", admin: false },
    application: { slug: app.slug, name: app.name, pk: app.pk },
    access_after: [
      ...bindings.map((b) => (b.user ? `user ${b.user_obj?.username || b.user}` : b.group ? `group ${b.group_obj?.name || b.group}` : `policy ${b.policy_obj?.name || b.policy}`)),
      `user ${input.username} (new)`,
    ],
    ...(fixMode ? { policy_engine_mode: { from: "all", to: "any", why: "with all, the new user would need to match every binding" } } : {}),
    other_apps_open_to_everyone: openApps.length ? openApps : "none",
    ...(openApps.length ? { warning: `The new user could also use ${openApps.join(", ")}: they have no bindings. Restrict them with site_access to keep the user to ${app.slug} only.` } : {}),
  };
}

async function applyAdd(input, p) {
  const created = await ak("/core/users/", {
    method: "POST",
    body: { username: p.user.username, name: p.user.name, email: p.user.email, type: USER_TYPE, path: USER_PATH, is_active: true, groups: [], roles: [] },
  });
  const user = await ak(`/core/users/${created.pk}/`);

  // Should never happen with no groups and no roles; never leave an admin behind if it does.
  if (user.is_superuser || (user.groups || []).length || (user.roles || []).length) {
    await ak(`/core/users/${user.pk}/`, { method: "DELETE" });
    throw new StepError(`Authentik gave "${user.username}" groups, roles or superuser rights; the user was deleted again`);
  }

  try {
    const order = Math.max(-1, ...(await bindingsOf(p.application)).map((b) => b.order)) + 1;
    await ak("/policies/bindings/", {
      method: "POST",
      body: { target: p.application.pk, user: user.pk, order, enabled: true, negate: false, timeout: 30 },
    });

    if (p.policy_engine_mode) {
      await ak(`/core/applications/${encodeURIComponent(p.application.slug)}/`, { method: "PATCH", body: { policy_engine_mode: "any" } });
    }
  } catch (e) {
    await ak(`/core/users/${user.pk}/`, { method: "DELETE" });
    throw new StepError(`Couldn't give "${user.username}" access to ${p.application.slug} (${e.message}); the user was deleted again`);
  }

  return {
    action: "created",
    username: user.username,
    application: p.application.slug,
    next_step: `Tell ${p.user.name} to open ${config.authentikPublicUrl}, click "Forgot password?" and enter ${p.user.email}: Authentik emails a link to set the password.`,
    ...(p.warning ? { warning: p.warning } : {}),
  };
}

// add_user: plans (or creates) one non-admin user allowed into one application.
async function addUser(input) {
  const p = await planAdd(input);

  if (!input.apply) {
    return {
      applied: false,
      plan: p,
      next: "Show this plan to the user. Only after they confirm, call add_user again with the same arguments and apply=true.",
    };
  }

  return { applied: true, ...(await applyAdd(input, p)) };
}

module.exports = { addUser };
