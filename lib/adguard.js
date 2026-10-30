const { config, StepError } = require("./config");
const { request } = require("./http");

function auth() {
  if (!config.adguardUser || !config.adguardPassword) {
    throw new StepError("ADGUARD_USER / ADGUARD_PASSWORD are not set on the container");
  }

  return { Authorization: `Basic ${Buffer.from(`${config.adguardUser}:${config.adguardPassword}`).toString("base64")}` };
}

const covers = (pattern, fqdn) =>
  pattern === fqdn || (pattern.startsWith("*.") && fqdn.endsWith(pattern.slice(1)) && fqdn.split(".").length === pattern.split(".").length);

// Local DNS for every site, public or private: on the LAN the name resolves to SWAG without asking
// Cloudflare, so the sites keep working while the internet connection is down. A wildcard rewrite already
// covering it is enough; an exact one pointing elsewhere is corrected.
async function plan(fqdn, domain) {
  const list = (await request("AdGuard", `${config.adguardUrl}/control/rewrite/list`, { headers: auth() })) || [];
  const exact = list.find((r) => r.domain === fqdn);
  // SWAG's address as most of the domain's rewrites answer it: the first one found could be a host that isn't
  // behind SWAG at all (a router, another server).
  const counts = new Map();

  for (const r of list.filter((x) => x.domain !== fqdn && x.domain.endsWith(`.${domain}`) && x.enabled !== false)) {
    counts.set(r.answer, (counts.get(r.answer) || 0) + 1);
  }

  const common = [...counts].sort((a, b) => b[1] - a[1] || (a[0] === config.lanHost ? -1 : b[0] === config.lanHost ? 1 : 0))[0]?.[0];
  const answer = config.adguardAnswer || common || config.lanHost;
  const rewrite = { domain: fqdn, answer, ...(list.some((r) => "enabled" in r) ? { enabled: true } : {}) };

  if (exact) {
    return exact.answer === answer && exact.enabled !== false ? { action: "exists", rewrite: exact } : { action: "update", from: exact, rewrite };
  }

  const wildcard = list.find((r) => covers(r.domain, fqdn) && r.enabled !== false);

  if (wildcard) {
    return { action: "covered", rewrite: wildcard };
  }

  return { action: "create", rewrite };
}

async function apply(p) {
  if (p.action === "update") {
    await request("AdGuard", `${config.adguardUrl}/control/rewrite/update`, {
      method: "PUT",
      headers: auth(),
      body: { target: p.from, update: p.rewrite },
    });
    return { action: "updated", rewrite: p.rewrite };
  }

  if (p.action !== "create") {
    return p;
  }

  await request("AdGuard", `${config.adguardUrl}/control/rewrite/add`, { method: "POST", headers: auth(), body: p.rewrite });
  return { action: "created", rewrite: p.rewrite };
}

// Removal touches exact rewrites only; a wildcard serves other sites too.
async function planRemove(fqdn) {
  const list = (await request("AdGuard", `${config.adguardUrl}/control/rewrite/list`, { headers: auth() })) || [];
  const exact = list.filter((r) => r.domain === fqdn);
  // Say so when a wildcard still answers for the name, so "none" isn't read as "the LAN no longer resolves it".
  const wildcard = list.find((r) => r.domain !== fqdn && covers(r.domain, fqdn) && r.enabled !== false);
  const still = wildcard ? { still_resolves_via_wildcard: `${wildcard.domain} -> ${wildcard.answer} (kept; it serves other sites)` } : {};
  return exact.length ? { action: "remove", rewrites: exact, ...still } : { action: "none", ...still };
}

async function applyRemove(p) {
  if (p.action !== "remove") {
    return p;
  }

  for (const r of p.rewrites) {
    await request("AdGuard", `${config.adguardUrl}/control/rewrite/delete`, { method: "POST", headers: auth(), body: r });
  }

  return { ...p, action: "removed", rewrites: p.rewrites.map((r) => `${r.domain} -> ${r.answer}`) };
}

module.exports = { plan, apply, covers, planRemove, applyRemove };
