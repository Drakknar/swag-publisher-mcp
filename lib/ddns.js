const fs = require("fs");
const path = require("path");
const { config, StepError } = require("./config");
const docker = require("./docker");

function read() {
  try {
    return JSON.parse(fs.readFileSync(config.ddnsConfig, "utf-8"));
  } catch (e) {
    throw new StepError(`Can't read ddns-updater config ${config.ddnsConfig}: ${e.message}`);
  }
}

// Public sites need an entry so their record follows the public IP. A new entry copies an existing
// one for the same domain (provider, zone, token, ttl, proxied). Private sites must NOT have one:
// ddns-updater would overwrite their LAN address with the public IP.
function plan(sub, domain, visibility) {
  const { settings = [] } = read();
  const existing = settings.find((s) => s.domain === domain && s.host === sub);

  if (visibility === "private") {
    return existing ? { action: "remove", entry: { domain, host: sub } } : { action: "not_needed" };
  }

  if (existing) {
    return { action: "exists", entry: { domain, host: sub, provider: existing.provider } };
  }

  const template = settings.find((s) => s.domain === domain && s.provider === "cloudflare");

  if (!template) {
    throw new StepError(`No cloudflare entry for ${domain} in ddns-updater to copy from`);
  }

  return { action: "add", entry: { ...template, host: sub } };
}

async function apply(p) {
  if (p.action !== "add" && p.action !== "remove") {
    return p;
  }

  const raw = fs.readFileSync(config.ddnsConfig, "utf-8");
  fs.mkdirSync(config.backupDir, { recursive: true });
  fs.writeFileSync(path.join(config.backupDir, `ddns-config.json.${new Date().toISOString().replace(/[:.]/g, "-")}`), raw);

  const data = JSON.parse(raw);

  if (p.action === "add") {
    data.settings.push(p.entry);
  } else {
    data.settings = data.settings.filter((s) => !(s.domain === p.entry.domain && s.host === p.entry.host));
  }

  fs.writeFileSync(config.ddnsConfig, `${JSON.stringify(data, null, 2)}\n`);

  // ddns-updater reads its config only at startup.
  await docker.restart(config.ddnsContainer);
  return { action: p.action === "add" ? "added" : "removed", entry: { domain: p.entry.domain, host: p.entry.host }, restarted: config.ddnsContainer };
}

// Same as a private site: drop the entry if there is one.
const planRemove = (sub, domain) => plan(sub, domain, "private");

module.exports = { plan, apply, planRemove };
