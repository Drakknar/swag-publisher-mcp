const { config, StepError } = require("./config");
const { request } = require("./http");

async function cf(path, opts = {}) {
  if (!config.cfToken) {
    throw new StepError("CF_API_TOKEN is not set on the container");
  }

  const data = await request("Cloudflare", `${config.cfApi}${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${config.cfToken}` },
  });

  if (!data?.success) {
    throw new StepError(`Cloudflare error: ${JSON.stringify(data?.errors || data).slice(0, 300)}`);
  }

  return data.result;
}

async function zoneId(domain) {
  const [zone] = await cf(`/zones?name=${encodeURIComponent(domain)}`);

  if (!zone) {
    throw new StepError(`Cloudflare zone ${domain} not found (check the token's zone resources)`);
  }

  return zone.id;
}

// The records named exactly fqdn (Cloudflare's name filter is exact, checked again before anything is deleted).
const recordsOf = async (zone, fqdn) =>
  (await cf(`/zones/${zone}/dns_records?name=${encodeURIComponent(fqdn)}&per_page=100`)).filter((r) => String(r.name).toLowerCase() === fqdn.toLowerCase());

// Public: A record with the apex's current public IP, proxied (ddns-updater keeps it current).
// Private: A record with the server's LAN address, DNS only (Cloudflare can't proxy a private IP).
async function plan(fqdn, domain, visibility) {
  const zone = await zoneId(domain);
  let wanted;

  if (visibility === "private") {
    wanted = { type: "A", name: fqdn, content: config.lanHost, proxied: false, ttl: 1 };
  } else {
    const apex = (await recordsOf(zone, domain)).find((r) => r.type === "A");

    if (!apex) {
      throw new StepError(`No A record on ${domain} to copy the public IP from`);
    }

    wanted = { type: "A", name: fqdn, content: apex.content, proxied: true, ttl: 1 };
  }

  // Exact name only (checked here too), and only records that answer for the address (a TXT doesn't block).
  const records = (await recordsOf(zone, fqdn)).filter((r) => ["A", "AAAA", "CNAME"].includes(r.type));
  const existing = records.find((r) => r.type !== "A") || records[0];

  if (records.filter((r) => r.type === "A").length > 1) {
    throw new StepError(`${fqdn} has several A records; change them by hand`);
  }

  if (!existing) {
    return { action: "create", zone, record: wanted };
  }

  const current = { type: existing.type, content: existing.content, proxied: existing.proxied };

  if (existing.type !== "A") {
    throw new StepError(`${fqdn} already has a ${existing.type} record (${existing.content}); change it by hand`);
  }

  if (existing.content === wanted.content && existing.proxied === wanted.proxied) {
    return { action: "exists", zone, record: current };
  }

  return { action: "update", zone, id: existing.id, from: current, record: wanted };
}

async function apply(p) {
  if (p.action === "create") {
    const r = await cf(`/zones/${p.zone}/dns_records`, { method: "POST", body: p.record });
    return { action: "created", record: { type: r.type, name: r.name, content: r.content, proxied: r.proxied } };
  }

  if (p.action === "update") {
    const r = await cf(`/zones/${p.zone}/dns_records/${p.id}`, { method: "PATCH", body: { content: p.record.content, proxied: p.record.proxied } });
    return { action: "updated", from: p.from, record: { type: r.type, name: r.name, content: r.content, proxied: r.proxied } };
  }

  return p;
}

async function planRemove(fqdn, domain) {
  let zone;

  try {
    zone = await zoneId(domain);
  } catch (e) {
    // Removal checks every domain; one the token can't see can't hold a record to delete either.
    if (e instanceof StepError && e.message.includes("not found")) {
      return { action: "skipped", reason: e.message };
    }

    throw e;
  }

  const records = await recordsOf(zone, fqdn);
  return records.length
    ? { action: "remove", zone, records: records.map((r) => ({ id: r.id, type: r.type, content: r.content, proxied: r.proxied })) }
    : { action: "none" };
}

async function applyRemove(p) {
  if (p.action !== "remove") {
    return p;
  }

  for (const r of p.records) {
    await cf(`/zones/${p.zone}/dns_records/${r.id}`, { method: "DELETE" });
  }

  return { action: "removed", records: p.records.map((r) => `${r.type} ${r.content}`) };
}

module.exports = { plan, apply, planRemove, applyRemove };
