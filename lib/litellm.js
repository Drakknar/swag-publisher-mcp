const fs = require("fs");
const path = require("path");
const { config, StepError } = require("./config");
const { request } = require("./http");
const docker = require("./docker");

// LiteLLM leftovers of a removed site: MCP servers and models pointing at it (config file or DB),
// virtual keys named after it, and key permissions naming MCP servers that are gone.

async function llm(p, opts = {}) {
  if (!config.litellmKey) {
    throw new StepError("LITELLM_KEY is not set on the container");
  }

  return request("LiteLLM", `${config.litellmUrl}${p}`, { ...opts, headers: { Authorization: `Bearer ${config.litellmKey}` } });
}

const isTop = (l) => /^[^\s#]/.test(l);
const isBlank = (l) => l.trim() === "";
const indent = (l) => l.match(/^ */)[0].length;
const nameOf = (entry) => (entry.head.match(/^ {2}(?:- model_name:\s*["']?)?([\w.:/-]+?)["']?:?\s*(#.*)?$/) || [])[1];

// Line ranges [start, end) of the entries under a top-level key: "  name:" maps (mcp_servers) or
// "  - ..." list items (model_list). An entry owns the comment lines directly above it (no blank line between).
function entries(lines, section) {
  const out = [];
  let inSection = false;

  for (let i = 0; i < lines.length; i++) {
    if (isTop(lines[i])) {
      inSection = lines[i].startsWith(`${section}:`);
      continue;
    }

    const head = section === "model_list" ? /^ {2}- / : /^ {2}[\w-]+:/;

    if (!inSection || !head.test(lines[i])) {
      continue;
    }

    let start = i;

    // Section headers ("  # --- Local audio.cpp ---") stay.
    while (start > 0 && /^ {2}#/.test(lines[start - 1]) && !/^ {2}# ---/.test(lines[start - 1])) {
      start--;
    }

    let end = i + 1;

    // Comments at any indent inside the entry belong to it ("# disabled for now:" at column 0 too).
    while (end < lines.length && (isBlank(lines[end]) || /^\s*#/.test(lines[end]) || indent(lines[end]) > 2)) {
      end++;
    }

    // Trailing blank and comment lines belong to whatever follows (the next entry or section).
    while (end > i + 1 && (isBlank(lines[end - 1]) || /^\s*#/.test(lines[end - 1]))) {
      end--;
    }

    out.push({ start, end, head: lines[i], body: lines.slice(i, end).join("\n") });
  }

  return out;
}

// Drops the chosen entries and the blank line after each one.
function cut(text, ranges) {
  const lines = text.split("\n");
  const drop = new Set();

  for (const { start, end } of ranges) {
    for (let k = start; k < end; k++) {
      drop.add(k);
    }

    if (isBlank(lines[end] ?? "x") && (start === 0 || isBlank(lines[start - 1]) || /:\s*$/.test(lines[start - 1]))) {
      drop.add(end);
    }
  }

  return lines.filter((_, k) => !drop.has(k)).join("\n");
}

// Literal secrets in removed lines are not shown in the plan (os.environ/ references are).
const mask = (l) =>
  l
    .replace(/^(\s*-?\s*[\w-]*(?:key|token|secret|password|auth_value)[\w-]*\s*:\s*)(?!os\.environ\/)\S.*$/i, "$1***")
    .replace(/((?:authorization\s*:\s*)?bearer\s+)(?!os\.environ\/)\S.*$/i, "$1***")
    .replace(/([?&](?:api_?key|token|access_token|key)=)[^&\s"']+/gi, "$1***");
const envRefs = (text) => [...new Set([...text.matchAll(/os\.environ\/([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]))];

function readConfig() {
  try {
    return fs.readFileSync(config.litellmConfig, "utf-8");
  } catch (e) {
    throw new StepError(`Can't read the LiteLLM config at ${config.litellmConfig} (mount appdata/lite-llm there): ${e.message}`);
  }
}

// m = matcher from match.js (URLs of the site, and its names for key aliases). keep = plan labels to leave
// alone; applied here so the config cut, key trimming and Open WebUI cascade all follow it.
async function planRemove(m, keep = []) {
  if (!config.litellmKey) {
    return { action: "skipped", reason: "LITELLM_KEY not set" };
  }

  const servers = await llm("/v1/mcp/server");
  const list = Array.isArray(servers) ? servers : servers.data || [];
  const goneServers = list.filter((s) => m.url(s.url) && !keep.includes(`litellm mcp ${s.server_name}`));
  // Key permissions may name a server by id, name or alias.
  const refs = (s) => [s.server_id, s.server_name, s.alias].filter(Boolean);
  const goneIds = new Set(goneServers.flatMap(refs));
  const liveIds = new Set(list.filter((s) => !goneServers.includes(s)).flatMap(refs));

  const models = ((await llm("/model/info")).data || []).filter((x) => m.url(x.litellm_params?.api_base) && !keep.includes(`litellm model ${x.model_name}`));

  // Config-file entries are cut out of litellm_config.yaml; DB entries go through the API.
  const fileServers = goneServers.filter((s) => s.is_config).map((s) => s.server_name);
  const fileModels = models.filter((x) => !x.model_info?.db_model).map((x) => x.model_name);
  let file = null;

  if (fileServers.length || fileModels.length) {
    const before = readConfig();
    const lines = before.split("\n");
    // A model name can have several deployments: only the entries that point at the site go.
    const ranges = [
      ...entries(lines, "mcp_servers").filter((e) => fileServers.includes(nameOf(e))),
      ...entries(lines, "model_list").filter((e) => fileModels.includes(nameOf(e)) && m.text(e.body)),
    ];
    const after = cut(before, ranges);
    const afterLines = after.split("\n");
    // An emptied section ("mcp_servers:" with nothing under it) may keep LiteLLM from starting.
    const emptied = ["mcp_servers", "model_list"].filter((s) => entries(lines, s).length && !entries(afterLines, s).length);

    if (emptied.length) {
      throw new StepError(`Removing these entries would leave ${emptied.join(" and ")} empty in ${config.litellmConfig}; edit it by hand.`);
    }

    const removedText = ranges.map((r) => lines.slice(r.start, r.end).join("\n")).join("\n");
    const stillUsed = new Set(envRefs(after));
    const found = new Set(ranges.map(nameOf));
    const missing = [...fileServers, ...fileModels].filter((n) => !found.has(n));
    file = {
      path: config.litellmConfig,
      removes: ranges.map((r) => r.head.trim()),
      diff: removedText.split("\n").map((l) => `- ${mask(l)}`).join("\n"),
      unused_env: envRefs(removedText).filter((v) => !stillUsed.has(v)),
      restart: config.litellmContainer,
      text: after,
      source: before,
      ...(missing.length ? { warning: `Not found in the config file, left alone: ${missing.join(", ")}` } : {}),
    };
  }

  const keys = [];
  const deleteKeys = [];
  const warnings = [];
  const allKeys = [];

  for (let page = 1; ; page++) {
    const r = await llm(`/key/list?return_full_object=true&size=100&page=${page}`);
    allKeys.push(...(r.keys || []));

    if (!r.total_pages || page >= r.total_pages) {
      break;
    }
  }

  for (const k of allKeys) {
    const label = `litellm key ${k.key_alias || k.key_name}`;

    if (k.key_alias && m.name(k.key_alias)) {
      deleteKeys.push({ token: k.token, label, alias: k.key_alias });
      continue;
    }

    const removedModels = (k.models || []).filter((n) => models.some((x) => x.model_name === n));

    if (removedModels.length) {
      warnings.push(`Key ${k.key_alias || k.key_name} lists model(s) ${removedModels.join(", ")}; fix it by hand (an empty list would mean every model).`);
    }

    const perm = k.object_permission;
    const ids = perm?.mcp_servers || [];
    const gone = (id) => goneIds.has(id) || !liveIds.has(id);
    const drop = ids.filter(gone);

    if (!drop.length) {
      continue;
    }

    const names = drop.map((id) => (goneIds.has(id) ? goneServers.find((s) => refs(s).includes(id)).server_name : `${id} (no longer exists)`));

    // An empty server list lifts the restriction instead of tightening it.
    if (drop.length === ids.length && !(perm.mcp_access_groups || []).length) {
      warnings.push(`Key ${k.key_alias || k.key_name} only has MCP access to ${names.join(", ")}; trimming would leave it unrestricted, so delete the key or fix it by hand.`);
      continue;
    }

    // Tool permissions are keyed by id or name, whichever the key used.
    const tools = Object.fromEntries(Object.entries(perm.mcp_tool_permissions || {}).filter(([id]) => !gone(id)));
    keys.push({
      token: k.token,
      label,
      alias: k.key_alias,
      drops_mcp_servers: names,
      object_permission: { mcp_servers: ids.filter((id) => !gone(id)), mcp_tool_permissions: tools },
    });
  }

  const db = {
    mcp_servers: goneServers.filter((s) => !s.is_config).map((s) => ({ id: s.server_id, name: s.server_name, label: `litellm mcp ${s.server_name}` })),
    models: models.filter((x) => x.model_info?.db_model).map((x) => ({ id: x.model_info.id, name: x.model_name, label: `litellm model ${x.model_name}` })),
  };

  if (!goneServers.length && !models.length && !keys.length && !deleteKeys.length) {
    return warnings.length ? { action: "none", warnings } : { action: "none" };
  }

  return {
    action: "remove",
    mcp_servers: goneServers.map((s) => s.server_name),
    models: models.map((x) => x.model_name),
    ...(file ? { config_file: file } : {}),
    ...(db.mcp_servers.length || db.models.length ? { db } : {}),
    ...(deleteKeys.length ? { delete_keys: deleteKeys } : {}),
    ...(keys.length ? { update_keys: keys } : {}),
    ...(warnings.length ? { warnings } : {}),
  };
}

function backup(text) {
  fs.mkdirSync(config.backupDir, { recursive: true });
  const dest = path.join(config.backupDir, `litellm_config.yaml.${new Date().toISOString().replace(/[:.]/g, "-")}`);
  fs.writeFileSync(dest, text);
  return dest;
}

async function applyRemove(p, keep = []) {
  if (p.action !== "remove") {
    return p;
  }

  const kept = (label) => keep.includes(label);
  const done = { action: "removed", deleted_keys: [], updated_keys: [], deleted_db: [] };

  // Checked before anything is deleted, so a stale plan stops the whole LiteLLM step.
  if (p.config_file?.source !== undefined && !kept("litellm config") && readConfig() !== p.config_file.source) {
    throw new StepError(`${config.litellmConfig} changed since the plan was made; nothing changed in LiteLLM. Call remove_site again.`);
  }

  for (const k of p.delete_keys || []) {
    if (!kept(k.label)) {
      await llm("/key/delete", { method: "POST", body: { keys: [k.token] } });
      done.deleted_keys.push(k.alias);
    }
  }

  for (const k of p.update_keys || []) {
    if (!kept(k.label)) {
      await llm("/key/update", { method: "POST", body: { key: k.token, object_permission: k.object_permission } });
      done.updated_keys.push(`${k.alias}: dropped ${k.drops_mcp_servers.join(", ")}`);
    }
  }

  for (const s of p.db?.mcp_servers || []) {
    if (!kept(s.label)) {
      await llm(`/v1/mcp/server/${encodeURIComponent(s.id)}`, { method: "DELETE" });
      done.deleted_db.push(s.label);
    }
  }

  for (const x of p.db?.models || []) {
    if (!kept(x.label)) {
      await llm("/model/delete", { method: "POST", body: { id: x.id } });
      done.deleted_db.push(x.label);
    }
  }

  if (p.config_file && !kept("litellm config")) {
    const current = readConfig();

    // The new text was cut from the file as it was when planning; an edit since then would be lost.
    if (p.config_file.source !== undefined && current !== p.config_file.source) {
      throw new StepError(`${config.litellmConfig} changed while this removal ran; nothing written there. Call remove_site again.`);
    }

    const saved = backup(current);
    fs.writeFileSync(config.litellmConfig, p.config_file.text);
    // Calls usually come through LiteLLM itself: restart only after this answer is on its way.
    setTimeout(() => docker.restart(config.litellmContainer).catch((e) => console.error(`LiteLLM restart failed: ${e.message}`)), 3000);
    done.config_file = {
      removed: p.config_file.removes,
      backup: saved,
      restart: `${config.litellmContainer} restarts in a few seconds; MCP/model calls fail briefly`,
    };

    if (p.config_file.unused_env.length) {
      done.config_file.next_step = `Delete the now unused variable(s) ${p.config_file.unused_env.join(", ")} from the ${config.litellmContainer} container (unRAID template).`;
    }
  }

  return done;
}

module.exports = { planRemove, applyRemove, entries, cut };
