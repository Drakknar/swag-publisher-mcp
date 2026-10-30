const { config, StepError } = require("./config");
const { request } = require("./http");
const { hostPort } = require("./match");

// Open WebUI leftovers of a removed site: External Tools connections (tool servers) and OpenAI/Ollama
// connections pointing at it, or at LiteLLM's per-server MCP URL (<litellm>/<server>/mcp) of a removed server.
// The plan holds only URLs; apply re-reads each config and drops those URLs, so nothing else is overwritten.

async function owui(p, opts = {}) {
  if (!config.owuiKey) {
    throw new StepError("OWUI_API_KEY is not set on the container");
  }

  return request("Open WebUI", `${config.owuiUrl}${p}`, { ...opts, headers: { Authorization: `Bearer ${config.owuiKey}` } });
}

// m = site matcher; mcpNames = LiteLLM MCP servers being removed.
function belongs(m, mcpNames) {
  const lite = hostPort(config.litellmUrl);
  return (u) => {
    const hp = u ? hostPort(u) : null;

    if (!hp) {
      return false;
    }

    if (m.url(u)) {
      return true;
    }

    if (!lite || hp.host !== lite.host || hp.port !== lite.port) {
      return false;
    }

    const first = new URL(/^\w+:\/\//.test(u) ? u : `http://${u}`).pathname.split("/").filter(Boolean)[0];
    return mcpNames.includes(first);
  };
}

// OpenAI/Ollama connections are parallel lists plus a config map keyed by index ("0", "1", ...).
function dropConnections(cfg, urlsKey, keysKey, configsKey, isGone) {
  const urls = cfg[urlsKey] || [];
  const keep = urls.map((u, i) => (isGone(u) ? null : i)).filter((i) => i !== null);

  if (keep.length === urls.length) {
    return null;
  }

  const out = { [urlsKey]: keep.map((i) => urls[i]) };

  if (keysKey) {
    out[keysKey] = keep.map((i) => (cfg[keysKey] || [])[i] ?? "");
  }

  out[configsKey] = Object.fromEntries(keep.map((oldI, newI) => [String(newI), (cfg[configsKey] || {})[String(oldI)]]).filter(([, v]) => v !== undefined));
  return out;
}

// The three kinds of connection: where to read/write them and how to rebuild the config without some URLs.
const KINDS = [
  {
    name: "tool",
    read: "/api/v1/configs/tool_servers",
    write: "/api/v1/configs/tool_servers",
    urls: (cfg) => (cfg.TOOL_SERVER_CONNECTIONS || []).map((c) => c.url),
    without: (cfg, isGone) => ({ TOOL_SERVER_CONNECTIONS: (cfg.TOOL_SERVER_CONNECTIONS || []).filter((c) => !isGone(c.url)) }),
  },
  {
    name: "openai",
    read: "/openai/config",
    write: "/openai/config/update",
    urls: (cfg) => cfg.OPENAI_API_BASE_URLS || [],
    without: (cfg, isGone) => ({ ENABLE_OPENAI_API: cfg.ENABLE_OPENAI_API, ...dropConnections(cfg, "OPENAI_API_BASE_URLS", "OPENAI_API_KEYS", "OPENAI_API_CONFIGS", isGone) }),
  },
  {
    name: "ollama",
    read: "/ollama/config",
    write: "/ollama/config/update",
    urls: (cfg) => cfg.OLLAMA_BASE_URLS || [],
    without: (cfg, isGone) => ({ ENABLE_OLLAMA_API: cfg.ENABLE_OLLAMA_API, ...dropConnections(cfg, "OLLAMA_BASE_URLS", null, "OLLAMA_API_CONFIGS", isGone) }),
  },
];

const labelOf = (kind, url) => `openwebui ${kind} ${url}`;

async function planRemove(m, mcpNames = []) {
  if (!config.owuiKey) {
    return { action: "skipped", reason: "OWUI_API_KEY not set" };
  }

  const isGone = belongs(m, mcpNames);
  const remove = [];

  for (const k of KINDS) {
    for (const url of k.urls(await owui(k.read)).filter(isGone)) {
      remove.push({ kind: k.name, url, label: labelOf(k.name, url) });
    }
  }

  return remove.length ? { action: "remove", connections: remove } : { action: "none" };
}

async function applyRemove(p, keep = []) {
  if (p.action !== "remove") {
    return p;
  }

  const removed = [];

  for (const k of KINDS) {
    const urls = new Set(p.connections.filter((c) => c.kind === k.name && !keep.includes(c.label)).map((c) => c.url));

    const cfg = urls.size ? await owui(k.read) : null;
    const present = cfg ? k.urls(cfg).filter((u) => urls.has(u)) : [];

    // Write only when something is still there to drop: a partial body could reset the config.
    if (present.length) {
      await owui(k.write, { method: "POST", body: k.without(cfg, (u) => urls.has(u)) });
      removed.push(...present.map((u) => labelOf(k.name, u)));
    }
  }

  return { action: "removed", connections: removed };
}

module.exports = { planRemove, applyRemove, dropConnections };
