// What belongs to a site being removed: URLs whose host:port is one of its upstreams or whose host is
// one of its names, and things named after it (LiteLLM key aliases).

function hostPort(u) {
  try {
    const x = new URL(/^[a-z][\w+.-]*:\/\//i.test(u) ? u : `http://${u}`);
    return { host: x.hostname.toLowerCase(), port: x.port || (x.protocol === "https:" ? "443" : "80") };
  } catch {
    return null;
  }
}

const norm = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// upstreams: proxy_pass URLs; fqdns: the site's host names; names: the site's names (subdomain, app name).
function matcher({ upstreams = [], fqdns = [], names = [] }) {
  const ups = upstreams.map(hostPort).filter(Boolean);
  const hosts = fqdns.map((h) => h.toLowerCase());
  const nameSet = new Set(names.map(norm).filter((n) => n.length >= 3));
  const patterns = [
    ...hosts.map((h) => new RegExp(`(^|[^\\w.-])${escape(h)}(?![\\w-])`, "i")),
    ...ups.map((x) => new RegExp(`(^|[^\\w.-])${escape(x.host)}:${x.port}(?!\\d)`, "i")),
  ];

  const url = (u) => {
    const hp = u ? hostPort(String(u).trim()) : null;
    return Boolean(hp) && (ups.some((x) => x.host === hp.host && x.port === hp.port) || hosts.includes(hp.host));
  };

  // Free text (configs, dashboards): any URL that matches, or a bare host name / host:port.
  const text = (t) => {
    const s = String(t ?? "");
    return [...s.matchAll(/https?:\/\/[^\s"'<>`\\]+/gi)].some((m) => url(m[0])) || patterns.some((p) => p.test(s));
  };

  return {
    url,
    text,
    name: (s) => nameSet.has(norm(s)),
    describe: { upstreams: ups.map((x) => `${x.host}:${x.port}`), hosts, names: [...nameSet] },
  };
}

module.exports = { matcher, hostPort, norm };
