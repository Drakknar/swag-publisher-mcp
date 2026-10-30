const fs = require("fs");
const path = require("path");
const { config } = require("./config");
const nginx = require("./nginx");
const docker = require("./docker");
const { hostPort } = require("./match");

// Report only: what removing a site can't safely delete itself. The container, its unRAID template and
// appdata folders (root-owned, need the server), and other SWAG confs that proxy to the same upstream.

const portsOf = (upstreams) =>
  upstreams
    .map(hostPort)
    .filter((x) => x && [config.lanHost, "127.0.0.1", "localhost"].includes(x.host))
    .map((x) => x.port);

// "/mnt/cache/appdata/ollama/models" -> "/mnt/user/appdata/ollama"; null outside appdata.
const appdataRoot = (p) => {
  const m = p.match(/^\/mnt\/[^/]+\/appdata\/([^/]+)/);
  return m ? `/mnt/user/appdata/${m[1]}` : null;
};

async function allContainers() {
  const r = await docker.call("GET", "/containers/json?all=1");

  // An empty list would count as "checked" and let shared folders through as safe to delete.
  if (r.status !== 200) {
    throw new Error(`Docker API answered ${r.status}`);
  }

  return JSON.parse(r.body);
}

const describeContainer = (c) => ({
  name: (c.Names || [])[0]?.replace(/^\//, ""),
  image: c.Image,
  state: c.State,
  host_paths: (c.Mounts || []).filter((x) => x.Type === "bind").map((x) => x.Source),
});

// Templates name host ports as <Config ... Type="Port" ...>8080</Config>; only names and paths are read
// out (templates hold secrets).
function templates(ports, names) {
  if (!fs.existsSync(config.templatesDir)) {
    return null;
  }

  const out = [];

  for (const f of fs.readdirSync(config.templatesDir).filter((x) => x.endsWith(".xml"))) {
    const xml = fs.readFileSync(path.join(config.templatesDir, f), "utf-8");
    const name = (xml.match(/<Name>([^<]*)<\/Name>/) || [])[1] || "";
    const byName = names.includes(name.toLowerCase());
    const byPort = [...xml.matchAll(/<Config[^>]*Type="Port"[^>]*>(\d+)<\/Config>/g)].some((x) => ports.includes(x[1]));

    if (byName || byPort) {
      out.push({
        file: f,
        container: name,
        matched_by: byName ? "container name" : "host port only (may be an unrelated old template that reused the port)",
        host_paths: [...new Set([...xml.matchAll(/<Config[^>]*Type="Path"[^>]*>([^<]+)<\/Config>/g)].map((x) => x[1]))],
      });
    }
  }

  return out;
}

async function scan({ site, upstreams, containerNames = [] }) {
  const ports = portsOf(upstreams);
  const ups = new Set(upstreams.map(hostPort).filter(Boolean).map((x) => `${x.host}:${x.port}`));
  const report = {};
  let all = [];

  try {
    all = await allContainers();
  } catch (e) {
    report.containers = { error: e.message };
  }

  const mine = all.filter((c) => (c.Ports || []).some((p) => ports.includes(String(p.PublicPort))));
  const found = mine.map(describeContainer);
  report.containers ??= found;

  const names = [...containerNames, ...found.map((c) => c.name.toLowerCase())];
  const tpl = templates(ports, names);
  report.templates = tpl ?? "not checked (TEMPLATES_DIR not mounted)";
  report.other_swag_confs = nginx
    .listSites()
    .filter((s) => s.file !== site?.file && s.upstreams.some((u) => ups.has(`${hostPort(u)?.host}:${hostPort(u)?.port}`)))
    .map((s) => ({ file: s.file, hosts: s.hosts }));

  // Folders only from the container itself or a template matched by name, never from a port-only match,
  // and never one another container still mounts (e.g. a models folder shared by two Ollama containers).
  const sure = [...found, ...(tpl || []).filter((t) => t.matched_by === "container name")];
  const usedElsewhere = new Map();

  for (const c of all.filter((x) => !mine.includes(x)).map(describeContainer)) {
    for (const root of c.host_paths.map(appdataRoot).filter(Boolean)) {
      usedElsewhere.set(root, c.name);
    }
  }

  const roots = [...new Set(sure.flatMap((x) => x.host_paths).map(appdataRoot).filter(Boolean))];
  // Without the container list, sharing can't be ruled out: no delete suggestion then.
  const verified = !report.containers.error;
  const folders = verified ? roots.filter((r) => !usedElsewhere.has(r)) : [];
  const shared = verified
    ? roots.filter((r) => usedElsewhere.has(r)).map((r) => `${r} (also used by ${usedElsewhere.get(r)})`)
    : roots.map((r) => `${r} (not checked: container list unavailable)`);

  if (!found.length && !(tpl || []).length && !report.other_swag_confs.length) {
    return { action: "none", ...report };
  }

  return {
    action: "check_by_hand",
    ...report,
    ...(folders.length ? { appdata_folders: folders } : {}),
    ...(shared.length ? { shared_folders_keep: shared } : {}),
    next_steps: [
      ...(found.length ? ["Remove the container (unRAID Docker tab → Remove, tick 'also remove image')."] : []),
      ...((tpl || []).length ? ["Check each template (matched_by) and delete the ones that belong to this app: unRAID Apps → Previous Apps, or remove the file under /boot/config/plugins/dockerMan/templates-user/."] : []),
      ...(folders.length ? [`On the server: rm -rf ${folders.join(" ")} (after the container is gone).`] : []),
      ...(report.other_swag_confs.length ? ["Other SWAG confs proxy to the same upstream: edit or remove them separately."] : []),
    ],
  };
}

module.exports = { scan };
