const fs = require("fs");
const path = require("path");
const { config, StepError } = require("./config");
const docker = require("./docker");

const AUTH_SERVER = "include /config/nginx/authentik-server.conf;";
const AUTH_LOCATION = "include /config/nginx/authentik-location.conf;";
const MARKER = "# managed by swag-publisher";
// A comment on a line of its own: this tool then refuses to edit or remove the conf.
const LOCK_LINE = /^\s*# publisher: locked\s*$/m;
const ACCESS_LINE = /^\s*(satisfy\s+any|allow\s+\S+|deny\s+all)\s*;\s*$/;
// Passes the credentials of Authentik's "Send HTTP-Basic Authentication" on to the app, as spag.conf does.
const BASIC_AUTH = [
  '# This section should be uncommented when the "Send HTTP Basic authentication" option',
  "# is enabled in the Authentik proxy provider",
  "auth_request_set $authentik_auth $upstream_http_authorization;",
  "proxy_set_header Authorization $authentik_auth;",
];
const AUTH_LOCATION_LINE = /^([ \t]*)include \/config\/nginx\/authentik-location\.conf;[^\n]*\n/m;

const isComment = (l) => /^\s*#/.test(l);
const active = (text) => text.split(/\r?\n/).filter((l) => !isComment(l)).join("\n");
const isBasicAuthLine = (l) => BASIC_AUTH.includes(l.trim());
const hasBasicAuth = (text) => active(text).includes("$upstream_http_authorization");

// The access lines (satisfy/allow/deny) at the top of "location / {", as the existing confs write them.
function accessLines(lines) {
  const start = lines.findIndex((l) => /^\s*location \/ \{/.test(l));

  if (start < 0) {
    return { start, idx: [] };
  }

  const idx = [];

  for (let i = start + 1; i < lines.length; i++) {
    // The Authentik include (and its Basic-auth lines) may sit above the access lines right after an edit added it.
    if (!lines[i].trim() || isComment(lines[i]) || lines[i].includes(AUTH_LOCATION) || isBasicAuthLine(lines[i])) {
      continue;
    }

    if (!ACCESS_LINE.test(lines[i])) {
      break;
    }

    idx.push(i);
  }

  return { start, idx };
}

function accessOf(lines) {
  const block = accessLines(lines).idx.map((i) => lines[i].trim());

  if (!block.length) {
    return "open";
  }

  return block.includes("satisfy any;") ? "lan_bypass" : "lan_only";
}

// What the top of "location / {" should hold: private sites answer the LAN only; public sites behind
// Authentik can let the LAN in without logging in ("satisfy any": LAN address OR Authentik login).
function wantedAccess({ visibility, auth, lanBypass }) {
  const allowed = (ranges) => [...ranges.map((r) => `allow ${r};`), "deny all;"];

  if (visibility === "private") {
    return allowed(config.lanRanges);
  }

  if (auth === "authentik_proxy" && lanBypass) {
    return ["satisfy any;", ...allowed(config.lanBypassRanges)];
  }

  return [];
}

function describe(file, text) {
  const body = active(text);
  // Only the directive itself, not "proxy_ssl_server_name on;".
  const hosts = [...new Set([...body.matchAll(/(?:^|[\s;{])server_name\s+([^;]+);/g)].flatMap((m) => m[1].trim().split(/\s+/)))];
  const upstreams = [...new Set([...body.matchAll(/proxy_pass\s+([^;]+);/g)].map((m) => m[1].trim()))];
  const auth = body.includes(AUTH_LOCATION) ? "authentik_proxy" : "none";
  return {
    file,
    hosts,
    upstreams,
    auth,
    basic_auth: auth === "authentik_proxy" && hasBasicAuth(text),
    access: accessOf(text.split(/\r?\n/)),
    managed: text.includes(MARKER),
    locked: LOCK_LINE.test(text),
  };
}

function listSites() {
  return fs
    .readdirSync(config.swagConfDir)
    .filter((f) => f.endsWith(".conf"))
    .sort()
    .map((f) => describe(f, fs.readFileSync(path.join(config.swagConfDir, f), "utf-8")));
}

// The conf serving "<sub>.*" (or the exact name), whatever its file is called.
function findSite(sub) {
  return listSites().find((s) => s.hosts.includes(`${sub}.*`) || s.hosts.some((h) => h.startsWith(`${sub}.`)));
}

// Block tree of a conf (comments removed): each node has its header ("location ~ \.php$"), its own
// statements (body) and nested blocks. Quotes are respected ("}" or "#" inside them is text); inline
// comments are dropped, or they would end up in the next block's header.
function tree(text) {
  const root = { header: "", body: "", children: [] };
  const stack = [root];
  let buf = "";
  let quote = null;
  let comment = false;

  for (const ch of active(text)) {
    if (comment) {
      comment = ch !== "\n";
      buf += comment ? "" : ch;
    } else if (quote) {
      buf += ch;
      quote = ch === quote ? null : quote;
    } else if (ch === '"' || ch === "'") {
      buf += ch;
      quote = ch;
    } else if (ch === "#" && (buf === "" || /\s$/.test(buf))) {
      comment = true;
    } else if (ch === "{") {
      const node = { header: buf.trim().replace(/\s+/g, " "), body: "", children: [] };
      stack.at(-1).children.push(node);
      stack.push(node);
      buf = "";
    } else if (ch === "}") {
      stack.at(-1).body += buf;
      buf = "";

      if (stack.length > 1) {
        stack.pop();
      }
    } else if (ch === ";") {
      stack.at(-1).body += `${buf.trim()};\n`;
      buf = "";
    } else {
      buf += ch;
    }
  }

  return root;
}

const SERVES = /^\s*(proxy_pass|fastcgi_pass|uwsgi_pass|grpc_pass|root|alias|try_files)\s/m;
const serves = (node) => SERVES.test(node.body) || node.children.some(serves);
const accessSet = (body) => body.split("\n").map((l) => l.trim()).filter((l) => ACCESS_LINE.test(l)).sort().join(" ");
const CATCH_ALL = new Set(["_", ".*", "*", "~.*", "~^.*$"]);

// The 2026-10-15 hardening, checked on every conf publish_site writes or leaves in place: every 443 server
// includes ssl.conf (TLS settings and the country block), no port-80 catch-all names (the default server
// refuses unknown hosts), and every other location that serves content is guarded like "location /"
// (the PHP lesson: a fastcgi/proxy location next to "location /" skipped its LAN rules and Authentik).
function hardening(text) {
  const warnings = [];

  for (const server of tree(text).children.filter((n) => n.header === "server")) {
    // The default server is the catch-all on purpose.
    if (/^\s*listen\s[^;]*default_server/m.test(server.body)) {
      continue;
    }

    const tls = /^\s*listen\s+(\[::\]:)?443\b/m.test(server.body);
    const names = [...server.body.matchAll(/^\s*server_name\s+([^;]+);/gm)].flatMap((m) => m[1].trim().split(/\s+/));

    if (tls && !server.body.includes("include /config/nginx/ssl.conf;")) {
      warnings.push(`The 443 server for ${names.join(" ")} doesn't include /config/nginx/ssl.conf: no country block and no shared TLS settings.`);
    }

    if (names.some((n) => CATCH_ALL.has(n))) {
      warnings.push(`server_name ${names.join(" ")} is a catch-all; use the site's own name (<sub>.*) so the default server keeps refusing unknown hosts.`);
    }

    if (!tls) {
      continue;
    }

    // Named locations (@x) can't be requested from outside.
    const locations = server.children.filter((n) => n.header.startsWith("location ") && !n.header.startsWith("location @"));
    const main = locations.find((n) => n.header === "location /");

    if (!main) {
      continue;
    }

    // A location's own allow/deny lines replace the server's (they don't add to them); auth_request is inherited.
    const serverAccess = accessSet(server.body);
    const serverAuth = server.body.includes(AUTH_LOCATION);
    const effectiveAccess = (n) => accessSet(n.body) || serverAccess;
    const effectiveAuth = (n) => serverAuth || n.body.includes(AUTH_LOCATION);
    const wantAccess = effectiveAccess(main);
    const wantAuth = effectiveAuth(main);

    for (const loc of locations) {
      if (loc === main || !serves(loc) || /^\s*(return\s|internal;)/m.test(loc.body) || accessSet(loc.body) === "deny all;") {
        continue;
      }

      const missing = [
        ...(wantAccess && effectiveAccess(loc) !== wantAccess ? ["the LAN allow/deny rules"] : []),
        ...(wantAuth && !effectiveAuth(loc) ? ["the Authentik login"] : []),
      ];

      if (missing.length) {
        warnings.push(`"${loc.header}" serves content without ${missing.join(" and ")} of "location /". Repeat them there unless it's a deliberate carve-out.`);
      }
    }
  }

  return warnings;
}

function render(ctx) {
  const a = ctx.auth === "authentik_proxy";
  const access = wantedAccess(ctx);
  return [
    `${MARKER} (${new Date().toISOString().slice(0, 10)}, ${ctx.visibility})`,
    "server {",
    "    listen 80;",
    "    listen [::]:80;",
    `    server_name ${ctx.sub}.*;`,
    "    return 301 https://$host$request_uri;",
    "}",
    "server {",
    "    listen 443 ssl;",
    "    listen [::]:443 ssl;",
    "    http2 on;",
    `    server_name ${ctx.sub}.*;`,
    "    include /config/nginx/ssl.conf;",
    ...(a ? [`    ${AUTH_SERVER}`] : []),
    "    client_max_body_size 0;",
    "    location / {",
    ...access.map((l) => `        ${l}`),
    ...(access.length ? [""] : []),
    ...(a ? [`        ${AUTH_LOCATION}`] : []),
    ...(a && ctx.basicAuth ? ["", ...BASIC_AUTH.map((l) => `        ${l}`), ""] : []),
    "        include /config/nginx/proxy.conf;",
    "        include /config/nginx/resolver.conf;",
    "        add_header 'Content-Security-Policy' 'upgrade-insecure-requests';",
    `        proxy_pass ${ctx.upstream};`,
    "    }",
    "}",
    "",
  ].join("\n");
}

// Edits an existing conf in place: the upstream (only when it has a single proxy_pass), the
// Authentik includes and the LAN access lines. Everything else the user wrote by hand is kept.
function edit(text, ctx) {
  let out = text;
  const info = describe("", text);

  if (ctx.upstream && !info.upstreams.includes(ctx.upstream)) {
    if (info.upstreams.length !== 1) {
      throw new StepError(`This conf has ${info.upstreams.length} proxy_pass targets (${info.upstreams.join(", ")}); change the upstream by hand.`);
    }

    // Every copy: a conf may repeat the same single upstream in several locations.
    // A function, so "$" in the value is never read as a replacement pattern.
    out = out.replace(/^([ \t]*proxy_pass\s+)[^;]+;/gm, (m, head) => `${head}${ctx.upstream};`);
  }

  const has = describe("", out).auth === "authentik_proxy";

  if (ctx.auth === "authentik_proxy" && !has) {
    out = out.replace(/^([ \t]*)include \/config\/nginx\/ssl\.conf;[^\n]*\n/m, (m, ind) => `${m}${ind}${AUTH_SERVER}\n`);
    out = out.replace(/^([ \t]*)location \/ \{[^\n]*\n/m, (m, ind) => `${m}${ind}    ${AUTH_LOCATION}\n`);

    if (describe("", out).auth !== "authentik_proxy" || !active(out).includes(AUTH_SERVER)) {
      throw new StepError("Couldn't find 'include /config/nginx/ssl.conf;' and 'location / {' to add Authentik; edit this conf by hand.");
    }
  } else if (ctx.auth !== "authentik_proxy" && has) {
    out = out
      .split("\n")
      .filter((l) => isComment(l) || !(l.includes(AUTH_SERVER) || l.includes(AUTH_LOCATION)))
      .join("\n");
  }

  // Replace the access lines at the top of "location / {" with the wanted ones.
  const lines = out.split("\n");
  const { start, idx } = accessLines(lines);
  const wanted = wantedAccess(ctx);
  const current = idx.map((i) => lines[i].trim());

  if (JSON.stringify(current) !== JSON.stringify(wanted)) {
    if (start < 0) {
      throw new StepError("No 'location / {' block to put the LAN access rules in; edit this conf by hand.");
    }

    const indent = `${lines[start].match(/^\s*/)[0]}    `;
    const kept = lines.filter((_, i) => !idx.includes(i));
    kept.splice(start + 1, 0, ...wanted.map((l) => `${indent}${l}`));
    out = kept.join("\n");
  }

  // Basic-auth passthrough: only behind the Authentik proxy; left as it is when the caller didn't say.
  const wantBasic = ctx.auth === "authentik_proxy" ? ctx.basicAuth : false;

  if (wantBasic && !hasBasicAuth(out)) {
    out = out.replace(AUTH_LOCATION_LINE, (m, ind) => `${m}\n${BASIC_AUTH.map((l) => `${ind}${l}\n`).join("")}`);
  } else if (wantBasic === false && hasBasicAuth(out)) {
    out = out
      .split("\n")
      .filter((l) => !isBasicAuthLine(l))
      .join("\n");
  }

  // nginx and Authentik must agree: a block left behind with the provider option off drops the browser's
  // own Authorization header, so the app's login stops working.
  if (wantBasic !== undefined && hasBasicAuth(out) !== wantBasic) {
    throw new StepError(
      wantBasic
        ? "Couldn't find 'include /config/nginx/authentik-location.conf;' to put the Basic-auth lines after; edit this conf by hand."
        : "This conf passes $upstream_http_authorization in a way the tool doesn't recognise; remove those lines by hand.",
    );
  }

  return out;
}

function backup(file, text) {
  fs.mkdirSync(config.backupDir, { recursive: true });
  const dest = path.join(config.backupDir, `${file}.${new Date().toISOString().replace(/[:.]/g, "-")}`);
  fs.writeFileSync(dest, text);
  return dest;
}

// Writes the conf, checks nginx accepts it, then reloads; a rejected conf is rolled back.
async function apply(file, text) {
  const target = path.join(config.swagConfDir, file);
  const previous = fs.existsSync(target) ? fs.readFileSync(target, "utf-8") : null;
  const saved = previous !== null ? backup(file, previous) : null;
  fs.writeFileSync(target, text);

  const test = await docker.exec(config.swagContainer, ["nginx", "-t"]);

  if (test.exitCode !== 0) {
    if (previous !== null) {
      fs.writeFileSync(target, previous);
    } else {
      fs.unlinkSync(target);
    }

    throw new StepError(`nginx rejected the config, change rolled back:\n${test.output.slice(-1200)}`);
  }

  const reload = await docker.exec(config.swagContainer, ["nginx", "-s", "reload"]);

  if (reload.exitCode !== 0) {
    throw new StepError(`nginx -t passed but reload failed: ${reload.output.slice(-600)}`);
  }

  return { file, backup: saved };
}

// The conf on disk is already as wanted, but it may have been edited by hand since nginx last loaded it:
// check and reload, so what the plan shows is what nginx serves. Nothing is written.
async function reload() {
  const test = await docker.exec(config.swagContainer, ["nginx", "-t"]);

  if (test.exitCode !== 0) {
    throw new StepError(`nginx -t fails with the confs on disk (nothing was changed; nginx keeps running the last good config):\n${test.output.slice(-1200)}`);
  }

  const r = await docker.exec(config.swagContainer, ["nginx", "-s", "reload"]);

  if (r.exitCode !== 0) {
    throw new StepError(`nginx -t passed but reload failed: ${r.output.slice(-600)}`);
  }

  return { reloaded: true };
}

// Removes a conf (backed up first); nginx is checked and reloaded, and the file restored if nginx objects.
async function remove(file) {
  const target = path.join(config.swagConfDir, file);
  const previous = fs.readFileSync(target, "utf-8");
  const saved = backup(file, previous);
  fs.unlinkSync(target);

  const test = await docker.exec(config.swagContainer, ["nginx", "-t"]);

  if (test.exitCode !== 0) {
    fs.writeFileSync(target, previous);
    throw new StepError(`nginx -t failed without this conf, restored it:\n${test.output.slice(-1200)}`);
  }

  const reload = await docker.exec(config.swagContainer, ["nginx", "-s", "reload"]);

  if (reload.exitCode !== 0) {
    throw new StepError(`Conf removed (backup ${saved}) and nginx -t passed, but the reload failed: ${reload.output.slice(-600)}`);
  }

  return { file, backup: saved };
}

module.exports = { listSites, findSite, render, edit, apply, reload, remove, describe, hardening };
