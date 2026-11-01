const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "publisher-test-"));
// Addresses are documentation or closed ports: every outside step fails at once, which plans report per step.
Object.assign(process.env, {
  DOMAINS: "example.test",
  LAN_HOST: "192.0.2.4",
  LAN_RANGES: "192.0.2.0/24,172.16.0.0/12",
  ADGUARD_URL: "http://127.0.0.1:1",
  AUTHENTIK_URL: "http://127.0.0.1:1",
  AUTHENTIK_PUBLIC_URL: "http://127.0.0.1:1",
  BASIC_AUTH_USERS: "tester",
  SWAG_CONF_DIR: dir,
  BACKUP_DIR: path.join(dir, "backups"),
  DOCKER_HOST_URL: "http://127.0.0.1:1",
  DDNS_CONFIG: path.join(dir, "ddns.json"),
  TEMPLATES_DIR: path.join(dir, "templates"),
  PUBLIC_NO_AUTH_ALLOW: "spallowed",
});
delete process.env.LAN_BYPASS_RANGES;

const nginx = require("../lib/nginx");
const { publish, removeSite } = require("../lib/publish");
const { config } = require("../lib/config");

const conf = (sub, inside = "", top = "") => `${top}server {
    listen 443 ssl;
    server_name ${sub}.*;
    include /config/nginx/ssl.conf;
    location / {
${inside}        proxy_pass http://192.0.2.4:1000;
    }
}
`;
const write = (sub, text) => fs.writeFileSync(path.join(dir, `${sub}.conf`), text);
const plan = (sub, extra = {}) => publish({ subdomain: sub, domain: "example.test", visibility: "public", auth: "none", upstream: "192.0.2.4:1000", ...extra });
const swagError = (r) => r.plan.swag.error || "";

test("the lan_bypass default leaves Docker's networks out", () => {
  assert.deepStrictEqual(config.lanBypassRanges, ["192.0.2.0/24"]);
  const out = nginx.edit(conf("spb"), { visibility: "public", auth: "authentik_proxy", lanBypass: true, upstream: null });
  assert.match(out, /satisfy any;/);
  assert.match(out, /allow 192\.0\.2\.0\/24;/);
  assert.doesNotMatch(out, /172\.16\.0\.0/);
});

test("private sites still allow every LAN range", () => {
  const out = nginx.edit(conf("spc"), { visibility: "private", auth: "none", upstream: null });
  assert.match(out, /allow 172\.16\.0\.0\/12;/);
});

test("a new public site with no login is refused", async () => {
  assert.match(swagError(await plan("spnew")), /PUBLIC_NO_AUTH_ALLOW/);
});

test("the allow-list permits a new public site with no login", async () => {
  const r = await plan("spallowed");
  assert.strictEqual(r.plan.swag.action, "create");
});

test("a site already public with no login can be re-published", async () => {
  write("spopen", conf("spopen"));
  const r = await plan("spopen");
  assert.strictEqual(swagError(r), "");
  assert.strictEqual(r.plan.swag.action, "unchanged");
});

test("a LAN-only site can't become public with no login", async () => {
  write("splan", conf("splan", "        allow 192.0.2.0/24;\n        deny all;\n"));
  assert.match(swagError(await plan("splan")), /PUBLIC_NO_AUTH_ALLOW/);
});

test("a locked conf is reported, and refused by publish and remove", async () => {
  const text = conf("splocked", "", "# publisher: locked\n");
  write("splocked", text);
  assert.strictEqual(nginx.findSite("splocked").locked, true);
  assert.strictEqual(nginx.findSite("spopen").locked, false);

  assert.match(swagError(await plan("splocked", { visibility: "private" })), /publisher: locked/);
  await assert.rejects(plan("splocked", { visibility: "private", apply: true }), /publisher: locked/);
  await assert.rejects(removeSite({ subdomain: "splocked", apply: true }), /publisher: locked/);
  assert.strictEqual(fs.readFileSync(path.join(dir, "splocked.conf"), "utf-8"), text);
});

test("the marker text inside another comment doesn't lock", () => {
  write("spnote", conf("spnote", "", "# see publisher: locked sites\n"));
  assert.strictEqual(nginx.findSite("spnote").locked, false);
});

test("any spelling of the lock line locks, a sentence about it does not", () => {
  for (const line of ["#publisher: locked", "# Publisher: Locked", "# publisher:locked", "# publisher: locked (hand edited)"]) {
    write("splock2", conf("splock2", "", `${line}\n`));
    assert.strictEqual(nginx.findSite("splock2").locked, true, line);
  }
  fs.unlinkSync(path.join(dir, "splock2.conf"));
});

test("access rules at server level or below an include count", () => {
  const server = `server {
    listen 443 ssl;
    server_name spsrv.*;
    allow 192.0.2.0/24;
    deny all;
    location / {
        proxy_pass http://192.0.2.4:1000;
    }
}
`;
  assert.strictEqual(nginx.describe("x", server).access, "lan_only");
  const below = conf("spbelow", "        include /config/nginx/proxy.conf;\n        satisfy any;\n        allow 192.0.2.0/24;\n        deny all;\n");
  assert.strictEqual(nginx.describe("x", below).access, "lan_bypass");
  assert.strictEqual(nginx.describe("x", conf("spo")).access, "open");
});

test("a site limited at server level isn't taken for already public", async () => {
  write("spsrvonly", conf("spsrvonly").replace("    location / {", "    allow 192.0.2.0/24;\n    deny all;\n    location / {"));
  assert.match(swagError(await plan("spsrvonly")), /Public without a login is refused/);
  fs.unlinkSync(path.join(dir, "spsrvonly.conf"));
});

test("Docker being unreachable leaves the conf as it was", async () => {
  write("sproll", "old\n");
  await assert.rejects(nginx.apply("sproll.conf", "new\n"), /rolled back/);
  assert.strictEqual(fs.readFileSync(path.join(dir, "sproll.conf"), "utf-8"), "old\n");
  await assert.rejects(nginx.remove("sproll.conf"), /rolled back/);
  assert.strictEqual(fs.readFileSync(path.join(dir, "sproll.conf"), "utf-8"), "old\n");
  await assert.rejects(nginx.apply("spnew2.conf", "new\n"), /rolled back/);
  assert.strictEqual(fs.existsSync(path.join(dir, "spnew2.conf")), false);
  fs.unlinkSync(path.join(dir, "sproll.conf"));
});

test("a plan that drops an allow range says so", async () => {
  const old = conf("spdrop", "        satisfy any;\n        allow 192.0.2.0/24;\n        allow 172.16.0.0/12;\n        deny all;\n");
  write("spdrop", old);
  const r = await plan("spdrop", { auth: "authentik_proxy", lan_bypass: true });
  assert.match(r.plan.access_warning_ranges, /172\.16\.0\.0\/12/);
  fs.unlinkSync(path.join(dir, "spdrop.conf"));
});
