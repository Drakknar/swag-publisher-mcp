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
