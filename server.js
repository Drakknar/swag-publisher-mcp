const http = require("http");
const fs = require("fs");
const path = require("path");
const { z } = require("zod");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { config, StepError } = require("./lib/config");
const nginx = require("./lib/nginx");
const crypto = require("crypto");
const { publish, removeSite, serial } = require("./lib/publish");
const access = require("./lib/access");
const users = require("./lib/users");

const INFO = { name: "swag-publisher", version: "0.9.5" };

// Without MCP_TOKEN every request is refused: this endpoint can rewrite nginx, DNS and Authentik.
function authorized(header) {
  if (!config.mcpToken) {
    return false;
  }

  const want = crypto.createHash("sha256").update(`Bearer ${config.mcpToken}`).digest();
  const got = crypto.createHash("sha256").update(String(header || "")).digest();
  return crypto.timingSafeEqual(want, got);
}

function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], structuredContent: data };
}

function wrap(fn) {
  return async (args) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      if (!(e instanceof StepError)) {
        console.error(e);
      }

      return { content: [{ type: "text", text: e.message }], isError: true };
    }
  };
}

function registerTools(server) {
  server.registerTool(
    "list_sites",
    {
      title: "List published sites",
      description: "List the SWAG reverse-proxy sites: conf file, host names, upstream(s), whether Authentik protects them and whether it passes Basic-auth credentials.",
      annotations: { readOnlyHint: true },
    },
    wrap(async () => ({ sites: nginx.listSites() })),
  );

  server.registerTool(
    "get_site",
    {
      title: "Show a site",
      description:
        "Show one SWAG site, found by subdomain (e.g. \"sppaperless\"): its nginx config and its Authentik side: application, who may use it, Basic-auth attributes, and for OpenID apps every SSO setting the app needs (client ID, issuer/discovery URL, endpoints, scopes, claims, signing). The client secret only with show_secret=true, when the user needs it to configure the app.",
      inputSchema: {
        subdomain: z.string(),
        domain: z.string().optional().describe(`Defaults to ${config.domains[0]}.`),
        show_secret: z.boolean().default(false).describe("Include the OpenID client secret."),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async ({ subdomain, domain, show_secret }) => {
      const sub = subdomain.toLowerCase();
      const site = nginx.findSite(sub);

      if (!site) {
        throw new StepError(`No site serves ${subdomain}`);
      }

      const d = domain || config.domains[0];
      let authentik;

      try {
        authentik = await access.siteInfo({ sub, domain: d, fqdn: `${sub}.${d}` }, { showSecret: show_secret });
      } catch (e) {
        authentik = { error: e.message };
      }

      return { ...site, conf: fs.readFileSync(path.join(config.swagConfDir, site.file), "utf-8"), authentik };
    }),
  );

  server.registerTool(
    "publish_site",
    {
      title: "Publish or edit a site",
      description:
        `Create or edit a site in one go: SWAG reverse proxy (nginx conf, validated with nginx -t, then reloaded), optional Authentik protection, Cloudflare DNS record, an AdGuard Home local DNS rewrite (always, so sites keep working on the LAN when the internet is down), and for public sites a ddns-updater entry. Domains: ${config.domains.join(", ")}. ` +
        "Before calling, ASK the user what they haven't already said: " +
        "(1) visibility: public (reachable from the internet; DNS = current public IP, proxied by Cloudflare) or private (home network and Tailscale only; DNS = the server's LAN IP, DNS only, and nginx refuses other addresses); " +
        "(2) auth: authentik_proxy (Authentik login in front of the whole site; for apps without their own login), openid (the app signs users in itself via OpenID Connect with Authentik; needs the app's callback URL in redirect_uris and returns client_id/secret to enter in the app), or none (the app's own login only); " +
        "(3) only for public + authentik_proxy: lan_bypass, i.e. skip the Authentik login when coming from the home network or Tailscale; " +
        `(4) only for authentik_proxy: basic_auth, for apps with their own HTTP Basic login (e.g. AdGuard Home, Resilio Sync): Authentik sends the app's username/password, taken from user/group attributes <prefix>_username and <prefix>_password, so users log in once. Ask for the app's username and password and pass them as basic_auth_username/basic_auth_password: the tool stores them on Authentik user ${config.basicAuthUsers.join(", ")} and on any extra basic_auth_users/basic_auth_groups the user names (ask whether anyone else needs access). ` +
        "With basic_auth, ALWAYS double-check lan_bypass with the user before planning, even if they already said yes: on the home network/Tailscale it skips Authentik and the browser's own Authorization header is dropped, so an app that logs in with HTTP Basic can't be logged into from there at all (form/cookie logins only ask again); recommend lan_bypass=false. " +
        "(5) for a NEW authentik_proxy or openid site: the app's display name (app_name), written like the existing Authentik apps: the product's own name and spelling (\"AdGuard Home\", \"Paperless-ngx\", \"jDownloader\"), or SP<Name> for the user's own services (\"SPMusic\"); " +
        "(6) for authentik_proxy and openid: who may use it, as allowed_users/allowed_groups (Authentik usernames/group names); without them a NEW app is open to every Authentik user, so ask. " +
        "Optional: access_token_validity/refresh_token_validity (token lifetimes; suggest a longer access_token_validity for authentik_proxy apps with long live sessions such as Foundry VTT). OpenID providers always get exactly the grant types authorization_code + refresh_token; an existing one with others is corrected in the plan. " +
        "Two steps: first call without apply to get the plan and show it to the user; call again with apply=true only after they confirm. Editing an existing site keeps its custom nginx lines and only changes the upstream, the Authentik includes, the Basic-auth block and the LAN access rules.",
      inputSchema: {
        subdomain: z.string().describe("Host label, e.g. \"newapp\" for newapp.example.com."),
        visibility: z.enum(["public", "private"]).describe("public = internet (Cloudflare proxied, ddns, AdGuard); private = LAN/Tailscale only. Ask the user if they haven't said."),
        auth: z.enum(["authentik_proxy", "openid", "none"]).describe("How the site is protected. Ask the user if they haven't said."),
        lan_bypass: z
          .boolean()
          .default(false)
          .describe(
            "public + authentik_proxy only: no Authentik login from the home network/Tailscale. Ask the user when auth is authentik_proxy; with basic_auth, confirm it again (an HTTP Basic app then can't be logged into from the LAN).",
          ),
        basic_auth: z
          .boolean()
          .optional()
          .describe(
            "authentik_proxy only: pass HTTP Basic credentials from Authentik to the app (provider's \"Send HTTP-Basic Authentication\" + the Authorization lines in the conf, as spag.conf). Omit to keep an existing site's setting; new sites default to off.",
          ),
        basic_auth_attribute_prefix: z
          .string()
          .optional()
          .describe("With basic_auth: attribute prefix, e.g. \"adguard\" -> adguard_username/adguard_password. Without it, a provider that already has attribute names keeps them; otherwise the subdomain without \"sp\"."),
        basic_auth_username: z.string().optional().describe("With basic_auth: the app's own login name, stored in Authentik so it is sent for the user."),
        basic_auth_password: z.string().optional().describe("With basic_auth: the app's own password. Stored in Authentik; never shown in plans or results."),
        basic_auth_users: z
          .array(z.string())
          .optional()
          .describe(`Extra Authentik usernames that get the login (always: ${config.basicAuthUsers.join(", ")}).`),
        basic_auth_groups: z.array(z.string()).optional().describe("Authentik group names that get the login (every member then logs in with it)."),
        app_name: z
          .string()
          .optional()
          .describe("New Authentik app only: display name of the application and its provider (e.g. \"AdGuard Home\", \"Paperless-ngx\"); the slug is it in lowercase with hyphens. Default: SP<Name> from the subdomain."),
        allowed_users: z
          .array(z.string())
          .optional()
          .describe("Authentik usernames allowed to use the app. Together with allowed_groups the COMPLETE list (replaces the current one); omit both to leave access as it is; both empty = every Authentik user."),
        allowed_groups: z.array(z.string()).optional().describe("Authentik group names allowed to use the app (see allowed_users)."),
        upstream: z.string().optional().describe("Where SWAG forwards to: a port on the server (\"64400\"), host:port, or a URL. Required for a new site."),
        domain: z.string().optional().describe(`Defaults to ${config.domains[0]}.`),
        redirect_uris: z.array(z.string()).optional().describe("auth=openid only: the app's OIDC callback URL(s), from the app's docs."),
        access_token_validity: z
          .string()
          .optional()
          .describe(
            "Authentik duration (\"hours=24\", \"days=7\", \"days=1;hours=12\"). authentik_proxy: how long the Authentik login lasts before it's asked again (raise it for apps with long live connections, e.g. Foundry VTT, which drop when it runs out). openid: lifetime of the app's access tokens. Omit to keep the current value (new providers: Authentik's default).",
          ),
        refresh_token_validity: z
          .string()
          .optional()
          .describe("auth=openid only, Authentik duration: how long the app may stay signed in by refreshing its tokens. Omit to keep the current value."),
        apply: z.boolean().default(false).describe("false = plan only; true = carry it out (only after the user confirmed the plan)."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    wrap((args) => publish(args)),
  );

  server.registerTool(
    "site_access",
    {
      title: "Show or change who may use a site",
      description:
        "Show, change or remove who may use a site's Authentik application (its user and group bindings; with none, every Authentik user gets in). " +
        "Without users/groups: shows the current access. With them: the COMPLETE new list (replaces the current one); both empty removes every restriction. " +
        "Other policy bindings are kept. Two steps: first call without apply and show the plan; call again with apply=true only after the user confirms.",
      inputSchema: {
        subdomain: z.string().describe("Host label of the site, e.g. \"spnc\"."),
        domain: z.string().optional().describe(`Defaults to ${config.domains[0]}.`),
        application: z.string().optional().describe("Authentik application slug, when the site's application can't be found automatically."),
        users: z.array(z.string()).optional().describe("Authentik usernames allowed in."),
        groups: z.array(z.string()).optional().describe("Authentik group names allowed in."),
        apply: z.boolean().default(false).describe("false = show/plan only; true = change (only after the user confirmed)."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    // Same queue as publish/remove: they change the same Authentik bindings.
    wrap((args) => serial(() => access.manage(args))),
  );

  server.registerTool(
    "add_user",
    {
      title: "Add a user for one app",
      description:
        "Create an Authentik user who may use exactly one application: never an admin (type external, no groups, no roles), added to that app's allowed list (everyone already allowed keeps access). " +
        `No password is handled here: the new user sets it with "Forgot password?" on the login page (${config.authentikPublicUrl}), which emails them a link; the result says what to tell them. ` +
        "Before calling, ASK the user what they haven't already said: the username, the display name, the email (required) and the app (site subdomain or Authentik application slug). " +
        "Two steps: first call without apply and show the plan, including any warning about other apps open to everyone; call again with apply=true only after the user confirms. To give an existing user another app, use site_access.",
      inputSchema: {
        username: z.string().describe("Login name, e.g. \"marcor\" (the existing ones are first name + surname initial)."),
        name: z.string().describe("Display name, e.g. \"Marco Rossi\"."),
        email: z.string().describe("The user's email (required: it's how they set and recover their password)."),
        subdomain: z.string().optional().describe("Host label of the app's site, e.g. \"spnc\"."),
        application: z.string().optional().describe("Authentik application slug, instead of subdomain or when the site's application can't be found."),
        domain: z.string().optional().describe(`Defaults to ${config.domains[0]}.`),
        apply: z.boolean().default(false).describe("false = plan only; true = create (only after the user confirmed)."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    wrap((args) => serial(() => users.addUser(args))),
  );

  server.registerTool(
    "remove_site",
    {
      title: "Remove a site",
      description:
        "Remove a site everywhere: its SWAG conf (backed up, nginx checked and reloaded), its Cloudflare records, ddns-updater entries and exact AdGuard rewrites on every domain, its Authentik application and provider, and the Basic-auth login attributes that provider sent (deleted from every user/group holding them, unless another site still uses the same attribute names). " +
        "Also: Authentik users and groups that only existed for this app. Only with remove_integrations=true (the app itself is gone, not just its site): LiteLLM MCP servers and models pointing at the site's upstream or host names (config file entries are cut out and LiteLLM restarted; DB entries via API), LiteLLM keys named after the site (deleted) and key permissions naming removed or missing MCP servers (trimmed); Open WebUI External Tools and OpenAI/Ollama connections pointing at the site or at a removed LiteLLM MCP server. Without it these are listed under check_by_hand.integrations. " +
        "Only reported (check_by_hand): the container, its unRAID template and appdata folders, other SWAG confs on the same upstream, and Home Assistant dashboards/panels/automations/scripts mentioning the site. " +
        "Two steps: first call without apply and show the whole plan to the user; call again with apply=true only after they confirm, passing keep for anything they want left alone. To change a site instead, use publish_site.",
      inputSchema: {
        subdomain: z.string().describe("Host label of the site, e.g. \"spoldapp\"."),
        upstream: z.string().optional().describe("The app's address (port, host:port or URL) when its SWAG conf is already gone and has no backup, so LiteLLM/Open WebUI/HA leftovers can still be matched. Otherwise the conf's (or its newest backup's) proxy_pass is used."),
        remove_integrations: z
          .boolean()
          .default(false)
          .describe("true only when the app itself is gone (container removed), not just its site: then LiteLLM MCP servers/models/keys and Open WebUI connections pointing at it are removed too. Default false: they are only listed under check_by_hand.integrations."),
        keep: z.array(z.string()).optional().describe("Labels from the plan to leave alone, e.g. [\"authentik user alice\", \"litellm mcp ignis\", \"litellm key OpenCode\", \"litellm config\", \"openwebui tool http://…\"]."),
        apply: z.boolean().default(false).describe("false = plan only; true = delete (only after the user confirmed)."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    wrap((args) => removeSite(args)),
  );
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

const httpServer = http.createServer(async (req, res) => {
  const url = req.url.split("?")[0].replace(/\/+$/, "") || "/";

  if (url === "/health") {
    return send(res, 200, { ok: true });
  }

  if (url !== "/mcp" && url !== "/") {
    return send(res, 404, { error: "not found" });
  }

  if (!authorized(req.headers.authorization)) {
    return send(res, 401, { jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
  }

  let body = "";

  for await (const chunk of req) {
    body += chunk;
  }

  // Stateless Streamable HTTP: a fresh server and transport per request.
  const server = new McpServer(INFO);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => {
    transport.close();
    server.close();
  });

  try {
    registerTools(server);
    await server.connect(transport);
    await transport.handleRequest(req, res, body ? JSON.parse(body) : undefined);
  } catch (e) {
    console.error(e);

    if (!res.headersSent) {
      send(res, 500, { jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
});

if (require.main === module) {
  httpServer.listen(config.port, () => {
    const missing = ["CF_API_TOKEN:cfToken", "ADGUARD_USER:adguardUser", "ADGUARD_PASSWORD:adguardPassword", "AUTHENTIK_TOKEN:authentikToken", "MCP_TOKEN:mcpToken"]
      .filter((p) => !config[p.split(":")[1]])
      .map((p) => p.split(":")[0]);
    console.log(`${INFO.name} ${INFO.version} on :${config.port}/mcp; domains ${config.domains.join(", ")}`);

    if (missing.length) {
      console.log(`Not set: ${missing.join(", ")}`);
    }

    if (!config.mcpToken) {
      console.log("MCP_TOKEN is not set: every /mcp request is refused (401).");
    }
  });
}

module.exports = { registerTools, httpServer };
