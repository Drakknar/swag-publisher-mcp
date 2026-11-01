# swag-publisher MCP

Publishes or edits a site in one step, as an MCP tool (used through LiteLLM as `swag_publisher-*`):

1. **Authentik** (optional): `authentik_proxy` creates a forward-auth proxy provider + application and attaches it to the embedded outpost; `openid` creates an OAuth2/OpenID provider + application and returns client id/secret and issuer for the app. Settings (flows, mappings, signing key) are copied from an existing provider.
2. **SWAG**: writes `site-confs/<sub>.conf` (same layout as the existing confs; editing an existing conf only changes its upstream, Authentik includes, Basic-auth block and LAN access lines; the Basic-auth block is checked after the edit so nginx and Authentik can't end up disagreeing), runs `nginx -t` in the swag container, rolls back if it fails, then `nginx -s reload`. Previous versions go to `/data/backups`.
3. **Cloudflare**: proxied A record with the apex's current IP (skipped if the name exists).
4. **ddns-updater**: copies an existing entry of the same domain with the new host, restarts `ddns-updater`.
5. **AdGuard Home**: DNS rewrite to SWAG via the API for **every** site, public or private, so the LAN resolves the names without Cloudflare and the sites keep working while the internet is down (skipped if an enabled wildcard covers it; an exact rewrite with another answer, or disabled, is corrected); adguard-home-sync copies it to the replica.

Tools: `list_sites`, `get_site` (conf + Authentik application, access, Basic-auth attributes and, for OpenID apps, every SSO setting; the client secret only with `show_secret`), `publish_site` (create or change), `site_access` (show or change who may use a site), `remove_site`, `add_user` (a non-admin user for one app). Both changing tools plan first and act only with `apply: true`, after the user confirms. The certificate needs no step: SWAG has a wildcard cert for both domains.

**Visibility** (`publish_site`, required):
- `public`: Cloudflare A record = current public IP, proxied; ddns-updater entry; AdGuard rewrite.
- `private`: Cloudflare A record = `LAN_HOST`, DNS only (Cloudflare can't proxy a private IP); **no** ddns-updater entry (it would overwrite the LAN IP with the public one, so an existing entry is removed, before the record changes) but still an AdGuard rewrite (the public record also answers the LAN IP, but only while Cloudflare is reachable); nginx allows only `LAN_RANGES` (`allow …; deny all;`), because SWAG is reachable from the internet and would otherwise serve the site to anyone sending the right host name.

**LAN bypass** (`lan_bypass`, public + `authentik_proxy` only): adds the same block the existing confs use, so the home network and Tailscale skip the Authentik login:

```nginx
location / {
    satisfy any;
    allow <each entry of LAN_RANGES>;
    deny all;
    include /config/nginx/authentik-location.conf;
```

**Basic auth passthrough** (`basic_auth`, `authentik_proxy` only): for apps with their own HTTP Basic login (AdGuard Home, Resilio Sync), Authentik logs in for the user. The provider gets "Send HTTP-Basic Authentication" with the user/group attributes `<prefix>_username` / `<prefix>_password` (`basic_auth_attribute_prefix`; without it an existing provider keeps its names, a new one gets the subdomain without `sp`), and the conf gets the standard block right after the Authentik include:

```nginx
        include /config/nginx/authentik-location.conf;

        # This section should be uncommented when the "Send HTTP Basic authentication" option
        # is enabled in the Authentik proxy provider
        auth_request_set $authentik_auth $upstream_http_authorization;
        proxy_set_header Authorization $authentik_auth;
```

Pass the app's login as `basic_auth_username` / `basic_auth_password` and the tool stores it in those attributes on the Authentik users in `BASIC_AUTH_USERS` plus any `basic_auth_users` / `basic_auth_groups` named; existing attributes are kept (merged), and the password never appears in plans or results. Without them, set the attributes in Authentik yourself. Either way, people already logged in must sign out of Authentik once (`/outpost.goauthentik.io/sign_out`) to pick up the login. With `lan_bypass`, LAN/Tailscale visitors skip Authentik, and `proxy_set_header Authorization` with the empty `$authentik_auth` drops the browser's own `Authorization` header, so an app that logs in with HTTP Basic can't be logged into from the LAN at all (form/cookie logins like AdGuard's only ask again); so the tool tells the assistant to confirm `lan_bypass` again whenever `basic_auth` is on. Omitting `basic_auth` when editing a site keeps its current setting; `basic_auth: false` removes the block and turns the provider option off (nginx first, so a rejected conf leaves both as they were).

**Names**: application and provider get the same display name (`app_name`, written like the existing ones: "AdGuard Home", "Paperless-ngx", "SPMusic"; default `SP<Name>` from the subdomain), and the slug is that name in lowercase with hyphens ("adguard-home"). A slug already used by another application stops the plan. Existing applications are found by the old `<sub>-<tld>` slug, their proxy provider's host, their OpenID redirect URIs, or their launch URL.

**Authentik providers** always use the `default-provider-authorization-implicit-consent` flow (no consent screen), like every provider set up so far; the other settings are copied from an existing provider of the same kind. OpenID providers are copied only from real OpenID providers (Authentik also lists proxy providers as OAuth2 ones), preferring one with a signing key (RS256).

**OpenID apps**: creating one returns the client ID and secret plus issuer, discovery URL, the single endpoints (authorize, token, userinfo, end-session, JWKS) for apps without discovery, scopes, claims (`preferred_username`, `email`, `groups`), the subject mode, signing algorithm, client authentication methods and PKCE. Later runs and `get_site` return the same without the secret (`get_site` with `show_secret: true` shows it). Existing apps set up by hand are found through their launch URL.

**Grant types** (OpenID providers, since 0.5.0): exactly `authorization_code` + `refresh_token`, all a web or mobile login needs. Newer Authentik (2026.x) creates providers with *no* grant types, and every login then fails at the authorize step with `invalid_request: The request is otherwise malformed`; the other grants (password, client_credentials, implicit, hybrid, device_code) would let tokens be had without the login flow and its MFA. New providers get the two; `get_site` lists a provider's grant types and warns when they differ; `publish_site` on a site whose existing OpenID provider differs plans an `update` that only sets the grant types (nothing else on a hand-made provider changes). Proxy providers keep the grant types Authentik gives them (the outpost needs them).

**Token validity** (since 0.5.0): `access_token_validity` and, for OpenID only, `refresh_token_validity`, in Authentik's duration syntax (`hours=24`, `days=7`, `days=1;hours=12`; anything else is refused). On a proxy provider `access_token_validity` is how long the Authentik login lasts before it's asked again: raise it for apps with long live connections (Foundry VTT's WebSocket drops when it runs out). On an OpenID provider it's the access-token lifetime, and `refresh_token_validity` is how long the app may stay signed in. Omitted = unchanged (new providers: Authentik's defaults); a change shows in the plan as `token_validity: {field: {from, to}}` and only those fields are patched. `get_site` shows the current values.

**Removal and AdGuard wildcards**: `remove_site` deletes exact rewrites only; when an enabled wildcard (e.g. `*.example.com`) still answers for the name, the plan and result say so in `still_resolves_via_wildcard`, so the LAN keeps resolving the name to SWAG, which then serves its default site.

**Access** (`allowed_users` / `allowed_groups` on `publish_site`, or the `site_access` tool): the complete list of Authentik users and groups that may use the application, as policy bindings (any one matching is enough). Omitted = unchanged; both empty = no restrictions (every Authentik user). Other policy bindings are kept. A new application without a list is open to every Authentik user, and the plan warns about it.

**Users** (since 0.6.0): `add_user` creates an Authentik user allowed into exactly one application (by `subdomain` or `application` slug), like the accounts made by hand: type `external`, path `users`, no groups, no roles, so never an admin (superuser comes only from groups; the result is checked and the user deleted again if Authentik gave it any). The user is *added* to the app's bindings (everyone already allowed keeps access; an app with `all` mode is switched to `any`). An app with no bindings is refused (binding one user would lock everyone else out: restrict it with `site_access` first), and the plan lists every other app without bindings, since those let any user in. Usernames and emails already in use (ignoring case, like the login) are refused; for an existing user use `site_access`. An email is required (since 0.6.1): no password goes through the tool, the user sets it with "Forgot password?" on the login page, i.e. Authentik's default recovery flow (`default-recovery-flow` from its `example/flows-recovery-email-verification.yaml` blueprint, left as shipped, with a Turnstile captcha), which emails them a link. Plan first, `apply: true` after confirmation.

**Changing a site**: call `publish_site` again for the same subdomain. Hand-written lines are kept; only the upstream (if the conf has a single `proxy_pass`), the Authentik includes, the Basic-auth block and the access lines at the top of `location /` change, and DNS/ddns/AdGuard follow the visibility. Turning Authentik off leaves its application in place (the plan says so). A conf that already matches is still checked with `nginx -t` and reloaded on apply (since 0.9.5), so hand edits are picked up. Refused (since 0.9.5): a conf that doesn't serve `<sub>.*` or the requested name (e.g. written for the other domain only), and any change to a conf that also serves other names, since the upstream and access lines are shared. The upstream must be a port, host:port or http(s) URL without whitespace, `;`, braces, quotes, `#`, `$` or `\` (it goes into `proxy_pass` as is).

**Removing a site** (`remove_site`): deletes the conf (backed up; refused if it also serves other names), then on every domain the Cloudflare records, ddns-updater entries, exact AdGuard rewrites (wildcards are left alone) and the Authentik application and provider.  For a proxy provider with Basic auth, it also deletes the `<prefix>_username`/`_password` attributes from every user and group that has them, unless another remaining provider uses the same attribute names (the plan lists attribute names and holders, never values).

**Removal clean-up beyond the site** (since 0.9.0, in the same plan → apply). Matching uses the site's upstreams (`proxy_pass`; when the conf is already gone, e.g. on a re-run, the newest conf backup in `/data/backups`, else `upstream`) and host names; the plan shows them under `matching`. The subdomain must be a plain label (`*` and the like are refused).
- **Authentik**: users and groups that only existed for this app (only its bindings refer to them; since 0.9.5 a user counts only when bound to the app by name, as `add_user` does, not when they only get in through a group). Superusers, service accounts, users/groups with roles, `BASIC_AUTH_USERS`, groups with parents or children and notification-rule groups are never touched. Order: Basic-auth attributes, orphans, providers, application last, so a re-run after a failure still finds everything through the app.
- **Integrations, only with `remove_integrations: true`** (since 0.9.3): unpublishing a site doesn't mean the app is gone (Home Assistant, LiteLLM itself, Nextcloud keep running), so by default the LiteLLM and Open WebUI items below are only listed under `check_by_hand.integrations`. Pass `remove_integrations: true` when the app itself (its container) was removed.
- **LiteLLM** (`LITELLM_KEY`): MCP servers and models whose URL/`api_base` points at the site. Entries in `litellm_config.yaml` are cut out with their own comment lines (backup in `/data/backups`; for a model only the deployments pointing at the site) and `lite-llm` is restarted a few seconds after the answer is sent, since the call usually comes through LiteLLM; DB entries are deleted by API. Keys whose alias is the site's name (e.g. `MyApp` for `spmyapp`) are deleted; keys whose MCP permissions name a removed or no longer existing server (by id, name or alias) are trimmed, except when nothing would be left: an empty list lifts the restriction, so those keys are only warned about. Variables only the removed entries used are listed in `unused_env` (delete them from the LiteLLM template). Keys that list a removed model are only warned about (an empty model list would mean every model).
- **Open WebUI** (`OWUI_API_KEY`): External Tools connections and OpenAI/Ollama connections pointing at the site, or at LiteLLM's per-server URL (`<litellm>/<server>/mcp`) of a removed MCP server.
- **Reported only** (`check_by_hand`, never blocks): the container on the upstream port (Docker API), its unRAID template and appdata folders (`/templates`; a template that only shares the host port is marked so and gets no folder suggestion; folders another container still mounts are listed under `shared_folders_keep`, and without the container list no folder is suggested for deletion), other SWAG confs on the same upstream, and Home Assistant (`HA_TOKEN`) dashboards, sidebar panels, automations, scripts and entity attributes mentioning the site (YAML-only config isn't visible).
- `keep`: plan labels to leave alone (`authentik user x`, `authentik group x`, `litellm key x`, `litellm mcp x`, `litellm model x`, `litellm config`, `openwebui tool <url>`, `openwebui openai <url>`, `openwebui ollama <url>`). `litellm mcp`/`litellm model` are applied while planning, so a kept server also keeps its key permissions and Open WebUI connection; pass the same `keep` on the plan and the apply call.
- A failed step doesn't stop the others; the result then has `rerun`: call again with the same arguments.

Each part is skipped (`action: skipped`) while its key is unset.

**Hardening check** (since 0.9.0): every `publish_site` plan lists `hardening` warnings for the conf as it will be: a 443 server without `include /config/nginx/ssl.conf` (country block, TLS settings), a catch-all `server_name`, another location that serves content (proxy/fastcgi/root/alias/try_files) without the LAN allow/deny lines or the Authentik include of `location /` (`internal`, `return` and `deny all` locations are fine), and a public site without Authentik. Confs from the template pass; the rest (country block, real IP from Cloudflare, default server refusing unknown hosts) is global in SWAG.

## Changelog (recent)

- **0.10.0** (2026-10-31, review): `LAN_BYPASS_RANGES`, `PUBLIC_NO_AUTH_ALLOW` and the `# publisher: locked` marker enforce the rules above on the server; `get_site` is no longer marked read-only, since `show_secret` returns a credential.
- **0.9.5** (2026-10-17, review): upstream validated before it goes into `proxy_pass` (`;`/braces/newlines could add nginx directives that `nginx -t` accepts), and replaced with a function (no `$1` expansion); `redirect_uris` must be single absolute URLs; `/mcp` refuses every request when `MCP_TOKEN` is unset (was open) and compares the token in constant time; `site_access` and `add_user` go through the same one-at-a-time queue as publish/remove; Authentik lists follow every page (a truncated binding/user list could make a user look orphaned); bindings are filtered by target client-side before any is planned for removal; a proxy application whose provider isn't the one for `https://<fqdn>` is refused (apply used to create a second provider the app didn't use); orphan users = bound by name only, group parents read as `parent` or `parents`; Cloudflare records matched by exact name client-side and TXT records no longer block publishing (several A records are refused); AdGuard answer = the most common answer on the domain, not the first rewrite found; LiteLLM config cut is refused if the file changed since planning (checked before any key/DB deletion); publish refuses confs that serve other names or not the requested domain; an unchanged conf gets `nginx -t` + reload on apply; Basic-auth/Authentik lines keep their indent after blank lines; conf-backup lookup sorted by timestamp.
- **0.9.4** (2026-10-17): proxy-provider PATCHes send the provider's current `mode` (`patchProvider`); without it Authentik answered 400 "Internal host cannot be empty when forward auth is disabled".

## Container

Image: `ghcr.io/drakknar/swag-publisher-mcp`, port 8080. Mounts:

| Container path | Holds |
|---|---|
| `/swag/site-confs` | SWAG's site confs |
| `/ddns/config.json` | ddns-updater's config |
| `/data` | backups |
| `/var/run/docker.sock` | `nginx -t`/reload in SWAG, restarting ddns-updater and LiteLLM, listing containers for `remove_site` |
| `/litellm` | `remove_site` edits `litellm_config.yaml` |
| `/templates` (read-only) | unRAID templates: `remove_site` reports them; they hold secrets, so only names and paths are read out |

Server-side rules (they hold whatever the caller sends):

- `lan_bypass` writes `LAN_BYPASS_RANGES`, by default `LAN_RANGES` without Docker's 172.16.0.0/12 networks, so containers don't skip Authentik.
- `visibility=public` with `auth=none` is refused unless the subdomain is in `PUBLIC_NO_AUTH_ALLOW` or the conf is already public with no login. An OpenID site looks like that in nginx, so it passes this check.
- A conf with the line `# publisher: locked` can't be published or removed through this tool, and `list_sites` and `get_site` show `locked: true`. Use it for sites whose loss would break access (the Authentik site, the editor) or that carry a hand-narrowed allow-list. `site_access` still works, since it changes only who may use the Authentik app.

Required variables: `MCP_TOKEN`, `DOMAINS`, `LAN_HOST`, `LAN_RANGES`, `ADGUARD_URL`, `AUTHENTIK_URL`, `AUTHENTIK_PUBLIC_URL`, `BASIC_AUTH_USERS`. The server won't start without the addresses, and without `MCP_TOKEN` every `/mcp` request gets 401.

Credentials: `CF_API_TOKEN` (Zone DNS Edit), `ADGUARD_USER` / `ADGUARD_PASSWORD`, `AUTHENTIK_TOKEN` (API token of an admin).

Optional, each part is skipped while its key is unset: `LITELLM_KEY` + `LITELLM_URL`, `OWUI_API_KEY` + `OWUI_URL`, `HA_TOKEN` + `HA_URL` (used read-only).

Other optional settings: `ADGUARD_ANSWER`, `SWAG_CONTAINER`, `DDNS_CONTAINER`, `LITELLM_CONFIG`, `LITELLM_CONTAINER`, `TEMPLATES_DIR`.
