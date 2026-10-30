// All settings come from the container's environment.
const env = process.env;

// No built-in addresses: a setting this server can't work without stops it at start-up.
function required(name) {
  if (!env[name]) throw new Error(`Environment variable ${name} is required`);
  return env[name];
}
const csv = (value) => value.split(",").map((x) => x.trim()).filter(Boolean);
const url = (value) => value.replace(/\/+$/, "");

const config = {
  port: Number(env.PORT || 8080),
  mcpToken: env.MCP_TOKEN || "",
  domains: csv(required("DOMAINS")),
  lanHost: required("LAN_HOST"),
  // Networks that count as "local": LAN, Tailscale, and Docker's networks. Other containers and Tailscale on the
  // host reach SWAG through the Docker bridge, never the internet.
  lanRanges: csv(required("LAN_RANGES")),

  swagConfDir: env.SWAG_CONF_DIR || "/swag/site-confs",
  swagContainer: env.SWAG_CONTAINER || "swag",
  backupDir: env.BACKUP_DIR || "/data/backups",

  dockerSocket: env.DOCKER_SOCKET || "/var/run/docker.sock",
  dockerHost: env.DOCKER_HOST_URL || "", // tests: http://127.0.0.1:port instead of the socket

  ddnsConfig: env.DDNS_CONFIG || "/ddns/config.json",
  ddnsContainer: env.DDNS_CONTAINER || "ddns-updater",

  cfToken: env.CF_API_TOKEN || "",
  cfApi: env.CF_API_URL || "https://api.cloudflare.com/client/v4",

  adguardUrl: url(required("ADGUARD_URL")),
  adguardUser: env.ADGUARD_USER || "",
  adguardPassword: env.ADGUARD_PASSWORD || "",
  adguardAnswer: env.ADGUARD_ANSWER || "", // default: copied from an existing rewrite, else LAN_HOST

  authentikUrl: url(required("AUTHENTIK_URL")),
  authentikPublicUrl: url(required("AUTHENTIK_PUBLIC_URL")),
  authentikToken: env.AUTHENTIK_TOKEN || "",
  // Authentik users that always get a site's Basic-auth login (publish_site can name more users/groups).
  basicAuthUsers: csv(required("BASIC_AUTH_USERS")),

  // remove_site's clean-up beyond the site itself; each part is skipped while its key/token is unset.
  litellmUrl: url(env.LITELLM_KEY ? required("LITELLM_URL") : ""),
  litellmKey: env.LITELLM_KEY || "",
  litellmConfig: env.LITELLM_CONFIG || "/litellm/litellm_config.yaml",
  litellmContainer: env.LITELLM_CONTAINER || "lite-llm",
  owuiUrl: url(env.OWUI_API_KEY ? required("OWUI_URL") : ""),
  owuiKey: env.OWUI_API_KEY || "",
  haUrl: url(env.HA_TOKEN ? required("HA_URL") : ""),
  haToken: env.HA_TOKEN || "",
  templatesDir: env.TEMPLATES_DIR || "/templates",
};

class StepError extends Error {}

module.exports = { config, StepError };
