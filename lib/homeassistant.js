const { config, StepError } = require("./config");

// Report only: Home Assistant dashboards, sidebar panels, automations and scripts that still mention the
// site (its host names or upstream host:port). YAML-only things (rest_command, configuration.yaml) aren't visible.

function connect() {
  return new Promise((resolve, reject) => {
    const url = config.haUrl.replace(/^http/, "ws") + "/api/websocket";
    let ws;

    try {
      ws = new WebSocket(url);
    } catch (e) {
      reject(new StepError(`Home Assistant websocket failed: ${e.message}`));
      return;
    }

    let id = 0;
    const waiting = new Map();
    const timer = setTimeout(() => {
      reject(new StepError("Home Assistant websocket: no answer in 20 s"));
      ws.close();
    }, 20000);

    // remove_site runs one at a time, so no call may hang: each one times out, and a dropped socket fails them all.
    const call = (msg) =>
      new Promise((res, rej) => {
        const n = ++id;
        const t = setTimeout(() => {
          waiting.delete(n);
          rej(new StepError(`Home Assistant: no answer to ${msg.type} in 20 s`));
        }, 20000);
        waiting.set(n, {
          res: (v) => (clearTimeout(t), res(v)),
          rej: (e) => (clearTimeout(t), rej(e)),
        });
        ws.send(JSON.stringify({ id: n, ...msg }));
      });

    const fail = (e) => {
      clearTimeout(timer);
      reject(e);
      waiting.forEach((w) => w.rej(e));
      waiting.clear();
    };

    ws.onerror = () => fail(new StepError(`Home Assistant unreachable at ${url}`));
    ws.onclose = () => fail(new StepError("Home Assistant closed the websocket"));
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);

      if (msg.type === "auth_required") {
        ws.send(JSON.stringify({ type: "auth", access_token: config.haToken }));
      } else if (msg.type === "auth_invalid") {
        fail(new StepError("Home Assistant rejected HA_TOKEN"));
      } else if (msg.type === "auth_ok") {
        clearTimeout(timer);
        resolve({ call, close: () => ws.close() });
      } else if (msg.type === "result" && waiting.has(msg.id)) {
        const w = waiting.get(msg.id);
        waiting.delete(msg.id);
        msg.success ? w.res(msg.result) : w.rej(new Error(msg.error?.message || "failed"));
      }
    };
  });
}

// One unreadable automation/script config must not end the whole scan.
async function rest(p) {
  try {
    const res = await fetch(`${config.haUrl}${p}`, { headers: { Authorization: `Bearer ${config.haToken}` }, signal: AbortSignal.timeout(15000) });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

async function scan(m) {
  if (!config.haToken) {
    return { action: "skipped", reason: "HA_TOKEN not set" };
  }

  const ha = await connect();
  const found = [];

  try {
    const panels = await ha.call({ type: "get_panels" });

    for (const p of Object.values(panels || {})) {
      if (m.text(JSON.stringify(p.config || {}))) {
        found.push(`sidebar panel "${p.title || p.url_path}" (/${p.url_path})`);
      }
    }

    const dashboards = [{ url_path: null, title: "Overview (default)" }, ...((await ha.call({ type: "lovelace/dashboards/list" }).catch(() => [])) || [])];

    for (const d of dashboards) {
      const cfg = await ha.call({ type: "lovelace/config", url_path: d.url_path, force: false }).catch(() => null);

      if (cfg && m.text(JSON.stringify(cfg))) {
        found.push(`dashboard "${d.title}"${d.url_path ? ` (/${d.url_path})` : ""}`);
      }
    }

    const states = await ha.call({ type: "get_states" });

    for (const s of states) {
      const [domain, objectId] = s.entity_id.split(".");
      let cfg = null;

      if (domain === "automation" && s.attributes?.id) {
        cfg = await rest(`/api/config/automation/config/${encodeURIComponent(s.attributes.id)}`);
      } else if (domain === "script") {
        cfg = await rest(`/api/config/script/config/${encodeURIComponent(objectId)}`);
      }

      if ((cfg && m.text(JSON.stringify(cfg))) || m.text(JSON.stringify(s.attributes || {}))) {
        found.push(`${s.entity_id}${s.attributes?.friendly_name ? ` ("${s.attributes.friendly_name}")` : ""}`);
      }
    }
  } finally {
    ha.close();
  }

  return found.length
    ? { action: "check_by_hand", mentions: found, note: "Not changed automatically. YAML-only config (rest_command, configuration.yaml, packages) isn't scanned." }
    : { action: "none", note: "Dashboards, panels, automations, scripts and entity attributes scanned; YAML-only config isn't." };
}

module.exports = { scan };
