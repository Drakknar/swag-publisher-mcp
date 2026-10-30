const http = require("http");
const { config, StepError } = require("./config");

// Minimal Docker Engine API client: only exec in a container and restart one.
function call(method, path, body) {
  return new Promise((resolve, reject) => {
    const target = config.dockerHost
      ? (() => {
          const u = new URL(config.dockerHost);
          return { host: u.hostname, port: u.port };
        })()
      : { socketPath: config.dockerSocket };
    const payload = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      { ...target, method, path, headers: payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {} },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      },
    );
    req.on("error", (e) => reject(new StepError(`Docker API unreachable: ${e.message}`)));
    req.setTimeout(60000, () => req.destroy(new Error("timeout")));
    req.end(payload);
  });
}

// Exec output is multiplexed: 8-byte frame headers (stream type + length) before each chunk.
function demux(buf) {
  let out = "";
  let i = 0;

  while (i + 8 <= buf.length && buf[i] <= 2 && buf[i + 1] === 0) {
    const len = buf.readUInt32BE(i + 4);
    out += buf.subarray(i + 8, i + 8 + len).toString("utf-8");
    i += 8 + len;
  }

  return i === 0 ? buf.toString("utf-8") : out;
}

async function exec(container, cmd) {
  const created = await call("POST", `/containers/${encodeURIComponent(container)}/exec`, {
    AttachStdout: true,
    AttachStderr: true,
    Cmd: cmd,
  });

  if (created.status !== 201) {
    throw new StepError(`Docker exec in ${container} failed (${created.status}): ${created.body.toString().slice(0, 300)}`);
  }

  const { Id } = JSON.parse(created.body);
  const started = await call("POST", `/exec/${Id}/start`, { Detach: false, Tty: false });
  const info = JSON.parse((await call("GET", `/exec/${Id}/json`)).body);
  return { exitCode: info.ExitCode, output: demux(started.body).trim() };
}

async function restart(container) {
  const r = await call("POST", `/containers/${encodeURIComponent(container)}/restart?t=10`);

  if (r.status !== 204) {
    throw new StepError(`Restarting ${container} failed (${r.status}): ${r.body.toString().slice(0, 300)}`);
  }
}

module.exports = { call, exec, restart, demux };
