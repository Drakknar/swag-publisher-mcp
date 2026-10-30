const { StepError } = require("./config");

// JSON request helper: throws StepError with the service's own message on failure.
async function request(service, url, { method = "GET", headers = {}, body } = {}) {
  let res;

  try {
    res = await fetch(url, {
      method,
      headers: { Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) {
    throw new StepError(`${service} unreachable (${url.split("?")[0]}): ${e.cause?.message || e.message}`);
  }

  const text = await res.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const detail = typeof data === "string" ? data : JSON.stringify(data);
    throw new StepError(`${service} ${method} ${url.split("?")[0]} failed (${res.status}): ${String(detail).slice(0, 400)}`);
  }

  return data;
}

module.exports = { request };
