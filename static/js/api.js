// Tiny fetch wrapper that auto-attaches the CSRF token and parses JSON.
// All state-changing requests must include X-CSRF-Token (read from the csrf
// cookie, which is set by the server on login).

function getCookie(name) {
  const m = document.cookie.match(new RegExp("(?:^|; )" + name.replace(/[$()*+./?[\\\]^{|}-]/g, "\\$&") + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

class ApiError extends Error {
  constructor(status, body) {
    const detail = (body && (body.detail || body.message)) || `HTTP ${status}`;
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
    this.status = status;
    this.body = body;
  }
}

async function request(method, path, body) {
  const headers = { "Accept": "application/json" };
  let payload = undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD") {
    const csrf = getCookie("csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  const res = await fetch(path, {
    method,
    headers,
    body: payload,
    credentials: "same-origin",
    cache: "no-store",
  });
  let parsed = null;
  if (res.status !== 204) {
    const text = await res.text();
    if (text) {
      try { parsed = JSON.parse(text); }
      catch { parsed = text; }
    }
  }
  if (!res.ok) throw new ApiError(res.status, parsed);
  return parsed;
}

export const api = {
  get:    (p)        => request("GET", p),
  post:   (p, body)  => request("POST", p, body ?? {}),
  put:    (p, body)  => request("PUT", p, body ?? {}),
  del:    (p)        => request("DELETE", p),
  ApiError,
};
