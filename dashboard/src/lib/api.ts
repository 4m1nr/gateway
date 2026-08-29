/**
 * The dashboard's API client.
 *
 * Every mutating call carries the CSRF token the server issued at login, and a
 * 401 anywhere means the session is gone — the app returns to the login screen
 * rather than showing a page full of failed panels.
 */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

let csrf: string | null = null;
let onSignedOut: (() => void) | null = null;

export function setCsrf(token: string | null) {
  csrf = token;
}

/** Registered by the app so any request can send it back to the login screen. */
export function setSignedOutHandler(fn: () => void) {
  onSignedOut = fn;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRF-Token", csrf ?? "");
  }

  const res = await fetch(path, { ...init, headers, credentials: "same-origin" });

  let body: unknown = {};
  try {
    body = await res.json();
  } catch {
    // An empty or non-JSON body is fine for a 204, and for anything else the
    // status carries the meaning.
  }

  if (res.status === 401 && path !== "/api/login") {
    csrf = null;
    onSignedOut?.();
    throw new ApiError("signed out", 401);
  }
  if (!res.ok) {
    const message =
      typeof body === "object" && body !== null && "error" in body
        ? String((body as { error: unknown }).error)
        : `request failed (${res.status})`;
    throw new ApiError(message, res.status);
  }
  return body as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: JSON.stringify(body ?? {}) }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE", body: "{}" }),
};

// ---------------------------------------------------------------- types ----

export type TunnelState = "up" | "degraded" | "down" | "unknown";

export interface Unit {
  name: string;
  active: string;
  enabled: string;
}

export interface Traffic {
  uplink: number;
  downlink: number;
}

export interface Status {
  tunnel: TunnelState;
  detail: string;
  fails: number;
  lifeline: boolean;
  default_policy: string;
  lan: string;
  box_ip: string;
  profiles: string[];
  units: Unit[];
  firewall: {
    loaded: boolean;
    killswitch_drops: number;
    proxy_clients: string[];
    direct_clients: string[];
    blocked_clients: string[];
  };
  traffic: Record<string, Traffic>;
  system: {
    uptime: number;
    load: number[];
    mem_total: number;
    mem_available: number;
    disk_total: number;
    disk_free: number;
    time: number;
    xray_uptime_sec: number;
  };
}

export interface Client {
  ip: string;
  name: string;
  policy: string;
}

export interface ClientsResponse {
  clients: Client[];
  policies: string[];
  profiles: string[];
  default_policy: string;
  config_error?: string;
}

export interface Job {
  name: string;
  schedule: string;
  script: string;
  user: string;
  enabled: boolean;
  description: string;
  managed: boolean;
}

export interface Outbound {
  tag: string;
  origin: string;
  address: string;
  resolved_ip: string;
  json: string;
}

export interface Session {
  authenticated: boolean;
  password_set: boolean;
  /** Set when the privileged helper could not be reached at all. Distinct from
   *  password_set: one is fixed with `gw web-passwd`, the other is not. */
  helper_error: string;
  csrf: string | null;
}
