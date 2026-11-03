import type { paths, Schemas } from "@cyberlab/contracts";
import createClient from "openapi-fetch";

import { readCsrfToken } from "@/lib/csrf";

export type ApiErrorBody = { error: { code: string; message: string; details?: unknown } };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
// No retry-after-refresh for the auth endpoints themselves.
const NO_REFRESH = ["/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh"];

export const AUTH_EXPIRED_EVENT = "cyberlab:auth-expired";

function withCsrf(request: Request): Request {
  if (SAFE_METHODS.has(request.method)) return request;
  const headers = new Headers(request.headers);
  // Read at request time: the token rotates on every refresh.
  headers.set("X-CSRF-Token", readCsrfToken());
  return new Request(request, { headers });
}

/** ok: new tokens set. expired: the session is gone (log in again). unavailable: API/Redis down. */
export type RefreshResult = "ok" | "expired" | "unavailable";

let refreshInFlight: Promise<RefreshResult> | null = null;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function refreshOnce(): Promise<RefreshResult> {
  const attempt = () =>
    fetch("/api/v1/auth/refresh", {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": readCsrfToken() },
    });
  try {
    let response = await attempt();
    if (response.status === 401) {
      const body = (await response.json().catch(() => null)) as ApiErrorBody | null;
      if (body?.error.code === "stale_refresh") {
        // Another tab rotated a moment ago and the jar already has its cookies: retry once.
        await sleep(300);
        response = await attempt();
      }
    }
    if (response.ok) return "ok";
    // 401 = invalid/reused/stale session; 403 = no CSRF cookie (session already gone).
    return response.status === 401 || response.status === 403 ? "expired" : "unavailable";
  } catch {
    return "unavailable";
  }
}

/** Single-flight: concurrent 401s in this tab share one refresh. */
export function refreshSession(): Promise<RefreshResult> {
  refreshInFlight ??= refreshOnce().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

async function sessionFetch(input: Request): Promise<Response> {
  // openapi-fetch only sends small JSON bodies, so keeping a replay copy is cheap. Large
  // evidence uploads go through XHR (lib/upload.ts) and never through here.
  const retry = input.clone();
  const response = await fetch(withCsrf(input));
  const path = new URL(input.url).pathname;
  if (response.status !== 401 || NO_REFRESH.includes(path)) return response;

  const refreshed = await refreshSession();
  if (refreshed === "ok") return fetch(withCsrf(retry));
  if (refreshed === "expired") window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
  // "unavailable": keep the session, surface the original error to the caller.
  return response;
}

export const api = createClient<paths>({
  baseUrl: "",
  credentials: "include",
  fetch: sessionFetch,
});

/** Unwrap an openapi-fetch result or throw a typed ApiError. */
export function unwrap<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.data !== undefined && result.response.ok) return result.data;
  const body = result.error as ApiErrorBody | undefined;
  const retryAfter = Number(result.response.headers.get("retry-after"));
  throw new ApiError(
    result.response.status,
    body?.error?.code ?? "http_error",
    body?.error?.message ?? `Request failed (${result.response.status})`,
    body?.error?.details,
    Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
  );
}

/** For 204 responses (no body). */
export function ensureOk(result: { error?: unknown; response: Response }): void {
  if (result.response.ok) return;
  unwrap({ ...result, data: undefined });
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "rate_limited") {
      const wait = error.retryAfterSeconds;
      return wait
        ? `Too many attempts. Try again in ${wait < 90 ? `${wait} s` : `${Math.ceil(wait / 60)} min`}.`
        : "Too many attempts. Please wait and try again.";
    }
    if (error.code === "service_unavailable") return "The service is temporarily unavailable.";
    return error.message;
  }
  return "Something went wrong. Please try again.";
}

export type Me = Schemas["MeOut"];
export type MemberRole = Schemas["MemberRole"];
