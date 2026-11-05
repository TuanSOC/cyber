import type { paths, Schemas } from "@cyberlab/contracts";
import createClient from "openapi-fetch";

import { readCsrfToken } from "@/lib/csrf";

export type ApiErrorBody = {
  error: { code: string; message: string; details?: unknown; [field: string]: unknown };
};

const NO_EXTRA: Readonly<Record<string, unknown>> = Object.freeze({});

export class ApiError extends Error {
  /**
   * The other fields of the error body (`reason` of a `409 policy_blocked`, `section_units` of
   * a report error...), without `code`, `message` and `details`. Data only, never rendered raw.
   */
  readonly extra: Readonly<Record<string, unknown>>;

  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
    readonly retryAfterSeconds?: number,
    extra?: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.extra = extra ?? NO_EXTRA;
  }

  /** A string field of the error body (e.g. `reason`), at most `maxLength` characters; else null. */
  extraString(field: string, maxLength = 64): string | null {
    const value = Object.hasOwn(this.extra, field) ? this.extra[field] : undefined;
    return typeof value === "string" && value.length > 0 && value.length <= maxLength ? value : null;
  }
}

/** The fields of an error body's `error` object other than code / message / details. */
export function errorBodyExtra(body: unknown): Readonly<Record<string, unknown>> {
  const error = (body as { error?: unknown } | null | undefined)?.error;
  if (!error || typeof error !== "object" || Array.isArray(error)) return NO_EXTRA;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(error)) {
    if (key !== "code" && key !== "message" && key !== "details") out[key] = value;
  }
  return Object.keys(out).length ? out : NO_EXTRA;
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

// Set on sign-out until the next successful login/register: polling queries still mounted
// during the navigation must not hit the API (and log 401/403s) with a dead session.
let signedOut = false;
const SESSION_START = ["/api/v1/auth/login", "/api/v1/auth/register"];
// Still allowed after endSession(): the logout call itself and starting a new session.
const ALLOWED_SIGNED_OUT = [...SESSION_START, "/api/v1/auth/logout"];

export function endSession(): void {
  signedOut = true;
}

function signedOutResponse(): Response {
  const body: ApiErrorBody = { error: { code: "unauthorized", message: "Signed out" } };
  return new Response(JSON.stringify(body), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}

async function sessionFetch(input: Request): Promise<Response> {
  const requestPath = new URL(input.url).pathname;
  if (signedOut && !ALLOWED_SIGNED_OUT.includes(requestPath)) return signedOutResponse();
  // openapi-fetch only sends small JSON bodies, so keeping a replay copy is cheap. Large
  // evidence uploads go through XHR (lib/upload.ts) and never through here.
  const retry = input.clone();
  const response = await fetch(withCsrf(input));
  const path = new URL(input.url).pathname;
  if (response.ok && SESSION_START.includes(path)) signedOut = false;
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
    errorBodyExtra(body),
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
