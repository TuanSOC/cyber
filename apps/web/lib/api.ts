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
// No retry-after-refresh for the auth endpoints themselves (M11: a 401 of the MFA verify is a
// wrong code or an expired challenge, never an expired session).
const NO_REFRESH = [
  "/api/v1/auth/login",
  "/api/v1/auth/register",
  "/api/v1/auth/refresh",
  "/api/v1/auth/mfa/verify",
];

export const AUTH_EXPIRED_EVENT = "cyberlab:auth-expired";

/**
 * M11: a `403 step_up_required` asks the user to confirm their identity. `sessionFetch`
 * dispatches this (cancelable) event once per prompt; the step-up dialog (mounted once in the
 * app shell, phase 10) calls `event.preventDefault()` to take it, then `settle(true)` after a
 * successful `POST /auth/step-up` (the request is retried once) or `settle(false)` when the
 * user cancels (the caller gets the original `ApiError`). Nobody listening = cancelled.
 */
export const STEP_UP_EVENT = "cyberlab:step-up-required";

export type StepUpMethod = "totp" | "recovery_code" | "password" | "sso";

export type StepUpRequest = {
  /** The `StepUpAction` the API named (e.g. `provider_key_change`). */
  action: string;
  methods: StepUpMethod[];
  settle: (confirmed: boolean) => void;
};

// The step-up endpoints never prompt for a step-up themselves.
const NO_STEP_UP = ["/api/v1/auth/step-up", "/api/v1/auth/sso/start"];

let stepUpInFlight: Promise<boolean> | null = null;

/** Single-flight: concurrent step-up refusals in this tab share one prompt. */
export function requestStepUp(action: string, methods: StepUpMethod[]): Promise<boolean> {
  stepUpInFlight ??= new Promise<boolean>((resolve) => {
    const detail: StepUpRequest = { action, methods, settle: resolve };
    const event = new CustomEvent<StepUpRequest>(STEP_UP_EVENT, { detail, cancelable: true });
    // dispatchEvent is false only when a listener called preventDefault (took the prompt).
    if (typeof window === "undefined" || window.dispatchEvent(event)) resolve(false);
  }).finally(() => {
    stepUpInFlight = null;
  });
  return stepUpInFlight;
}

/** The step-up details of a `403 step_up_required` response, else null. */
export async function stepUpDetails(
  response: Response,
): Promise<{ action: string; methods: StepUpMethod[] } | null> {
  if (response.status !== 403) return null;
  const body = (await response.clone().json().catch(() => null)) as ApiErrorBody | null;
  if (body?.error?.code !== "step_up_required") return null;
  const action = typeof body.error.action === "string" ? body.error.action : "";
  const raw = Array.isArray(body.error.methods) ? body.error.methods : [];
  const allowed: StepUpMethod[] = ["totp", "recovery_code", "password", "sso"];
  const methods = raw.filter((m): m is StepUpMethod => allowed.includes(m as StepUpMethod));
  return { action, methods };
}

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
// M11: a login answers 202 (MFA challenge, no session yet) or 200; the MFA verify completes it.
const SESSION_START = ["/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/mfa/verify"];
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

/** The fetch of `api` (exported for its tests): CSRF header, refresh retry, step-up retry. */
export async function sessionFetch(input: Request): Promise<Response> {
  const requestPath = new URL(input.url).pathname;
  if (signedOut && !ALLOWED_SIGNED_OUT.includes(requestPath)) return signedOutResponse();
  // openapi-fetch only sends small JSON bodies, so keeping a replay copy is cheap. Large
  // evidence uploads go through XHR (lib/upload.ts) and never through here.
  const replay = input.clone();
  let response = await fetch(withCsrf(input));
  const path = new URL(input.url).pathname;
  // 200 / 201 only: a 202 login is an MFA challenge, not a session (M11).
  if ((response.status === 200 || response.status === 201) && SESSION_START.includes(path)) {
    signedOut = false;
  }
  if (response.status === 401 && !NO_REFRESH.includes(path)) {
    const refreshed = await refreshSession();
    if (refreshed === "expired") window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
    // "unavailable": keep the session, surface the original error to the caller.
    if (refreshed !== "ok") return response;
    response = await fetch(withCsrf(replay.clone()));
  }
  if (response.status === 403 && !NO_STEP_UP.includes(path)) {
    const stepUp = await stepUpDetails(response);
    if (stepUp && (await requestStepUp(stepUp.action, stepUp.methods))) {
      // Retried once; a second refusal reaches the caller as an ApiError.
      return fetch(withCsrf(replay.clone()));
    }
  }
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
/** M11: the `202` of `POST /auth/login` when a second factor is needed (no session yet). */
export type MfaChallenge = Schemas["MfaChallengeOut"];

export function isMfaChallenge(value: unknown): value is MfaChallenge {
  return (
    typeof value === "object" && value !== null && (value as { mfa_required?: unknown }).mfa_required === true
  );
}
export type MemberRole = Schemas["MemberRole"];
