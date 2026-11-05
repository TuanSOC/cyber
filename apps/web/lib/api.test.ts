import { describe, expect, it } from "vitest";

import { ApiError, ensureOk, errorBodyExtra, unwrap } from "@/lib/api";

function errorResult(status: number, body: unknown, headers?: HeadersInit) {
  return { data: undefined, error: body, response: new Response(null, { status, headers }) };
}

function caught(fn: () => unknown): ApiError {
  try {
    fn();
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("expected an ApiError");
}

describe("unwrap", () => {
  it("returns the data of an ok answer", () => {
    expect(unwrap({ data: { a: 1 }, response: new Response(null, { status: 200 }) })).toEqual({ a: 1 });
  });

  it("keeps code, message, details, retry-after and the extra body fields", () => {
    const error = caught(() =>
      unwrap(
        errorResult(
          409,
          { error: { code: "policy_blocked", message: "blocked", details: { x: 1 }, reason: "case_ai_excluded", n: 3 } },
          { "retry-after": "12" },
        ),
      ),
    );
    expect(error.status).toBe(409);
    expect(error.code).toBe("policy_blocked");
    expect(error.message).toBe("blocked");
    expect(error.details).toEqual({ x: 1 });
    expect(error.retryAfterSeconds).toBe(12);
    expect(error.extra).toEqual({ reason: "case_ai_excluded", n: 3 });
    expect(error.extraString("reason")).toBe("case_ai_excluded");
    expect(error.extraString("n")).toBeNull();
  });

  it("falls back without a body and bounds extraString", () => {
    const error = caught(() => unwrap(errorResult(502, undefined)));
    expect(error.code).toBe("http_error");
    expect(error.extra).toEqual({});
    const long = caught(() => unwrap(errorResult(409, { error: { code: "c", message: "m", reason: "x".repeat(65) } })));
    expect(long.extraString("reason")).toBeNull();
    expect(long.extraString("reason", 100)).toHaveLength(65);
  });

  it("ensureOk keeps the extra fields too", () => {
    const error = caught(() => ensureOk(errorResult(409, { error: { code: "policy_blocked", message: "m", reason: "tlp_red" } })));
    expect(error.extraString("reason")).toBe("tlp_red");
  });

  it("errorBodyExtra ignores non-object bodies", () => {
    expect(errorBodyExtra(null)).toEqual({});
    expect(errorBodyExtra({ error: "text" })).toEqual({});
    expect(errorBodyExtra({ error: [1] })).toEqual({});
    expect(new ApiError(400, "c", "m").extra).toEqual({});
  });
});
