import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  STEP_UP_EVENT,
  type StepUpRequest,
  isMfaChallenge,
  requestStepUp,
  sessionFetch,
  stepUpDetails,
} from "@/lib/api";

const ORGS = "http://cyberlab.test/api/v1/orgs";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const STEP_UP = {
  error: { code: "step_up_required", message: "Confirm", action: "provider_key_change", methods: ["password", "bogus"] },
};

let target: EventTarget;

beforeEach(() => {
  target = new EventTarget();
  vi.stubGlobal("window", target);
  vi.stubGlobal("document", { cookie: "cl_csrf=test-token" });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function answerPrompts(confirmed: boolean): StepUpRequest[] {
  const seen: StepUpRequest[] = [];
  target.addEventListener(STEP_UP_EVENT, (event) => {
    event.preventDefault();
    const detail = (event as CustomEvent<StepUpRequest>).detail;
    seen.push(detail);
    detail.settle(confirmed);
  });
  return seen;
}

describe("step-up interception (M11)", () => {
  it("reads the action and the known methods of a step_up_required answer", async () => {
    expect(await stepUpDetails(json(403, STEP_UP))).toEqual({
      action: "provider_key_change",
      methods: ["password"],
    });
    expect(await stepUpDetails(json(403, { error: { code: "forbidden", message: "no" } }))).toBeNull();
    expect(await stepUpDetails(json(401, STEP_UP))).toBeNull();
  });

  it("is cancelled when no dialog takes the prompt", async () => {
    expect(await requestStepUp("tlp_downgrade", ["password"])).toBe(false);
  });

  it("shares one prompt between concurrent refusals", async () => {
    let settle: ((ok: boolean) => void) | undefined;
    let prompts = 0;
    target.addEventListener(STEP_UP_EVENT, (event) => {
      event.preventDefault();
      prompts += 1;
      settle = (event as CustomEvent<StepUpRequest>).detail.settle;
    });
    const first = requestStepUp("a", ["password"]);
    const second = requestStepUp("a", ["password"]);
    settle?.(true);
    expect(await Promise.all([first, second])).toEqual([true, true]);
    expect(prompts).toBe(1);
  });

  it("retries the request once after a confirmed step-up", async () => {
    const seen = answerPrompts(true);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(403, STEP_UP))
      .mockResolvedValueOnce(json(200, { items: [], total: 0 }));
    vi.stubGlobal("fetch", fetchMock);
    const response = await sessionFetch(new Request(ORGS, { method: "POST", body: "{}" }));
    expect(await response.json()).toEqual({ items: [], total: 0 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const retried = fetchMock.mock.calls[1][0] as Request;
    expect(retried.headers.get("X-CSRF-Token")).toBe("test-token");
    expect(await retried.text()).toBe("{}");
    expect(seen.map((s) => s.action)).toEqual(["provider_key_change"]);
  });

  it("surfaces the original error when the user cancels", async () => {
    answerPrompts(false);
    const fetchMock = vi.fn().mockResolvedValueOnce(json(403, STEP_UP));
    vi.stubGlobal("fetch", fetchMock);
    const response = await sessionFetch(new Request(ORGS, { method: "POST", body: "{}" }));
    expect(response.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("recognizes the login 202 MFA challenge", () => {
    expect(isMfaChallenge({ mfa_required: true, methods: ["totp"] })).toBe(true);
    expect(isMfaChallenge({ user: {}, memberships: [] })).toBe(false);
    expect(isMfaChallenge(null)).toBe(false);
  });
});
