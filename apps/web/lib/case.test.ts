import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, unwrap } from "@/lib/api";
import {
  PolicyApiError,
  caseErrorMessage,
  caseTabHref,
  checkStatusReason,
  evidenceExclusionBadges,
  filenameFromDisposition,
  isCaseEvent,
  isPolicyBlocked,
  needsStatusReason,
  parseCaseTab,
  policyBlockedReason,
  saveBlob,
  saveDownload,
  sharePolicyLine,
  shareReasonText,
  shareToggleState,
  unwrapCase,
  visText,
} from "@/lib/case";

const ORG = "11111111-1111-4111-8111-111111111111";
const INV = "22222222-2222-4222-8222-222222222222";

function errorResult(status: number, body: unknown) {
  return { data: undefined, error: body, response: new Response(null, { status }) };
}

describe("tabs", () => {
  it("parses ?tab= with an overview fallback", () => {
    expect(parseCaseTab("notes")).toBe("notes");
    expect(parseCaseTab("attack")).toBe("attack");
    expect(parseCaseTab("javascript:alert(1)")).toBe("overview");
    expect(parseCaseTab(null)).toBe("overview");
  });

  it("builds encoded case links with an optional anchor", () => {
    expect(caseTabHref(ORG, INV)).toBe(`/o/${ORG}/investigations/${INV}`);
    expect(caseTabHref(ORG, INV, "overview", "share-policy")).toBe(`/o/${ORG}/investigations/${INV}#share-policy`);
    expect(caseTabHref(ORG, "a/b", "iocs")).toBe(`/o/${ORG}/investigations/a%2Fb?tab=iocs`);
  });
});

describe("status workflow", () => {
  it("needs a reason to close, archive and reopen", () => {
    expect(needsStatusReason("open", "closed")).toBe(true);
    expect(needsStatusReason("in_progress", "closed")).toBe(true);
    expect(needsStatusReason("closed", "archived")).toBe(true);
    expect(needsStatusReason("closed", "in_progress")).toBe(true);
    expect(needsStatusReason("open", "in_progress")).toBe(false);
  });

  it("checks the reason text", () => {
    expect(checkStatusReason("  ")).toEqual({ ok: false, message: "A reason is required." });
    expect(checkStatusReason("x".repeat(501)).ok).toBe(false);
    expect(checkStatusReason("a\u0000b").ok).toBe(false);
    expect(checkStatusReason("  done  ")).toEqual({ ok: true, reason: "done" });
  });
});

describe("share policy", () => {
  it("TLP:RED forces both flags on, whatever the role", () => {
    for (const perms of [
      { canTurnOn: false, canTurnOff: false },
      { canTurnOn: true, canTurnOff: false },
      { canTurnOn: true, canTurnOff: true },
    ]) {
      const state = shareToggleState({ flag: false, tlpRed: true, ...perms });
      expect(state).toMatchObject({ checked: true, disabled: true });
      expect(state.note).toContain("TLP:RED");
    }
  });

  it("role matrix: viewer, analyst, admin", () => {
    const viewer = { canTurnOn: false, canTurnOff: false };
    const analyst = { canTurnOn: true, canTurnOff: false };
    const admin = { canTurnOn: true, canTurnOff: true };
    // Turning on.
    expect(shareToggleState({ flag: false, tlpRed: false, ...viewer }).disabled).toBe(true);
    expect(shareToggleState({ flag: false, tlpRed: false, ...analyst }).disabled).toBe(false);
    expect(shareToggleState({ flag: false, tlpRed: false, ...admin }).disabled).toBe(false);
    // Turning off: admin only, with the reason shown.
    const analystOff = shareToggleState({ flag: true, tlpRed: false, ...analyst });
    expect(analystOff).toMatchObject({ checked: true, disabled: true });
    expect(analystOff.note).toContain("integrations.manage");
    expect(shareToggleState({ flag: true, tlpRed: false, ...admin }).disabled).toBe(false);
    // Archived: read-only for everyone.
    expect(shareToggleState({ flag: false, tlpRed: false, readOnly: true, ...admin }).disabled).toBe(true);
  });

  it("explains the computed policy", () => {
    expect(sharePolicyLine({ ai_blocked: false, ti_blocked: false, reasons: [] })).toContain("allowed");
    const red = sharePolicyLine({ ai_blocked: true, ti_blocked: true, reasons: ["tlp_red"] });
    expect(red).toContain("AI and threat-intel providers");
    expect(red).toContain("TLP:RED");
    expect(shareReasonText("weird_code")).toContain("weird_code");
    expect(evidenceExclusionBadges({ ai_excluded: true, ti_excluded: false })).toEqual(["No AI"]);
  });
});

describe("errors", () => {
  it("keeps the policy_blocked reason through unwrapCase", () => {
    let caught: unknown;
    try {
      unwrapCase(errorResult(409, { error: { code: "policy_blocked", message: "blocked", reason: "case_ai_excluded" } }));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect(isPolicyBlocked(caught)).toBe(true);
    expect(policyBlockedReason(caught)).toBe("case_ai_excluded");
    expect(caseErrorMessage(caught)).toBe("The case is marked “do not send to AI”.");
  });

  it("keeps the reason through the shared unwrap (AI / TI wrappers) and a hand-built PolicyApiError", () => {
    let caught: unknown;
    try {
      unwrap(errorResult(409, { error: { code: "policy_blocked", message: "blocked", reason: "tlp_red" } }));
    } catch (error) {
      caught = error;
    }
    expect(policyBlockedReason(caught)).toBe("tlp_red");
    expect(caseErrorMessage(caught)).toContain("TLP:RED");
    const manual = new PolicyApiError(new ApiError(409, "policy_blocked", "x"), "evidence_ti_excluded");
    expect(manual.reason).toBe("evidence_ti_excluded");
    expect(policyBlockedReason(manual)).toBe("evidence_ti_excluded");
    // A reason on another code is not a policy reason.
    expect(policyBlockedReason(new ApiError(409, "ai_busy", "x", undefined, undefined, { reason: "tlp_red" }))).toBeNull();
  });

  it("ignores a non-string or oversized reason", () => {
    for (const reason of [42, "x".repeat(65)]) {
      let caught: unknown;
      try {
        unwrapCase(errorResult(409, { error: { code: "policy_blocked", message: "b", reason } }));
      } catch (error) {
        caught = error;
      }
      expect(policyBlockedReason(caught)).toBeNull();
      expect(caseErrorMessage(caught)).toContain("share policy");
    }
  });

  it("maps the stable codes, 403 and 404", () => {
    const mk = (status: number, code: string) => new ApiError(status, code, "server text");
    expect(caseErrorMessage(mk(409, "stale_note"))).toContain("edited this note");
    expect(caseErrorMessage(mk(422, "status_reason_required"))).toContain("reason is required");
    expect(caseErrorMessage(mk(403, "tlp_downgrade_forbidden"))).toContain("org.update");
    expect(caseErrorMessage(mk(403, "forbidden"))).toBe("Your role does not allow this action.");
    expect(caseErrorMessage(mk(404, "not_found"))).toContain("Not found");
    expect(caseErrorMessage(mk(501, "not_implemented"))).toContain("not available yet");
    expect(caseErrorMessage(mk(400, "other"))).toBe("server text");
    // A plain ApiError from lib/api (AI / TI paths) has no reason: generic text.
    expect(policyBlockedReason(mk(409, "policy_blocked"))).toBeNull();
    expect(isPolicyBlocked(mk(409, "policy_blocked"))).toBe(true);
    expect(isPolicyBlocked(new Error("x"))).toBe(false);
  });
});

describe("visible invisibles", () => {
  it("marks bidi, zero-width and control characters, keeps newlines and tabs", () => {
    expect(visText("a‮b")).toBe("a⟨U+202E⟩b");
    expect(visText("x​y")).toBe("x⟨U+200B⟩y");
    expect(visText("l1\nl2\tz")).toBe("l1\nl2\tz");
    expect(visText("\u0007")).toBe("⟨U+0007⟩");
    expect(visText(null)).toBe("");
  });
});

describe("timeline", () => {
  it("treats entries without evidence as case events", () => {
    expect(isCaseEvent({ evidence_id: null })).toBe(true);
    expect(isCaseEvent({ evidence_id: INV })).toBe(false);
  });
});

describe("downloads", () => {
  afterEach(() => vi.useRealTimers());

  it("reads the filename from Content-Disposition", () => {
    expect(filenameFromDisposition(`attachment; filename*=UTF-8''CASE-00012%20iocs.csv`)).toBe("CASE-00012 iocs.csv");
    expect(filenameFromDisposition(`attachment; filename="plain.json"`)).toBe("plain.json");
    expect(filenameFromDisposition(`attachment; filename="fallback.csv"; filename*=UTF-8''%E2%9C%93.csv`)).toBe("✓.csv");
    expect(filenameFromDisposition("attachment; filename=bare.stix.json")).toBe("bare.stix.json");
    // Path parts, leading dots, control and bidi characters are removed.
    expect(filenameFromDisposition(`attachment; filename="../../etc/passwd"`)).toBe("_.._etc_passwd");
    expect(filenameFromDisposition(`attachment; filename*=UTF-8''evil%E2%80%AEtxt.exe`)).toBe("eviltxt.exe");
    expect(filenameFromDisposition("attachment")).toBeNull();
    expect(filenameFromDisposition(null)).toBeNull();
  });

  it("saves under the server filename and revokes the blob URL", () => {
    vi.useFakeTimers();
    const created: string[] = [];
    const revoked: string[] = [];
    const clicks: [string, string][] = [];
    const deps = {
      createObjectURL: () => {
        created.push("blob:1");
        return "blob:1";
      },
      revokeObjectURL: (url: string) => revoked.push(url),
      click: (href: string, name: string) => clicks.push([href, name]),
    };
    const response = new Response("a,b", {
      status: 200,
      headers: { "content-disposition": `attachment; filename*=UTF-8''case.csv` },
    });
    const name = saveDownload({ data: new Blob(["a,b"]), response }, "fallback.csv", deps);
    expect(name).toBe("case.csv");
    expect(clicks).toEqual([["blob:1", "case.csv"]]);
    vi.runAllTimers();
    expect(revoked).toEqual(created);
  });

  it("revokes even when the click throws", () => {
    vi.useFakeTimers();
    const revoked: string[] = [];
    expect(() =>
      saveBlob(new Blob(["x"]), "x.txt", {
        createObjectURL: () => "blob:2",
        revokeObjectURL: (url) => revoked.push(url),
        click: () => {
          throw new Error("blocked");
        },
      }),
    ).toThrow("blocked");
    vi.runAllTimers();
    expect(revoked).toEqual(["blob:2"]);
  });

  it("turns a failed export into a typed error and saves nothing", () => {
    const deps = { createObjectURL: vi.fn(() => "blob:3"), revokeObjectURL: vi.fn(), click: vi.fn() };
    expect(() =>
      saveDownload(errorResult(403, { error: { code: "forbidden", message: "nope" } }), "x.csv", deps),
    ).toThrow(ApiError);
    expect(deps.createObjectURL).not.toHaveBeenCalled();
  });
});
