import { describe, expect, it } from "vitest";

import {
  HOLD_REASON_MAX,
  type LegalHold,
  checkReason,
  holdScopeLabel,
  holdState,
  protectingHolds,
  releaseProtectsUntil,
  s3SyncLabel,
} from "@/lib/legal-holds";

const NOW = Date.parse("2026-11-06T12:00:00Z");

function hold(over: Partial<LegalHold> = {}): LegalHold {
  return {
    id: "h1",
    scope: "investigation",
    investigation_id: "inv1",
    case_ref: "CASE-00012",
    reason: "Litigation notice",
    placed_by: "u1",
    placed_by_name: "Alice",
    placed_at: "2026-11-01T12:00:00Z",
    released_by: null,
    released_at: null,
    release_reason: null,
    protects_until: null,
    active: true,
    s3_sync: "pending",
    s3_synced_at: null,
    ...over,
  };
}

describe("legal holds", () => {
  it("requires a reason of at most 500 characters", () => {
    expect(checkReason("   ")).toBe("A reason is required.");
    expect(checkReason("x".repeat(HOLD_REASON_MAX))).toBeNull();
    expect(checkReason("x".repeat(HOLD_REASON_MAX + 1))).toContain("At most 500");
  });

  it("keeps a released hold protecting until the delay passed (RT1)", () => {
    expect(holdState(hold(), NOW)).toBe("active");
    const released = { released_at: "2026-11-05T12:00:00Z", active: false };
    expect(holdState(hold({ ...released, protects_until: "2026-11-12T12:00:00Z" }), NOW)).toBe("protecting");
    expect(holdState(hold({ ...released, protects_until: "2026-11-06T11:00:00Z" }), NOW)).toBe("released");
    expect(protectingHolds([hold(), hold({ id: "h2", ...released, protects_until: "2026-10-01T00:00:00Z" })], NOW)).toHaveLength(1);
  });

  it("computes the protection end of a release now", () => {
    expect(releaseProtectsUntil(NOW, 7).toISOString()).toBe("2026-11-13T12:00:00.000Z");
  });

  it("shows the object-store sync for case holds only (RT5)", () => {
    expect(s3SyncLabel(hold())).toBe("Object-store hold: pending");
    expect(s3SyncLabel(hold({ s3_synced_at: "2026-11-06T12:01:00Z", s3_sync: "synced" }))).toBe("Object-store hold: synced");
    expect(s3SyncLabel(hold({ scope: "org", investigation_id: null }))).toBeNull();
  });

  it("labels the scope", () => {
    expect(holdScopeLabel(hold({ scope: "org", case_ref: null }))).toBe("Whole organization");
    expect(holdScopeLabel(hold())).toBe("CASE-00012");
  });
});
