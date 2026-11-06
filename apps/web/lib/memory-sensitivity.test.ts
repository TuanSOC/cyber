import { describe, expect, it } from "vitest";

import {
  RELEASE_REASON_MAX,
  RELEASE_REASON_MIN,
  enrichDisabledReason,
  evidenceEnrichDisabledReason,
  releaseReady,
  restrictionOf,
} from "@/lib/memory-sensitivity";

describe("release", () => {
  it("needs the acknowledgement and a reason within bounds", () => {
    const reason = "Case closed; legal approved AI use.";
    expect(releaseReady(false, reason)).toBe(false);
    expect(releaseReady(true, "")).toBe(false);
    expect(releaseReady(true, " ".repeat(20))).toBe(false);
    expect(releaseReady(true, "x".repeat(RELEASE_REASON_MIN - 1))).toBe(false);
    expect(releaseReady(true, "x".repeat(RELEASE_REASON_MAX + 1))).toBe(false);
    expect(releaseReady(true, reason)).toBe(true);
  });
});

describe("restriction", () => {
  it("prefers the sensitivity route and falls back to the evidence field", () => {
    expect(restrictionOf("released", "restricted")).toBe("released");
    expect(restrictionOf(undefined, "restricted")).toBe("restricted");
    expect(restrictionOf(undefined, null)).toBe("none");
    expect(restrictionOf(undefined, undefined)).toBeNull();
  });
});

describe("Enrich on a memory job (RT16)", () => {
  it("is hidden while restricted, while the TI flag is set, and while unknown (fail closed)", () => {
    expect(enrichDisabledReason("restricted", false)).toMatch(/restricted/);
    expect(enrichDisabledReason("released", true)).toMatch(/share policy/);
    expect(enrichDisabledReason("none", true)).toMatch(/share policy/);
    expect(enrichDisabledReason(null, false)).toMatch(/unavailable/);
    expect(enrichDisabledReason("released", null)).toMatch(/unavailable/);
  });

  it("shows only once released and the TI flag is cleared", () => {
    expect(enrichDisabledReason("released", false)).toBeUndefined();
    expect(enrichDisabledReason("none", false)).toBeUndefined();
  });
});

describe("Enrich on the other analyses of the evidence", () => {
  it("hides it on restricted or TI-excluded evidence and while the record loads", () => {
    expect(evidenceEnrichDisabledReason(undefined)).toBeDefined();
    expect(evidenceEnrichDisabledReason({ memory_sensitivity: "restricted", ti_excluded: false })).toMatch(/restricted/);
    expect(evidenceEnrichDisabledReason({ memory_sensitivity: null, ti_excluded: true })).toMatch(/excludes/);
    expect(evidenceEnrichDisabledReason({ memory_sensitivity: "released", ti_excluded: false })).toBeUndefined();
    expect(evidenceEnrichDisabledReason({ memory_sensitivity: null, ti_excluded: false })).toBeUndefined();
  });
});
