import { describe, expect, it } from "vitest";

import {
  NEVER_PURGED,
  type RetentionPolicy,
  acknowledgementMatches,
  addDays,
  checkDays,
  countTotals,
  enforceState,
  enforcementStart,
  filterItems,
  outcomeOptionText,
  runHref,
  runItemsParams,
  formatDay,
  formatDays,
  hasPending,
  isLowering,
  labelText,
  loweredFields,
  loweringNotice,
  parseDays,
  pendingValue,
  policyBody,
  previewBody,
  targetValues,
} from "@/lib/retention";

const NOW = Date.parse("2026-11-06T12:00:00Z");

function policyFixture(over: Partial<RetentionPolicy> = {}): RetentionPolicy {
  return {
    ti_results_days: 365,
    ai_runs_days: null,
    closed_case_days: 730,
    pending_ti_results_days: null,
    pending_ai_runs_days: null,
    pending_closed_case_days: null,
    effective_at: null,
    enforce: false,
    pending_enforce: false,
    enforce_effective_at: null,
    delay_days: 7,
    floors: { ti_results_days: 30, ai_runs_days: 30, closed_case_days: 90 },
    updated_by: null,
    updated_at: null,
    ...over,
  };
}

describe("retention values", () => {
  it("formats keep forever and days", () => {
    expect(formatDays(null)).toBe("Keep forever");
    expect(formatDays(1)).toBe("1 day");
    expect(formatDays(36500)).toBe("36,500 days");
  });

  it("checks the floor and the upper bound", () => {
    expect(checkDays(null, 30)).toBeNull();
    expect(checkDays(29, 30)).toContain("At least 30 days");
    expect(checkDays(30, 30)).toBeNull();
    expect(checkDays(36501, 30)).toContain("At most");
    expect(checkDays(1.5, 30)).toBe("Whole days only.");
  });

  it("parses days inputs", () => {
    expect(parseDays("")).toBeNull();
    expect(parseDays(" 90 ")).toBe(90);
    expect(parseDays("9e3")).toBeNaN();
    expect(parseDays("-1")).toBeNaN();
  });

  it("knows what lowering is (a limit where there was none, or a shorter one)", () => {
    expect(isLowering(null, 90)).toBe(true);
    expect(isLowering(365, 90)).toBe(true);
    expect(isLowering(90, 365)).toBe(false);
    expect(isLowering(90, null)).toBe(false);
    const policy = policyFixture();
    expect(loweredFields(policy, { ti_results_days: 100, ai_runs_days: 60, closed_case_days: null })).toEqual([
      "ti_results_days",
      "ai_runs_days",
    ]);
  });

  it("names the delay and its date in the lowering notice", () => {
    const text = loweringNotice(["ti_results_days"], 7, NOW);
    expect(text).toContain("Threat-intel history");
    expect(text).toContain("7-day delay");
    expect(text).toContain(formatDay(addDays(NOW, 7)));
  });

  it("reads pending values only with effective_at, and targets them", () => {
    const pending = policyFixture({ pending_ti_results_days: 90, effective_at: "2026-11-13T12:00:00Z" });
    expect(pendingValue(pending, "ti_results_days")).toBe(90);
    expect(pendingValue(policyFixture({ pending_ti_results_days: 90 }), "ti_results_days")).toBeNull();
    expect(targetValues(pending)).toEqual({ ti_results_days: 90, ai_runs_days: null, closed_case_days: 730 });
    expect(hasPending(pending)).toBe(true);
    expect(hasPending(policyFixture())).toBe(false);
  });

  it("previews the effective policy by default and the targets with pending values", () => {
    const pending = policyFixture({ pending_ti_results_days: 90, effective_at: "2026-11-13T12:00:00Z" });
    expect(previewBody(pending, false)).toEqual({});
    expect(previewBody(pending, true)).toEqual({ ti_results_days: 90, ai_runs_days: null, closed_case_days: 730 });
  });
});

describe("enforcement", () => {
  it("is off by default, pending until the delay, then on", () => {
    expect(enforceState(policyFixture())).toBe("off");
    expect(enforceState(policyFixture({ pending_enforce: true, enforce_effective_at: "2026-11-13T12:00:00Z" }))).toBe(
      "pending",
    );
    expect(enforceState(policyFixture({ enforce: true }))).toBe("on");
  });

  it("compares the typed org name after NFC normalization and trimming", () => {
    const composed = "Caf\u00e9 SOC";
    const decomposed = "Cafe\u0301 SOC";
    expect(acknowledgementMatches(`  ${decomposed} `, composed)).toBe(true);
    expect(acknowledgementMatches("cafe soc", composed)).toBe(false);
    expect(acknowledgementMatches("Caf\u00e9", composed)).toBe(false);
    expect(acknowledgementMatches("", "")).toBe(false);
    expect(acknowledgementMatches("   ", "   ")).toBe(false);
  });

  it("starts enforcement after the delay", () => {
    expect(enforcementStart(policyFixture(), NOW).toISOString()).toBe("2026-11-13T12:00:00.000Z");
    const pending = policyFixture({ pending_enforce: true, enforce_effective_at: "2026-11-10T00:00:00Z" });
    expect(enforcementStart(pending, NOW).toISOString()).toBe("2026-11-10T00:00:00.000Z");
  });

  it("sends the acknowledgement only when turning enforcement on", () => {
    const values = { ti_results_days: 90, ai_runs_days: null, closed_case_days: 730 };
    expect(policyBody(values, true, true)).toEqual({ ...values, enforce: true, acknowledge_destruction: true });
    expect(policyBody(values, false, true)).toEqual({ ...values, enforce: false });
    expect(policyBody(values, true)).toEqual({ ...values, enforce: true });
  });

  it("lists what is never purged", () => {
    expect(NEVER_PURGED.join(" ")).toContain("hashes, custody, audit logs");
    expect(NEVER_PURGED.join(" ")).toContain("signed report snapshots");
  });
});

describe("runs", () => {
  it("totals the known categories only", () => {
    const count = { candidates: 2, rows: 10, bytes: 100, skipped_hold: 1, skipped_locked: 0, kept_cited: 3 };
    const totals = countTotals({ ti_results: count, closed_case: count, __proto__x: count });
    expect(totals).toEqual({ candidates: 4, rows: 20, bytes: 200, skipped_hold: 2, skipped_locked: 0, kept_cited: 6 });
  });

  it("filters items by outcome", () => {
    const base = { bytes: 0, category: "ti_results" as const, created_at: "2026-11-06T00:00:00Z", job_id: null, ref_id: "1", ref_table: "ti_results", rows: 1 };
    const items = [
      { ...base, id: "a", outcome: "purged" as const },
      { ...base, id: "b", outcome: "skipped_hold" as const },
    ];
    expect(filterItems(items, "all")).toHaveLength(2);
    expect(filterItems(items, "skipped_hold").map((item) => item.id)).toEqual(["b"]);
  });

  it("asks the API for one page of items, filtered by outcome (M7 follow-up)", () => {
    expect(runItemsParams({ outcome: "all", offset: 0 })).toEqual({ limit: 50, offset: 0 });
    expect(runItemsParams({ outcome: "skipped_hold", offset: 100 })).toEqual({ limit: 50, offset: 100, outcome: "skipped_hold" });
    expect(runItemsParams({ outcome: "all", offset: -3 })).toEqual({ limit: 50, offset: 0 });
    expect(runItemsParams({ outcome: "all", offset: Number.NaN })).toEqual({ limit: 50, offset: 0 });
    expect(outcomeOptionText("all", { purged: 3 }, 1200)).toBe("All (1,200)");
    expect(outcomeOptionText("purged", { purged: 3 }, 3)).toBe("Purged (3)");
    expect(outcomeOptionText("kept_cited", { purged: 3 }, 3)).toMatch(/\(0\)$/);
  });

  it("links a retention run by id only", () => {
    const org = "11111111-1111-4111-8111-111111111111";
    const run = "55555555-5555-4555-8555-555555555555";
    expect(runHref(org, run)).toBe(`/o/${org}/settings/retention/runs/${run}`);
    expect(runHref(org, "../../x")).toBeNull();
  });

  it("strips control and bidi characters from labels and caps them", () => {
    expect(labelText("ti\u202eresults\u0000")).toBe("tiresults");
    expect(labelText(null)).toBe("—");
    expect(labelText("x".repeat(100), 10)).toBe(`${"x".repeat(10)}…`);
  });
});
