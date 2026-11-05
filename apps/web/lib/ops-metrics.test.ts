import { describe, expect, it } from "vitest";

import {
  type KindMetrics,
  activeTotal,
  errorClassSummary,
  errorClassText,
  errorCodeText,
  failureHref,
  failureKindLabel,
  recentFailures,
  formatDuration,
  formatRatio,
  kindLabel,
  sortedItems,
} from "@/lib/ops-metrics";

function item(over: Partial<KindMetrics>): KindMetrics {
  return {
    kind: "pcap",
    subkind: null,
    total: 0,
    succeeded: 0,
    failed: 0,
    failure_ratio: null,
    parse_success_ratio: null,
    queue_p50_ms: null,
    queue_p95_ms: null,
    run_p50_ms: null,
    run_p95_ms: null,
    error_classes: {},
    ...over,
  };
}

describe("operations numbers formatting", () => {
  it("formats ratios as percentages", () => {
    expect(formatRatio(null)).toBe("—");
    expect(formatRatio(0)).toBe("0 %");
    expect(formatRatio(0.125)).toBe("12.5 %");
    expect(formatRatio(1)).toBe("100 %");
    expect(formatRatio(2 / 3)).toBe("66.7 %");
    expect(formatRatio(Number.NaN)).toBe("—");
  });

  it("formats durations", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(-1)).toBe("—");
    expect(formatDuration(850)).toBe("850 ms");
    expect(formatDuration(4200)).toBe("4.2 s");
    expect(formatDuration(42_000)).toBe("42 s");
    expect(formatDuration(185_000)).toBe("3 min 05 s");
    expect(formatDuration(7_800_000)).toBe("2 h 10 min");
  });

  it("labels and orders kinds", () => {
    expect(kindLabel(item({ kind: "static", subkind: "full" }))).toBe("Static analysis · full");
    expect(kindLabel(item({ kind: "ai", subkind: "<b>x</b>" }))).toBe("AI analyst · bxb");
    const sorted = sortedItems([item({ kind: "report" }), item({ kind: "static", subkind: "full" }), item({ kind: "static", subkind: "av" }), item({ kind: "pcap" })]);
    expect(sorted.map((row) => `${row.kind}:${row.subkind ?? ""}`)).toEqual(["pcap:", "static:av", "static:full", "report:"]);
  });

  it("summarises error classes, largest first", () => {
    expect(errorClassSummary({})).toBe("—");
    expect(errorClassSummary({ infra: 1, parse: 3, other: 0, "<x>": 9 })).toBe("parse 3, infra 1");
  });

  it("shows the server's error class, unknown values as other", () => {
    expect(errorClassText("parse")).toBe("parse");
    expect(errorClassText("infra")).toBe("infra");
    expect(errorClassText("toString")).toBe("other");
    expect(errorClassText("<b>")).toBe("other");
    expect(errorClassText(null)).toBe("other");
    expect(errorCodeText("zeek_failed")).toBe("zeek_failed");
    expect(errorCodeText("<script>")).toBe("other");
  });

  it("labels and links recent failures from the metrics answer", () => {
    const org = "11111111-1111-4111-8111-111111111111";
    const job = "44444444-4444-4444-8444-444444444444";
    expect(failureKindLabel({ kind: "pcap", subkind: null })).toBe("PCAP");
    expect(failureKindLabel({ kind: "static", subkind: "av" })).toBe("AV scan");
    expect(failureKindLabel({ kind: "static", subkind: "full" })).toBe("Static (full)");
    expect(failureHref(org, { kind: "static", job_id: job })).toBe(`/o/${org}/malware/${job}`);
    expect(failureHref(org, { kind: "pcap", job_id: job })).toBe(`/o/${org}/pcap/${job}`);
    expect(failureHref(org, { kind: "pcap", job_id: "../../x" })).toBeNull();
    const failure = {
      job_id: job,
      kind: "pcap" as const,
      subkind: null,
      error_code: "zeek_failed",
      error_class: "parse" as const,
      finished_at: null,
      investigation_id: org,
      evidence_id: org,
      href: `/pcap/${job}`,
    };
    expect(recentFailures({ recent_failures: Array(7).fill(failure) })).toHaveLength(5);
    expect(recentFailures({})).toEqual([]);
  });

  it("totals active jobs of the known kinds", () => {
    expect(activeTotal({ pcap: 2, ai: 1, bogus: 50 })).toBe(3);
  });
});
