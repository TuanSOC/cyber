import { describe, expect, it } from "vitest";

import {
  ANALYSIS_POLL_MS,
  analysisErrorText,
  anyActive,
  formatDuration,
  hasSummary,
  isActiveStatus,
  jobDurationMs,
  jobDurationText,
  justSucceeded,
  latestPerEvidence,
  pollWhileActive,
  toolVersions,
} from "./analysis";

describe("active status", () => {
  it.each([
    ["queued", true],
    ["running", true],
    ["succeeded", false],
    ["failed", false],
  ] as const)("%s → %s", (status, expected) => {
    expect(isActiveStatus(status)).toBe(expected);
  });

  it("polls only while some job is in flight", () => {
    expect(anyActive(undefined)).toBe(false);
    expect(pollWhileActive(undefined)).toBe(false);
    expect(pollWhileActive([{ status: "succeeded" }, { status: "failed" }])).toBe(false);
    expect(pollWhileActive([{ status: "failed" }, { status: "running" }])).toBe(ANALYSIS_POLL_MS);
    expect(pollWhileActive([{ status: "queued" }])).toBe(ANALYSIS_POLL_MS);
  });
});

describe("justSucceeded", () => {
  it("detects an active → succeeded transition", () => {
    expect(justSucceeded([{ id: "a", status: "running" }], [{ id: "a", status: "succeeded" }])).toBe(true);
    expect(justSucceeded([{ id: "a", status: "queued" }], [{ id: "a", status: "succeeded" }])).toBe(true);
  });

  it("ignores first loads, failures and already finished jobs", () => {
    expect(justSucceeded(undefined, [{ id: "a", status: "succeeded" }])).toBe(false);
    expect(justSucceeded([{ id: "a", status: "running" }], [{ id: "a", status: "failed" }])).toBe(false);
    expect(justSucceeded([{ id: "a", status: "succeeded" }], [{ id: "a", status: "succeeded" }])).toBe(false);
    expect(justSucceeded([], [{ id: "b", status: "succeeded" }])).toBe(false);
  });
});

describe("analysisErrorText", () => {
  it("maps known codes to human text", () => {
    expect(analysisErrorText("unsupported_capture_format")).toMatch(/pcap or pcapng/);
    expect(analysisErrorText("tool_timeout")).toMatch(/did not finish/);
  });

  it("falls back to the raw code and handles empty values", () => {
    expect(analysisErrorText("brand_new_code")).toBe("Analysis failed (brand_new_code).");
    expect(analysisErrorText(null)).toBeNull();
    expect(analysisErrorText("")).toBeNull();
  });

  it("does not resolve prototype keys", () => {
    expect(analysisErrorText("toString")).toBe("Analysis failed (toString).");
  });
});

describe("durations", () => {
  it.each([
    [0, "0 ms"],
    [850, "850 ms"],
    [42_000, "42 s"],
    [185_000, "3 m 05 s"],
    [3_720_000, "1 h 02 m"],
    [-1, "—"],
    [Number.NaN, "—"],
  ])("formatDuration(%s) = %s", (ms, expected) => {
    expect(formatDuration(ms)).toBe(expected);
  });

  const start = "2026-11-04T10:00:00Z";
  it("measures finished, running and unstarted jobs", () => {
    expect(jobDurationMs({ started_at: start, finished_at: "2026-11-04T10:00:30Z" }, 0)).toBe(30_000);
    expect(jobDurationMs({ started_at: start, finished_at: null }, Date.parse(start) + 5_000)).toBe(5_000);
    expect(jobDurationMs({ started_at: null, finished_at: null }, Date.now())).toBeNull();
    expect(jobDurationText({ started_at: null, finished_at: "2026-11-04T10:00:30Z" }, 0)).toBe("—");
    expect(jobDurationText({ started_at: "garbage", finished_at: null }, 0)).toBe("—");
  });
});

describe("summary helpers", () => {
  it("treats an empty or malformed summary as absent", () => {
    expect(hasSummary({})).toBe(false);
    expect(hasSummary(undefined)).toBe(false);
    expect(hasSummary({ packets: 1 })).toBe(true);
  });

  it("extracts tool versions and skips malformed values", () => {
    expect(toolVersions({ tool_versions: { zeek: "7.0.5", suricata: 7, bad: { x: 1 }, nil: null } })).toEqual([
      ["zeek", "7.0.5"],
      ["suricata", "7"],
    ]);
    expect(toolVersions({ tool_versions: ["zeek"] })).toEqual([]);
    expect(toolVersions({})).toEqual([]);
  });
});

describe("latestPerEvidence", () => {
  it("keeps the first (newest) job of each evidence in order", () => {
    const jobs = [
      { id: "3", evidence_id: "e1" },
      { id: "2", evidence_id: "e2" },
      { id: "1", evidence_id: "e1" },
    ];
    expect(latestPerEvidence(jobs).map((job) => job.id)).toEqual(["3", "2"]);
  });
});
