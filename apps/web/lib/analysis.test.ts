import { describe, expect, it } from "vitest";

import { JOB_TASKS } from "./ai";
import {
  ANALYSIS_POLL_MS,
  ANALYZER_ROUTES,
  type Analyzer,
  analysisErrorText,
  analysisKindLabel,
  analysisSegment,
  anyActive,
  evidenceKind,
  jobsOf,
  knownErrorText,
  offeredRuns,
  runKindOf,
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

// M8 RT1: every analyzer-keyed map covers every analyzer; memory never falls into a pcap /
// static "else". (Typed maps fail typecheck when the contract gains an analyzer; this test
// fails at runtime if a map is widened by a cast.)
const ANALYZERS: Analyzer[] = ["pcap", "static", "memory", "disk", "reverse"];

describe("analyzer exhaustiveness", () => {
  it("every analyzer has its own route, label and AI task list", () => {
    expect(Object.keys(ANALYZER_ROUTES).sort()).toEqual([...ANALYZERS].sort());
    expect(new Set(Object.values(ANALYZER_ROUTES)).size).toBe(ANALYZERS.length);
    expect(Object.keys(JOB_TASKS).sort()).toEqual([...ANALYZERS].sort());
    expect(JOB_TASKS.memory).toEqual([]);
    expect(JOB_TASKS.disk).toEqual([]);
    expect(JOB_TASKS.reverse).toEqual([]);
  });

  it("reverse-engineering jobs link to /reverse-engineering and are labelled by profile (M10)", () => {
    expect(analysisSegment({ id: "j1", analyzer: "reverse" })).toBe("reverse-engineering/j1");
    expect(analysisKindLabel({ analyzer: "reverse", profile: "quick" })).toBe("RE (quick)");
    expect(analysisKindLabel({ analyzer: "reverse", profile: "full" })).toBe("RE (full)");
    expect(runKindOf({ analyzer: "reverse", profile: "full" })).toBeNull();
    expect(analysisErrorText("static_analysis_required")).toMatch(/full static analysis/);
  });

  it("disk jobs link to /forensics and are labelled by profile (M9)", () => {
    expect(analysisSegment({ id: "j1", analyzer: "disk" })).toBe("forensics/j1");
    expect(analysisKindLabel({ analyzer: "disk", profile: "triage" })).toBe("Disk (triage)");
    expect(analysisKindLabel({ analyzer: "disk", profile: "full" })).toBe("Disk (full)");
    expect(analysisKindLabel({ analyzer: "disk", profile: "extract" })).toBe("Disk (file export)");
    expect(runKindOf({ analyzer: "disk", profile: "triage" })).toBeNull();
    expect(analysisErrorText("no_supported_filesystem")).toMatch(/NTFS, FAT/);
  });

  it("memory jobs link to /memory and are labelled by profile", () => {
    expect(analysisSegment({ id: "j1", analyzer: "memory" })).toBe("memory/j1");
    expect(analysisSegment({ id: "j1", analyzer: "static" })).toBe("malware/j1");
    expect(analysisSegment({ id: "j1", analyzer: "pcap" })).toBe("pcap/j1");
    expect(analysisKindLabel({ analyzer: "memory", profile: "triage" })).toBe("Memory (triage)");
    expect(analysisKindLabel({ analyzer: "memory", profile: "full" })).toBe("Memory (full)");
    expect(analysisKindLabel({ analyzer: "static", profile: "full" })).toBe("Static (full)");
    expect(runKindOf({ analyzer: "memory", profile: "triage" })).toBeNull();
  });

  it("explains the memory error codes", () => {
    expect(analysisErrorText("symbols_missing")).toMatch(/symbol table/);
    expect(analysisErrorText("unsupported_memory_format")).toMatch(/compressed or archived/);
    expect(knownErrorText("not_implemented")).toMatch(/not available yet/);
  });
});

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

describe("latestPerEvidence per analyzer", () => {
  it("keeps one row per evidence and kind of run", () => {
    const jobs = [
      { id: "5", evidence_id: "e1", analyzer: "static" as const, profile: "av" as const },
      { id: "4", evidence_id: "e1", analyzer: "static" as const, profile: "full" as const },
      { id: "3", evidence_id: "e1", analyzer: "pcap" as const, profile: null },
      { id: "2", evidence_id: "e1", analyzer: "static" as const, profile: "full" as const },
    ];
    expect(latestPerEvidence(jobs).map((job) => job.id)).toEqual(["5", "4", "3"]);
  });
});

describe("static error texts", () => {
  it.each([
    "sample_too_large",
    "av_unavailable",
    "av_not_fully_scanned",
    "results_not_available",
    "report_unavailable",
    "analysis_not_succeeded",
  ])("%s has a human text", (code) => {
    expect(knownErrorText(code)).toBeTruthy();
    expect(analysisErrorText(code)).not.toContain("Analysis failed (");
  });

  it("knownErrorText is null for unknown or empty codes", () => {
    expect(knownErrorText("nope")).toBeNull();
    expect(knownErrorText("toString")).toBeNull();
    expect(knownErrorText(null)).toBeNull();
  });
});

describe("analyzers and profiles", () => {
  it("labels and routes jobs by analyzer", () => {
    expect(analysisKindLabel({ analyzer: "pcap", profile: null })).toBe("PCAP");
    expect(analysisKindLabel({ analyzer: "static", profile: "full" })).toBe("Static (full)");
    expect(analysisKindLabel({ analyzer: "static", profile: "av" })).toBe("AV scan");
    expect(analysisSegment({ id: "j1", analyzer: "pcap" })).toBe("pcap/j1");
    expect(analysisSegment({ id: "j2", analyzer: "static" })).toBe("malware/j2");
    expect(runKindOf({ analyzer: "static", profile: "av" })).toBe("static_av");
    expect(runKindOf({ analyzer: "static", profile: null })).toBe("static_full");
  });

  it("filters jobs by analyzer and profile", () => {
    const jobs = [
      { id: "1", analyzer: "pcap" as const, profile: null },
      { id: "2", analyzer: "static" as const, profile: "full" as const },
      { id: "3", analyzer: "static" as const, profile: "av" as const },
    ];
    expect(jobsOf(jobs, "static").map((j) => j.id)).toEqual(["2", "3"]);
    expect(jobsOf(jobs, "static", "av").map((j) => j.id)).toEqual(["3"]);
    expect(jobsOf(jobs, "pcap").map((j) => j.id)).toEqual(["1"]);
  });
});

describe("evidenceKind / offeredRuns", () => {
  const ev = (detected_mime: string, original_filename = "file", detected_description = "") => ({
    detected_mime,
    original_filename,
    detected_description,
  });

  it.each([
    [ev("application/vnd.tcpdump.pcap"), "capture"],
    [ev("application/octet-stream", "x.bin", "pcapng capture file - version 1.0"), "capture"],
    [ev("application/octet-stream", "trace.PCAPNG"), "capture"],
    [ev("application/vnd.microsoft.portable-executable", "a.exe"), "executable"],
    [ev("application/x-dosexec", "a.dll"), "executable"],
    [ev("application/x-executable", "tool"), "executable"],
    [ev("application/x-sharedlib", "libx.so"), "executable"],
    [ev("application/x-pie-executable", "bin"), "executable"],
    [ev("application/octet-stream", "x", "PE32+ executable (console) x86-64, for MS Windows"), "executable"],
    [ev("application/octet-stream", "setup.exe"), "executable"],
    [ev("application/x-coredump", "core"), "other"],
    [ev("application/octet-stream", "core", "ELF 64-bit LSB core file, x86-64"), "other"],
    [ev("application/pdf", "invoice.exe"), "other"],
    [ev("application/zip", "a.zip"), "other"],
    [ev("text/plain", "notes.pcap"), "other"],
  ] as const)("%o → %s", (evidence, kind) => {
    expect(evidenceKind(evidence)).toBe(kind);
  });

  it("offers the fitting runs first and every other run in the menu", () => {
    expect(offeredRuns("capture")).toEqual({ primary: ["pcap"], more: ["static_full", "static_av"] });
    expect(offeredRuns("executable")).toEqual({ primary: ["static_full", "static_av"], more: ["pcap"] });
    expect(offeredRuns("other")).toEqual({ primary: ["static_av"], more: ["static_full", "pcap"] });
    for (const kind of ["capture", "executable", "other"] as const) {
      const { primary, more } = offeredRuns(kind);
      expect(new Set([...primary, ...more])).toEqual(new Set(["pcap", "static_full", "static_av"]));
    }
  });
});
