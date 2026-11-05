import { describe, expect, it } from "vitest";

import {
  AV_DB_MAX_AGE_DAYS,
  avDbAge,
  categoryLabel,
  compileTimeText,
  entropyLevel,
  entropyPercent,
  groupByLibrary,
  hex,
  isWritableExecutable,
  metaEntries,
  notableCategory,
  parseAttackFilter,
  parseStaticSummary,
  parseStaticTab,
  reportFilename,
  sectionWarnings,
  staticEngineErrorText,
  STATIC_REF_TABS,
  staticTabs,
  staticTruncationText,
} from "./static-results";

describe("entropy", () => {
  it.each([
    [0, "low"],
    [0.5, "low"],
    [4.2, "typical"],
    [6.49, "typical"],
    [6.5, "elevated"],
    [7.2, "elevated"],
    [7.21, "high"],
    [8, "high"],
    [Number.NaN, "typical"],
  ] as const)("%s → %s", (value, level) => {
    expect(entropyLevel(value)).toBe(level);
  });

  it("maps 0–8 onto 0–100 and clamps", () => {
    expect(entropyPercent(4)).toBe(50);
    expect(entropyPercent(8)).toBe(100);
    expect(entropyPercent(9)).toBe(100);
    expect(entropyPercent(-1)).toBe(0);
    expect(entropyPercent(Number.POSITIVE_INFINITY)).toBe(0);
  });
});

describe("sections", () => {
  it("flags writable + executable sections", () => {
    expect(isWritableExecutable(["read", "write", "execute"])).toBe(true);
    expect(isWritableExecutable(["read", "execute"])).toBe(false);
    expect(isWritableExecutable(["WRITE", "Execute"])).toBe(true);
  });

  it("lists the reasons a section stands out", () => {
    const base = { flags: ["read", "execute"], entropy: 6, raw_size: 4096, virtual_size: 4096 };
    expect(sectionWarnings(base)).toEqual([]);
    expect(sectionWarnings({ ...base, flags: ["write", "execute"], entropy: 7.6 })).toEqual([
      "writable and executable",
      "high entropy",
    ]);
    expect(sectionWarnings({ ...base, raw_size: 0, virtual_size: 65536 })).toEqual(["executable with no raw data"]);
  });
});

describe("notable imports", () => {
  it("matches exact names and their A / W variants", () => {
    expect(notableCategory("VirtualAllocEx")).toBe("process_injection");
    expect(notableCategory("CreateServiceW")).toBe("persistence");
    expect(notableCategory("ShellExecuteExA")).toBe("execution");
    expect(notableCategory("OutputDebugStringA")).toBe("anti_analysis");
    expect(notableCategory("InternetOpenUrlW")).toBe("networking");
  });

  it("ignores other names, case variants and missing functions", () => {
    expect(notableCategory("GetProcAddress")).toBeNull();
    expect(notableCategory("virtualallocex")).toBeNull();
    expect(notableCategory("VirtualAllocExX")).toBeNull();
    expect(notableCategory("")).toBeNull();
    expect(notableCategory(null)).toBeNull();
    expect(notableCategory("__proto__")).toBeNull();
  });

  it("labels categories, unknown ones verbatim", () => {
    expect(categoryLabel("process_injection")).toBe("Process injection");
    expect(categoryLabel("something_new")).toBe("something_new");
  });

  it("groups consecutive imports by library", () => {
    const groups = groupByLibrary([
      { library: "a.dll", id: 1 },
      { library: "a.dll", id: 2 },
      { library: "b.dll", id: 3 },
    ]);
    expect(groups.map((g) => [g.library, g.items.length])).toEqual([
      ["a.dll", 2],
      ["b.dll", 1],
    ]);
    expect(groupByLibrary([])).toEqual([]);
  });
});

describe("engine errors and truncation", () => {
  it("explains AV problems as an incomplete scan, never as clean", () => {
    expect(staticEngineErrorText("av_not_fully_scanned")).toMatch(/not a clean result/);
    expect(staticEngineErrorText("av_unavailable")).toMatch(/not scanned/);
    expect(staticEngineErrorText("capa_skipped")).toMatch(/capabilities are missing/);
    expect(staticEngineErrorText("floss_skipped")).toMatch(/decoded strings are missing/);
  });

  it("shows unknown codes verbatim", () => {
    expect(staticEngineErrorText("brand_new_engine_failed")).toContain("brand_new_engine_failed");
    expect(staticEngineErrorText("constructor")).toContain("(constructor)");
    expect(staticTruncationText("strings")).toMatch(/Strings capped/);
    expect(staticTruncationText("odd_key")).toContain("odd_key");
  });
});

describe("AV database age", () => {
  const analyzedAt = Date.parse("2026-11-04T12:00:00Z");

  it("is stale when older than 7 days at analysis time", () => {
    const fresh = avDbAge([["clamav_db", "27800"], ["clamav_db_date", "2026-11-01T08:00:00Z"]], analyzedAt);
    expect(fresh).toMatchObject({ version: "27800", date: "2026-11-01", days: 3, stale: false, custom: false });
    const old = avDbAge([["clamav_db_date", "2026-10-20T00:00:00Z"]], analyzedAt);
    expect(old?.days).toBe(15);
    expect(old?.stale).toBe(true);
    const edge = avDbAge([["clamav_db_date", "2026-10-28T12:00:00Z"]], analyzedAt);
    expect(edge?.days).toBe(AV_DB_MAX_AGE_DAYS);
    expect(edge?.stale).toBe(false);
  });

  it("handles custom, unknown and missing databases", () => {
    expect(avDbAge([["clamav_db", "custom:test.ndb"]], analyzedAt)).toMatchObject({ custom: true, days: null, stale: false });
    expect(avDbAge([["clamav_db", "unavailable"]], analyzedAt)).toMatchObject({ date: null, stale: false });
    expect(avDbAge([["clamav_db_date", "not a date"]], analyzedAt)).toMatchObject({ days: null, stale: false });
    expect(avDbAge([["yara", "4.5.2"]], analyzedAt)).toBeNull();
  });
});

describe("filters and formatting", () => {
  it("accepts ATT&CK technique and sub-technique ids only", () => {
    expect(parseAttackFilter("")).toEqual({ invalid: false });
    expect(parseAttackFilter(" t1055 ")).toEqual({ attack: "T1055", invalid: false });
    expect(parseAttackFilter("T1055.012")).toEqual({ attack: "T1055.012", invalid: false });
    expect(parseAttackFilter("T105")).toEqual({ invalid: true });
    expect(parseAttackFilter("T1055.1")).toEqual({ invalid: true });
    expect(parseAttackFilter("1055")).toEqual({ invalid: true });
  });

  it("formats addresses and compile times", () => {
    expect(hex(0x401000)).toBe("0x401000");
    expect(hex(0)).toBe("0x0");
    expect(hex(null)).toBe("—");
    expect(hex(-1)).toBe("—");
    expect(compileTimeText(0)).toBeNull();
    expect(compileTimeText(null)).toBeNull();
    expect(compileTimeText(1_700_000_000)).toBe("2023-11-14T22:13:20Z");
  });

  it("turns rule meta into sorted text pairs", () => {
    expect(metaEntries({ b: "x", a: 1, c: true, d: { nested: 1 } })).toEqual([
      ["a", "1"],
      ["b", "x"],
      ["c", "true"],
      ["d", ""],
    ]);
    expect(metaEntries(null)).toEqual([]);
  });
});

describe("tabs", () => {
  it("offers only signature tabs for the AV profile", () => {
    expect(staticTabs("av").map(([tab]) => tab)).toEqual(["findings", "signatures", "iocs", "ai"]);
    expect(staticTabs("full")).toHaveLength(10);
    expect(parseStaticTab("ai", "av")).toBe("ai");
    expect(parseStaticTab("strings", "full")).toBe("strings");
    expect(parseStaticTab("strings", "av")).toBe("overview");
    expect(parseStaticTab("bogus", "full")).toBe("overview");
    expect(parseStaticTab(null, "full")).toBe("overview");
  });
});

describe("parseStaticSummary", () => {
  it("reads the ingest summary defensively", () => {
    const s = parseStaticSummary({
      profile: "full",
      file_format: "pe",
      sample: { file_type: "PE32 executable", mime: "application/x-dosexec", entropy: 6.1 },
      counts: { findings: 2, signatures: 1, strings: "x" },
      engine_errors: ["capa_skipped", 3, ""],
      truncated: { strings: true, imports: false },
      tool_versions: { clamav: "1.4.3", clamav_db_date: "2026-11-01T00:00:00Z", bad: {} },
    });
    expect(s).toMatchObject({ profile: "full", fileFormat: "pe", fileType: "PE32 executable", entropy: 6.1 });
    expect(s.counts).toEqual({ findings: 2, signatures: 1 });
    expect(s.countRows.map((r) => r.key)).toEqual(["findings", "signatures"]);
    expect(s.engineErrors).toEqual(["capa_skipped"]);
    expect(s.truncated).toEqual(["strings"]);
    expect(s.toolVersions).toEqual([
      ["clamav", "1.4.3"],
      ["clamav_db_date", "2026-11-01T00:00:00Z"],
    ]);
  });

  it("returns empty values for missing or malformed summaries", () => {
    for (const summary of [null, undefined, {}, [], "x"]) {
      const s = parseStaticSummary(summary);
      expect(s.fileType).toBeNull();
      expect(s.counts).toEqual({});
      expect(s.engineErrors).toEqual([]);
    }
  });
});

describe("reportFilename", () => {
  it("prefers the RFC 5987 name and keeps it a safe .json basename", () => {
    expect(
      reportFilename(`attachment; filename="sample.exe.static-report-1234abcd.json"; filename*=UTF-8''s%C3%A4mple.exe.static-report-1234abcd.json`),
    ).toBe("sämple.exe.static-report-1234abcd.json");
    expect(reportFilename(`attachment; filename="a.json"`)).toBe("a.json");
    expect(reportFilename(`attachment; filename=plain.json`)).toBe("plain.json");
    expect(reportFilename(`attachment; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd`)).toBe("_.._etc_passwd.json");
    expect(reportFilename(`attachment; filename*=UTF-8''%E0%A4%A`)).toBe("static-report.json");
    expect(reportFilename(null)).toBe("static-report.json");
    expect(reportFilename("inline")).toBe("static-report.json");
  });
});

describe("cited rows (ref)", () => {
  it("reads ref on every citable static tab", () => {
    for (const tab of ["findings", "signatures", "capabilities", "strings", "imports", "iocs"]) {
      expect(STATIC_REF_TABS.has(tab)).toBe(true);
      expect(parseStaticTab(tab, "full")).toBe(tab);
    }
    expect(STATIC_REF_TABS.has("sections")).toBe(false);
  });
});
