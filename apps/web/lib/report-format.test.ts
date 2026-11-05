import { describe, expect, it } from "vitest";

import {
  citationHref,
  downloadFilename,
  formatUtc,
  isInvisible,
  jobRoutes,
  percentOf,
  reportsHref,
  sizeAgainstLimit,
  truncationNote,
  unitsAgainstBudget,
  vis,
} from "@/lib/report-format";
import rules from "@/lib/vis-rules.json";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "55555555-5555-4555-8555-555555555555";
const ROW = "99999999-9999-4999-8999-999999999991";
const EVIDENCE = "44444444-4444-4444-8444-444444444444";
const CASE = "33333333-3333-4333-8333-333333333333";
const PCAP_JOBS = jobRoutes([
  { analyzer: "pcap", job_id: JOB, created_at: "", evidence_id: EVIDENCE, status: "succeeded", tool_versions: {} },
]);
const INTERNAL_PATH = `/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`;

describe("vis (RT24, same rule as cyberlab_jobs.vis)", () => {
  it("makes bidi, zero-width, control and tag characters visible", () => {
    expect(vis("evil‮gnp.exe")).toBe("evil⟨U+202E⟩gnp.exe");
    expect(vis("a​b‍c")).toBe("a⟨U+200B⟩b⟨U+200D⟩c");
    expect(vis("bell\u0007")).toBe("bell⟨U+0007⟩");
    expect(vis("\u001b[31m")).toBe("⟨U+001B⟩[31m");
    expect(vis("\u007f\u0085")).toBe("⟨U+007F⟩⟨U+0085⟩");
    expect(vis("­")).toBe("⟨U+00AD⟩");
    expect(vis("؜⁦x⁩")).toBe("⟨U+061C⟩⟨U+2066⟩x⟨U+2069⟩");
    expect(vis("﻿BOM")).toBe("⟨U+FEFF⟩BOM");
    // A tag character (astral plane): one marker for the code point, not two surrogates.
    expect(vis("x\u{E0041}y")).toBe("x⟨U+E0041⟩y");
  });

  it("keeps everything else literal (newline, tab, Vietnamese, emoji, markup)", () => {
    expect(vis("line 1\nline\t2")).toBe("line 1\nline\t2");
    expect(vis("Tiếng Việt có dấu")).toBe("Tiếng Việt có dấu");
    expect(vis("🙂 ok")).toBe("🙂 ok");
    expect(vis("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
    expect(vis("evil[.]example")).toBe("evil[.]example"); // never refanged
    expect(vis("")).toBe("");
    expect(vis(null)).toBe("");
  });

  it("follows the materialized range table at every boundary", () => {
    for (const [start, end] of rules.ranges as unknown as [number, number, string][]) {
      expect(isInvisible(start)).toBe(true);
      expect(isInvisible(end)).toBe(true);
      if (!rules.ranges.some((r) => (r[0] as number) <= start - 1 && start - 1 <= (r[1] as number))) {
        expect(isInvisible(start - 1)).toBe(false);
      }
      if (!rules.ranges.some((r) => (r[0] as number) <= end + 1 && end + 1 <= (r[1] as number))) {
        expect(isInvisible(end + 1)).toBe(false);
      }
    }
    expect(isInvisible(0x0a)).toBe(false);
    expect(isInvisible(0x09)).toBe(false);
    expect(isInvisible(0x41)).toBe(false);
    expect(rules.marker).toBe("⟨U+XXXX⟩");
  });
});

describe("citationHref (internal routes from ids only)", () => {
  it("builds job, evidence and note links from UUID ids", () => {
    expect(citationHref(ORG, { kind: "finding", ref_id: ROW, job_id: JOB, path: INTERNAL_PATH }, PCAP_JOBS)).toBe(
      `/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`,
    );
    expect(
      citationHref(ORG, { kind: "evidence", ref_id: EVIDENCE, job_id: null, path: `/o/${ORG}/evidence/${EVIDENCE}` }, PCAP_JOBS),
    ).toBe(`/o/${ORG}/evidence/${EVIDENCE}`);
    expect(citationHref(ORG, { kind: "note", ref_id: ROW, job_id: null, path: "/x" }, PCAP_JOBS, CASE)).toBe(
      `/o/${ORG}/investigations/${CASE}`,
    );
    // The static analyzer maps to the malware route; a kind with no tab links to the overview.
    const staticJobs = jobRoutes([{ analyzer: "static", job_id: JOB, created_at: "", evidence_id: EVIDENCE, status: "succeeded", tool_versions: {} }]);
    expect(citationHref(ORG, { kind: "capability", ref_id: ROW, job_id: JOB, path: "/p" }, staticJobs)).toBe(
      `/o/${ORG}/malware/${JOB}?tab=capabilities&ref=${ROW}`,
    );
    expect(citationHref(ORG, { kind: "sample", ref_id: ROW, job_id: JOB, path: "/p" }, staticJobs)).toBe(`/o/${ORG}/malware/${JOB}`);
  });

  it("never uses the snapshot path as the href", () => {
    const evilPath = `/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}&next=//attacker.example`;
    const href = citationHref(ORG, { kind: "finding", ref_id: ROW, job_id: JOB, path: evilPath }, PCAP_JOBS);
    expect(href).toBe(`/o/${ORG}/pcap/${JOB}?tab=findings&ref=${ROW}`);
    // The path only chooses among the two job routes when the job is not in the snapshot.
    expect(citationHref(ORG, { kind: "finding", ref_id: ROW, job_id: JOB, path: INTERNAL_PATH }, new Map())).toBe(href);
    expect(citationHref(ORG, { kind: "finding", ref_id: ROW, job_id: JOB, path: "javascript:alert(1)" }, new Map())).toBeNull();
  });

  it("refuses non-UUID ids, unknown kinds and external snapshots", () => {
    expect(citationHref(ORG, { kind: "finding", ref_id: ROW, job_id: JOB, path: null }, PCAP_JOBS)).toBeNull(); // external
    expect(citationHref(ORG, { kind: "finding", ref_id: ROW, job_id: "../../admin", path: INTERNAL_PATH }, PCAP_JOBS)).toBeNull();
    expect(citationHref(ORG, { kind: "evidence", ref_id: "javascript:alert(1)", job_id: null, path: "/x" }, PCAP_JOBS)).toBeNull();
    expect(citationHref("not-an-org", { kind: "finding", ref_id: ROW, job_id: JOB, path: INTERNAL_PATH }, PCAP_JOBS)).toBeNull();
    expect(citationHref(ORG, { kind: "weird", ref_id: ROW, job_id: JOB, path: INTERNAL_PATH }, PCAP_JOBS)).toBeNull();
    expect(citationHref(ORG, { kind: "custody", ref_id: ROW, job_id: null, path: "/x" }, PCAP_JOBS)).toBeNull();
    expect(citationHref(ORG, { kind: "note", ref_id: ROW, job_id: null, path: "/x" }, PCAP_JOBS, "x")).toBeNull();
    // A ref with URL syntax is encoded into the query, never a new path or origin.
    expect(citationHref(ORG, { kind: "flow", ref_id: "C1/../x?y=#z", job_id: JOB, path: INTERNAL_PATH }, PCAP_JOBS)).toBe(
      `/o/${ORG}/pcap/${JOB}?tab=flows&ref=C1%2F..%2Fx%3Fy%3D%23z`,
    );
  });
});

describe("formatting", () => {
  it("UTC timestamps, truncation notes, size and budget", () => {
    expect(formatUtc("2026-11-06T09:00:00.000000Z")).toBe("2026-11-06 09:00 UTC");
    expect(formatUtc(null)).toBe("—");
    expect(truncationNote(500, 3412)).toBe("Showing 500 of 3,412.");
    expect(truncationNote(3, 3)).toBeNull();
    expect(percentOf(1, 0)).toBe(0);
    expect(sizeAgainstLimit(4 * 1024 * 1024, 8 * 1024 * 1024)).toBe("4.0 MiB of 8.0 MiB (50 %)");
    expect(unitsAgainstBudget(375_000, 750_000)).toBe("375,000 of 750,000 render units (50 %)");
    expect(reportsHref(ORG)).toBe(`/o/${ORG}/reports`);
    expect(reportsHref(ORG, ROW, 3)).toBe(`/o/${ORG}/reports/${ROW}/v/3`);
  });

  it("download filenames come from the server, sanitized, with a known extension", () => {
    expect(downloadFilename('attachment; filename="report-v2-TLP_AMBER.pdf"', "x.pdf")).toBe("report-v2-TLP_AMBER.pdf");
    expect(downloadFilename("attachment; filename*=UTF-8''b%C3%A1o-c%C3%A1o.md", "x.md")).toBe("báo-cáo.md");
    expect(downloadFilename('attachment; filename="../../etc/passwd"', "fallback.pdf")).toBe("fallback.pdf");
    expect(downloadFilename('attachment; filename="..\\evil.pdf"', "f.pdf")).toBe("_evil.pdf");
    expect(downloadFilename('attachment; filename="run.exe"', "f.pdf")).toBe("f.pdf");
    expect(downloadFilename(null, "f.sig.json")).toBe("f.sig.json");
  });
});
