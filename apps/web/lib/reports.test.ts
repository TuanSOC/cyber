import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";
import {
  DraftSaver,
  type ReportDetail,
  type ReportUpdate,
  ReportApiError,
  addCitedRow,
  citedRowRef,
  asSnapshot,
  budgetRows,
  defaultDraft,
  distributionRequired,
  draftProblems,
  isSelectableAiRun,
  latestRenders,
  removeCitedRow,
  renderErrorText,
  renderPollMs,
  reportErrorText,
  sectionCountsOf,
  sectionUnitsOf,
  toggleId,
  unwrapReport,
} from "@/lib/reports";

const OPENAPI = path.resolve(__dirname, "../../../packages/contracts/openapi.json");
const JOB = "55555555-5555-4555-8555-555555555555";

function detail(revision: number): ReportDetail {
  return {
    draft: defaultDraft(),
    versions: [],
    report: {
      id: "22222222-2222-4222-8222-222222222222",
      investigation_id: "33333333-3333-4333-8333-333333333333",
      case_ref: "CASE-1",
      title: "T",
      template: "incident_v1",
      tlp: "amber",
      profile: "internal",
      distribution: null,
      status: "draft",
      revision,
      latest_version: 0,
      latest: null,
      created_by: "u",
      created_by_name: "U",
      created_at: "2026-11-05T00:00:00Z",
      updated_at: "2026-11-05T00:00:00Z",
    },
  };
}

const stale = () => new ApiError(409, "stale_draft", "stale");

describe("draft defaults match the frozen API schema", () => {
  it("defaultDraft mirrors the OpenAPI defaults of DraftInclude", () => {
    const spec = JSON.parse(readFileSync(OPENAPI, "utf8"));
    const include = spec.components.schemas.DraftInclude.properties;
    const draft = defaultDraft();
    expect(draft.include.evidence).toBe(include.evidence.default);
    expect(draft.include.custody).toBe(include.custody.default);
    expect(draft.include.ti).toBe(include.ti.default);
    expect(draft.include.jobs).toBe(include.jobs.default);
    for (const key of ["findings", "alerts", "iocs", "attack", "notes", "ai_runs", "cited_rows"] as const) {
      expect(draft.include[key]).toEqual(include[key].default);
    }
    expect(draft.include.timeline).toMatchObject(include.timeline.default);
    expect(Object.keys(draft.sections).sort()).toEqual(Object.keys(spec.components.schemas.DraftSections.properties).sort());
    expect(Object.keys(draft.include).sort()).toEqual(Object.keys(include).sort());
  });
});

describe("DraftSaver (debounced autosave with revision)", () => {
  it("merges changes, sends the current revision and uses the answer's revision next", async () => {
    const save = vi.fn(async (body: ReportUpdate) => detail(body.revision + 1));
    const saver = new DraftSaver(3, save, 10_000);
    saver.change({ title: "A" });
    saver.change({ distribution: "SOC" });
    expect(saver.getState().status).toBe("dirty");
    await saver.flush();
    expect(save).toHaveBeenCalledTimes(1);
    expect(save.mock.calls[0][0]).toEqual({ title: "A", distribution: "SOC", acknowledge_tlp_downgrade: false, revision: 3 });
    expect(saver.getState()).toMatchObject({ status: "saved", revision: 4 });

    saver.change({ title: "B" });
    await saver.flush();
    expect(save.mock.calls[1][0]).toMatchObject({ title: "B", revision: 4 });
    expect(saver.getState().revision).toBe(5);
    saver.dispose();
  });

  it("debounces: one request after the edits stop", async () => {
    vi.useFakeTimers();
    try {
      const save = vi.fn(async (body: ReportUpdate) => detail(body.revision + 1));
      const saver = new DraftSaver(1, save, 1000);
      saver.change({ title: "a" });
      await vi.advanceTimersByTimeAsync(500);
      saver.change({ title: "ab" });
      await vi.advanceTimersByTimeAsync(500);
      expect(save).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(600);
      expect(save).toHaveBeenCalledTimes(1);
      expect(save.mock.calls[0][0].title).toBe("ab");
      saver.dispose();
    } finally {
      vi.useRealTimers();
    }
  });

  it("edits made while a save is in flight go in the next request with the new revision", async () => {
    let release: (value: ReportDetail) => void = () => {};
    const save = vi
      .fn<(body: ReportUpdate) => Promise<ReportDetail>>()
      .mockImplementationOnce(() => new Promise((resolve) => (release = resolve)))
      .mockImplementation(async (body) => detail(body.revision + 1));
    const saver = new DraftSaver(7, save, 10_000);
    saver.change({ title: "first" });
    const flushing = saver.flush();
    saver.change({ title: "second" });
    expect(saver.getState().status).toBe("saving");
    release(detail(8));
    await flushing;
    expect(save).toHaveBeenCalledTimes(2);
    expect(save.mock.calls[1][0]).toMatchObject({ title: "second", revision: 8 });
    expect(saver.getState()).toMatchObject({ status: "saved", revision: 9 });
  });

  it("stops on 409 stale_draft and never overwrites: no further request until reset", async () => {
    const save = vi.fn(async () => {
      throw stale();
    });
    const saver = new DraftSaver(2, save, 10_000);
    const seen: string[] = [];
    saver.subscribe(() => seen.push(saver.getState().status));
    saver.change({ title: "mine" });
    await saver.flush();
    expect(saver.getState().status).toBe("conflict");
    expect(saver.hasPending).toBe(true); // the unsaved patch is kept, not sent

    saver.change({ title: "more" }); // ignored while in conflict
    await saver.flush();
    saver.retry();
    expect(save).toHaveBeenCalledTimes(1);
    expect(seen).toContain("conflict");

    saver.reset(5);
    expect(saver.getState()).toMatchObject({ status: "saved", revision: 5 });
    expect(saver.hasPending).toBe(false);
  });

  it("keeps the patch after another error and retries it", async () => {
    const save = vi
      .fn<(body: ReportUpdate) => Promise<ReportDetail>>()
      .mockRejectedValueOnce(new ApiError(422, "selection_out_of_scope", "x"))
      .mockImplementation(async (body) => detail(body.revision + 1));
    const saver = new DraftSaver(1, save, 10_000);
    saver.change({ title: "x", tlp: "green", acknowledge_tlp_downgrade: true });
    await saver.flush();
    expect(saver.getState().status).toBe("error");
    saver.retry();
    await saver.flush();
    expect(save.mock.calls[1][0]).toMatchObject({ title: "x", tlp: "green", acknowledge_tlp_downgrade: true, revision: 1 });
    expect(saver.getState().status).toBe("saved");
  });

  it("markConflict (a stale finalize) stops autosave", async () => {
    const save = vi.fn(async (body: ReportUpdate) => detail(body.revision + 1));
    const saver = new DraftSaver(1, save, 10_000);
    saver.markConflict(stale());
    saver.change({ title: "x" });
    await saver.flush();
    expect(save).not.toHaveBeenCalled();
    expect(saver.getState().status).toBe("conflict");
  });
});

describe("draft rules", () => {
  const fields = { title: "Report", tlp: "amber" as const, profile: "internal" as const, distribution: "", draft: defaultDraft() };

  it("requires a distribution for RED, AMBER+STRICT and external", () => {
    expect(distributionRequired("red", "internal")).toBe(true);
    expect(distributionRequired("amber_strict", "internal")).toBe(true);
    expect(distributionRequired("amber", "external")).toBe(true);
    expect(distributionRequired("amber", "internal")).toBe(false);
    expect(draftProblems(fields)).toEqual([]);
    expect(draftProblems({ ...fields, tlp: "red" })).toEqual([
      "TLP:RED and TLP:AMBER+STRICT reports need a distribution statement (who may receive it).",
    ]);
    expect(draftProblems({ ...fields, tlp: "red", distribution: "SOC only" })).toEqual([]);
    expect(draftProblems({ ...fields, profile: "external" })[0]).toMatch(/External reports need a distribution/);
  });

  it("counts characters as the API does (code points) and flags limits", () => {
    const long = "ệ".repeat(20_001);
    const problems = draftProblems({ ...fields, title: " ", draft: { ...fields.draft, sections: { ...fields.draft.sections, impact: long } } });
    expect(problems).toContain("The report needs a title.");
    expect(problems).toContain("Impact is over 20,000 characters.");
    expect(draftProblems({ ...fields, draft: { ...fields.draft, sections: { ...fields.draft.sections, impact: "🙂".repeat(20_000) } } })).toEqual([]);
  });

  it("cited rows are deduplicated and capped at 200", () => {
    const row = { kind: "finding" as const, ref_id: "r1", job_id: JOB };
    const first = addCitedRow(defaultDraft(), row);
    expect(first.added).toBe(true);
    expect(addCitedRow(first.draft, { ...row }).reason).toBe("duplicate");
    expect(addCitedRow(first.draft, { ...row, job_id: null }).added).toBe(true);
    let draft = defaultDraft();
    for (let i = 0; i < 200; i += 1) draft = addCitedRow(draft, { kind: "alert", ref_id: `a${i}`, job_id: JOB }).draft;
    expect(addCitedRow(draft, row)).toMatchObject({ added: false, reason: "full" });
    expect(removeCitedRow(first.draft, row).include.cited_rows).toEqual([]);
  });

  it("citedRowRef maps case rows to citable refs", () => {
    expect(citedRowRef("finding", "f1", JOB)).toEqual({ kind: "finding", ref_id: "f1", job_id: JOB });
    expect(citedRowRef("note", "n1")).toEqual({ kind: "note", ref_id: "n1" });
    expect(citedRowRef("status", "s1")).toBeNull();
    expect(citedRowRef("ai_run", "r1", JOB)).toBeNull();
    expect(citedRowRef("flow", "7")).toBeNull();
    expect(citedRowRef("flow", "7", JOB)).toEqual({ kind: "flow", ref_id: "7", job_id: JOB });
    expect(citedRowRef("ioc", null)).toBeNull();
    expect(citedRowRef("ioc", "a b")).toBeNull();
    expect(citedRowRef("__proto__", "x")).toBeNull();
  });

  it("toggleId keeps order and the cap", () => {
    expect(toggleId(["a"], "b", true)).toEqual(["a", "b"]);
    expect(toggleId(["a", "b"], "a", false)).toEqual(["b"]);
    expect(toggleId(["a"], "a", true)).toEqual(["a"]);
    expect(toggleId(["a", "b"], "c", true, 2)).toEqual(["a", "b"]);
  });

  it("AI runs: completed only, never refused or canary-leak", () => {
    expect(isSelectableAiRun({ status: "completed", error_code: null, refusal_category: null })).toBe(true);
    expect(isSelectableAiRun({ status: "refused", error_code: null, refusal_category: "cyber" })).toBe(false);
    expect(isSelectableAiRun({ status: "completed", error_code: null, refusal_category: "x" })).toBe(false);
    expect(isSelectableAiRun({ status: "failed", error_code: "canary_leak", refusal_category: null })).toBe(false);
    expect(isSelectableAiRun({ status: "completed", error_code: "canary_leak", refusal_category: null })).toBe(false);
    expect(isSelectableAiRun({ status: "partial", error_code: null, refusal_category: null })).toBe(false);
  });
});

describe("errors", () => {
  it("unwrapReport keeps the extra fields of the error body", () => {
    const response = new Response(null, { status: 422 });
    const error = { error: { code: "report_too_large_to_render", message: "too big", section_units: { findings: 600_000, ai: 10 } } };
    let caught: unknown;
    try {
      unwrapReport({ error, response });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ReportApiError);
    expect(caught).toBeInstanceOf(ApiError);
    expect(sectionUnitsOf(caught)).toEqual({ findings: 600_000, ai: 10 });
    expect(reportErrorText(caught)).toMatch(/render budget/);
  });

  it("reads units and counts from details too, and ignores junk", () => {
    const viaDetails = new ApiError(422, "report_too_large", "x", {
      section_counts: { findings: { included: 500, total: 3412 }, bad: { included: "x" } },
      section_units: { findings: "lots" },
    });
    expect(sectionCountsOf(viaDetails)).toEqual({ findings: { included: 500, total: 3412 } });
    expect(sectionUnitsOf(viaDetails)).toBeNull();
    expect(sectionUnitsOf(new Error("x"))).toBeNull();
    expect(reportErrorText(new ApiError(500, "unknown_code", "x"))).toBeNull();
  });
});

describe("budget and renders", () => {
  it("budget rows: largest first, with hints for narrowable sections", () => {
    const rows = budgetRows({ findings: 600, report: 50, citations: 300, schema_version: 18, ai: 0 });
    expect(rows.map((r) => r.key)).toEqual(["findings", "citations", "report"]);
    expect(rows[0].hint).toMatch(/minimum severity/);
    expect(rows[2].hint).toBeNull();
    expect(rows[0].share).toBeCloseTo(63.2, 1);
  });

  it("polls only while a render is active", () => {
    expect(renderPollMs(undefined)).toBe(false);
    expect(renderPollMs([{ status: "succeeded" }, { status: "failed" }])).toBe(false);
    expect(renderPollMs([{ status: "succeeded" }, { status: "queued" }])).toBe(3000);
    expect(renderPollMs([{ status: "running" }])).toBe(3000);
  });

  it("latest render per format and typed failure text", () => {
    const base = {
      bytes: null,
      error_code: null,
      finished_at: null,
      pages: null,
      renderer_version: null,
      requested_by: "u",
      sha256: null,
      started_at: null,
      version_id: "v",
    };
    const latest = latestRenders([
      { ...base, id: "1", format: "pdf", status: "failed", error_code: "oom", created_at: "2026-11-05T10:00:00Z" },
      { ...base, id: "2", format: "pdf", status: "queued", created_at: "2026-11-05T11:00:00Z" },
      { ...base, id: "3", format: "md", status: "succeeded", created_at: "2026-11-05T09:00:00Z" },
    ]);
    expect(latest.pdf?.id).toBe("2");
    expect(latest.md?.id).toBe("3");
    expect(latest.html).toBeUndefined();
    expect(renderErrorText("too_many_pages").text).toMatch(/300-page/);
    expect(renderErrorText("brand_new").text).toBe("Rendering failed (brand new).");
  });

  it("asSnapshot accepts only a v1 snapshot shape", () => {
    const golden = JSON.parse(
      readFileSync(path.resolve(__dirname, "../components/reports/fixtures/golden_snapshot.json"), "utf8"),
    );
    expect(asSnapshot(golden)).not.toBeNull();
    expect(asSnapshot({ ...golden, schema_version: "cyberlab.report.v2" })).toBeNull();
    expect(asSnapshot({ ...golden, citations: null })).toBeNull();
    expect(asSnapshot("x")).toBeNull();
  });
});
