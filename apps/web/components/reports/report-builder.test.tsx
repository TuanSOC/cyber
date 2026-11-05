import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { appendCitedRow } from "@/components/reports/add-to-report";
import { DISTRIBUTION_REQUIRED_TEXT, DistributionField, ProfileField, SectionsEditor } from "@/components/reports/builder-fields";
import { type FinalizeSummary, FinalizeForm } from "@/components/reports/finalize-dialog";
import { SaveState } from "@/components/reports/report-builder";
import { RenderRow } from "@/components/reports/report-renders";
import { AiRunsPicker } from "@/components/reports/selection-pickers";
import { TlpSelect } from "@/components/tlp/tlp-select";
import type { AiRun } from "@/lib/ai";
import { ApiError } from "@/lib/api";
import * as reports from "@/lib/reports";
import {
  EXTERNAL_REVIEW_ACK,
  EXTERNAL_REVIEW_WARNING,
  ReportApiError,
  type ReportDetail,
  type ReportUpdate,
  defaultDraft,
  emptySections,
} from "@/lib/reports";

vi.mock("@/lib/reports", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/reports")>();
  return { ...actual, getReport: vi.fn(), updateReport: vi.fn() };
});

const ORG = "11111111-1111-4111-8111-111111111111";
const REPORT = "22222222-2222-4222-8222-222222222222";
const JOB = "55555555-5555-4555-8555-555555555555";

function render(node: ReactElement): string {
  return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);
}

const noop = () => {};

function submitButton(markup: string): string {
  const match = /<button[^>]*type="submit"[^>]*>/.exec(markup);
  if (!match) throw new Error("no submit button");
  return match[0];
}

const summary: FinalizeSummary = {
  tlp: "amber",
  caseTlp: "amber",
  profile: "internal",
  distribution: "",
  nextVersion: 3,
  counts: { findings: { included: 500, total: 3412 } },
};

describe("builder fields", () => {
  it("distribution is required for RED / AMBER+STRICT / external, with a counter", () => {
    const required = render(<DistributionField value="" required onChange={noop} disabled={false} />);
    expect(required).toContain("(required)");
    expect(required).toContain(DISTRIBUTION_REQUIRED_TEXT);
    expect(required).toContain('aria-invalid="true"');
    expect(required).toContain("0 / 500 characters");
    const optional = render(<DistributionField value="SOC" required={false} onChange={noop} disabled={false} />);
    expect(optional).toContain("(optional)");
    expect(optional).not.toContain(DISTRIBUTION_REQUIRED_TEXT);
  });

  it("profile external explains what it removes and that review is needed (RT8)", () => {
    const markup = render(<ProfileField value="external" onChange={noop} disabled={false} />);
    expect(markup).toContain("pseudonyms");
    expect(markup).toContain("analyst notes, custody IP addresses");
    expect(markup).toContain(EXTERNAL_REVIEW_WARNING.slice(0, 40));
    expect(render(<ProfileField value="internal" onChange={noop} disabled={false} />)).not.toContain("pattern-based");
  });

  it("analyst sections are plain textareas with limits and counters", () => {
    const markup = render(
      <SectionsEditor sections={{ ...emptySections(), impact: "x".repeat(19_000) }} onChange={noop} disabled={false} />,
    );
    expect(markup.match(/<textarea/g)).toHaveLength(8);
    expect(markup.match(/maxLength="20000"/gi)).toHaveLength(8);
    expect(markup).not.toContain("contenteditable");
    expect(markup).toContain("19,000 / 20,000 characters");
  });

  it("a downgrade below the case TLP is disabled for roles without org.update", () => {
    const analyst = render(<TlpSelect value="amber" current="amber" canDowngrade={false} onChange={noop} />);
    expect(analyst).toMatch(/<option value="clear" disabled="">/);
    expect(analyst).toMatch(/<option value="green" disabled="">/);
    expect(analyst).toMatch(/<option value="red">/);
    const admin = render(<TlpSelect value="green" current="amber" canDowngrade onChange={noop} />);
    expect(admin).not.toMatch(/<option value="clear" disabled="">/);
    expect(admin).toContain("I confirm lowering the marking from TLP:AMBER to TLP:GREEN");
  });
});

describe("autosave state", () => {
  it("a conflict shows the banner with Reload, never a silent overwrite", () => {
    const markup = render(
      <SaveState state={{ status: "conflict", revision: 4, error: new ApiError(409, "stale_draft", "x") }} onReload={noop} onRetry={noop} />,
    );
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('tabindex="-1"');
    expect(markup).toContain("changed somewhere else");
    expect(markup).toContain("nothing was overwritten");
    expect(markup).toContain("Reload");
    expect(markup).toContain('data-save-status="conflict"');
  });

  it("an error offers a retry with the typed reason", () => {
    const markup = render(
      <SaveState
        state={{ status: "error", revision: 4, error: new ApiError(422, "selection_out_of_scope", "x") }}
        onReload={noop}
        onRetry={noop}
      />,
    );
    expect(markup).toContain("not part of this case any more");
    expect(markup).toContain("Retry saving");
  });
});

describe("finalize confirmation", () => {
  it("summarizes the version and allows finalize when nothing blocks", () => {
    const markup = render(
      <FinalizeForm summary={summary} canDowngrade={false} blockers={[]} pending={false} error={null} onSubmit={noop} onCancel={noop} />,
    );
    expect(markup).toContain("A signed, immutable version v3 will be created.");
    expect(markup).toContain("Showing 500 of 3,412.");
    expect(markup).toContain("Change note");
    expect(markup).toContain("0 / 500 characters");
    expect(submitButton(markup)).not.toContain('disabled=""');
  });

  it("external needs the review acknowledgement (RT8)", () => {
    const markup = render(
      <FinalizeForm
        summary={{ ...summary, profile: "external", distribution: "Partner CERT" }}
        canDowngrade={false}
        blockers={[]}
        pending={false}
        error={null}
        onSubmit={noop}
        onCancel={noop}
      />,
    );
    expect(markup).toContain(EXTERNAL_REVIEW_ACK);
    expect(submitButton(markup)).toContain('disabled=""');
  });

  it("below the case TLP: an explanation for analysts, the acknowledgement for admins (RT7)", () => {
    const below = { ...summary, tlp: "amber" as const, caseTlp: "red" as const };
    const error = new ApiError(409, "tlp_below_case", "x");
    const analyst = render(
      <FinalizeForm summary={below} canDowngrade={false} blockers={[]} pending={false} error={error} onSubmit={noop} onCancel={noop} />,
    );
    expect(analyst).toContain("The case is marked TLP:RED, more restrictive than this report&#x27;s TLP:AMBER.");
    expect(analyst).toContain("Only an admin can sign a report below the case TLP.");
    expect(submitButton(analyst)).toContain('disabled=""');
    const admin = render(
      <FinalizeForm summary={below} canDowngrade blockers={[]} pending={false} error={error} onSubmit={noop} onCancel={noop} />,
    );
    expect(admin).toContain("I confirm signing this report below the case marking.");
    expect(submitButton(admin)).toContain('disabled=""'); // until the box is ticked
  });

  it("422 report_too_large_to_render lists the per-section units and hints (RT1)", () => {
    const base = new ApiError(422, "report_too_large_to_render", "too big");
    const error = new ReportApiError(base, { section_units: { findings: 700_000, timeline: 90_000 } });
    const markup = render(
      <FinalizeForm summary={summary} canDowngrade={false} blockers={[]} pending={false} error={error} onSubmit={noop} onCancel={noop} />,
    );
    expect(markup).toContain("over the render budget");
    expect(markup).toContain("700,000");
    expect(markup).toContain("Narrow the timeline kinds or time range, or lower the maximum.");
  });

  it("blockers (distribution required) disable finalize", () => {
    const markup = render(
      <FinalizeForm
        summary={{ ...summary, tlp: "red", caseTlp: "red" }}
        canDowngrade={false}
        blockers={["TLP:RED and TLP:AMBER+STRICT reports need a distribution statement (who may receive it)."]}
        pending={false}
        error={null}
        onSubmit={noop}
        onCancel={noop}
      />,
    );
    expect(markup).toContain("need a distribution statement");
    expect(submitButton(markup)).toContain('disabled=""');
  });
});

describe("pickers and renders", () => {
  const run = (id: string, over: Partial<AiRun> = {}): AiRun =>
    ({
      id,
      task: "summarize_pcap",
      scope: "job",
      status: "completed",
      provider: "anthropic",
      model: "claude-x",
      served_model: null,
      finished_at: "2026-11-05T10:00:00Z",
      created_at: "2026-11-05T09:00:00Z",
      citation_accuracy: 0.9,
      claims_unsupported: 2,
      ...over,
    }) as AiRun;

  it("AI runs show the model and stop at 10 selections", () => {
    const include = { ...defaultDraft().include, ai_runs: Array.from({ length: 10 }, (_, i) => `r${i}`) };
    const markup = render(
      <AiRunsPicker include={include} onChange={noop} disabled={false} runs={[run("r0"), run("new")]} loading={false} error={null} />,
    );
    expect(markup).toContain("anthropic / claude-x");
    expect(markup).toContain("citations verified 90%");
    const boxes = markup.match(/<input type="checkbox"[^>]*>/g) ?? [];
    expect(boxes[0]).toContain("checked");
    expect(boxes[0]).not.toContain("disabled");
    expect(boxes[1]).toContain("disabled");
  });

  it("render rows show typed failures with a hint, and downloads only when ready", () => {
    const base = {
      id: "33333333-3333-4333-8333-333333333333",
      version_id: "v",
      format: "pdf" as const,
      bytes: null,
      pages: null,
      sha256: null,
      renderer_version: null,
      requested_by: "u",
      created_at: "2026-11-05T10:00:00Z",
      started_at: null,
      finished_at: null,
    };
    const failed = render(
      <ul>
        <RenderRow
          format="pdf"
          render={{ ...base, status: "failed", error_code: "too_many_pages" }}
          canRender
          canDownload
          onRender={noop}
          onDownload={noop}
          pending={false}
        />
      </ul>,
    );
    expect(failed).toContain("Failed: The document is over the 300-page limit.");
    expect(failed).toContain("Finalize a narrower version");
    expect(failed).toContain("Render again");
    expect(failed).not.toContain("Download");
    const ready = render(
      <ul>
        <RenderRow
          format="pdf"
          render={{ ...base, status: "succeeded", error_code: null, bytes: 2048, pages: 12, sha256: "b".repeat(64), finished_at: "2026-11-05T10:01:00Z" }}
          canRender
          canDownload
          onRender={noop}
          onDownload={noop}
          pending={false}
        />
      </ul>,
    );
    expect(ready).toContain("Ready · 2.0 KiB · 12 pages");
    expect(ready).toContain("Download");
    expect(ready).not.toContain("Render again");
  });
});

describe("appendCitedRow (Add to report)", () => {
  const getReport = vi.mocked(reports.getReport);
  const updateReport = vi.mocked(reports.updateReport);
  beforeEach(() => {
    getReport.mockReset();
    updateReport.mockReset();
  });

  function detail(revision: number, rows = defaultDraft().include.cited_rows): ReportDetail {
    const draft = defaultDraft();
    draft.include.cited_rows = rows;
    return { draft, versions: [], report: { id: REPORT, revision } as ReportDetail["report"] };
  }

  it("PATCHes with the read revision and retries once from a fresh read on stale_draft", async () => {
    const reads = [detail(4), detail(6)];
    getReport.mockImplementation(async () => reads.shift() ?? detail(9));
    const update = updateReport
      .mockRejectedValueOnce(new ApiError(409, "stale_draft", "x"))
      .mockImplementation(async (_o: string, _r: string, body: ReportUpdate) => detail(body.revision + 1));
    const row = { kind: "finding" as const, ref_id: "f1", job_id: JOB };
    await expect(appendCitedRow(ORG, REPORT, row)).resolves.toBe("added");
    expect(update).toHaveBeenCalledTimes(2);
    expect(update.mock.calls[0][2]).toMatchObject({ revision: 4 });
    expect(update.mock.calls[1][2]).toMatchObject({ revision: 6, draft: { include: { cited_rows: [row] } } });
  });

  it("does not write a duplicate, and gives up after a second conflict", async () => {
    const row = { kind: "alert" as const, ref_id: "a1", job_id: JOB };
    getReport.mockResolvedValue(detail(2, [row]));
    const update = updateReport;
    await expect(appendCitedRow(ORG, REPORT, row)).resolves.toBe("duplicate");
    expect(update).not.toHaveBeenCalled();

    getReport.mockResolvedValue(detail(2));
    update.mockRejectedValue(new ApiError(409, "stale_draft", "x"));
    await expect(appendCitedRow(ORG, REPORT, row)).rejects.toMatchObject({ code: "stale_draft" });
    expect(update).toHaveBeenCalledTimes(2);
  });
});
