import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { EnforceAcknowledgement } from "@/components/retention/enforce-acknowledgement";
import { PreviewResult } from "@/components/retention/retention-preview";
import {
  EnforceSwitch,
  PolicyFieldRow,
  RetentionPolicyCard,
  draftFromPolicy,
  draftValues,
} from "@/components/retention/retention-policy-card";
import { RunsTable } from "@/components/retention/retention-runs";
import { RunItemsTable } from "@/components/retention/run-detail";
import { NEVER_PURGED, type RetentionPolicy, type RetentionPreview, formatDay } from "@/lib/retention";

const ORG = "11111111-1111-4111-8111-111111111111";
const noop = () => undefined;
const HOSTILE = '<img src=x onerror="alert(1)"><script>alert(1)</script>';

function render(node: ReactElement): string {
  return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);
}

function policy(over: Partial<RetentionPolicy> = {}): RetentionPolicy {
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

describe("retention policy form", () => {
  it("shows current, pending with its effective date, and the floor", () => {
    const p = policy({ pending_ti_results_days: 90, effective_at: "2026-11-13T12:00:00Z" });
    const html = render(
      <PolicyFieldRow field="ti_results_days" policy={p} draft={draftFromPolicy(p).ti_results_days} editable onChange={noop} />,
    );
    expect(html).toContain("365 days");
    expect(html).toContain("90 days");
    expect(html).toContain(`takes effect on ${formatDay("2026-11-13T12:00:00Z")}`);
    expect(html).toContain("Minimum");
    expect(html).toContain("30 days");
    // The input starts from the pending target, so saving other fields keeps it.
    expect(html).toContain('value="90"');
  });

  it("shows keep forever and no input for viewers", () => {
    const p = policy();
    const html = render(
      <PolicyFieldRow field="ai_runs_days" policy={p} draft={draftFromPolicy(p).ai_runs_days} editable={false} onChange={noop} />,
    );
    expect(html).toContain("Keep forever");
    expect(html).not.toContain("<input");
  });

  it("validates the draft against the floors", () => {
    const p = policy();
    const draft = draftFromPolicy(p);
    draft.ti_results_days = { forever: false, raw: "10" };
    draft.ai_runs_days = { forever: false, raw: "" };
    const { values, errors } = draftValues(draft, p.floors);
    expect(errors.ti_results_days).toContain("At least 30 days");
    expect(errors.ai_runs_days).toContain("keep forever");
    expect(errors.closed_case_days).toBeUndefined();
    expect(values.closed_case_days).toBe(730);
  });

  it("hides the save button and disables the switch without org.update", () => {
    const html = render(<RetentionPolicyCard orgId={ORG} orgName="Acme" policy={policy()} editable={false} />);
    expect(html).toContain("Only owners and admins can change the retention policy.");
    expect(html).not.toContain("Save values");
    expect(html).toMatch(/role="switch"[^>]*disabled=""/);
  });

  it("shows enforcement as off by default and pending until its date", () => {
    expect(render(<EnforceSwitch policy={policy()} editable pending={false} onToggle={noop} />)).toContain("off (dry run)");
    const pending = policy({ pending_enforce: true, enforce_effective_at: "2026-11-13T12:00:00Z" });
    const html = render(<EnforceSwitch policy={pending} editable pending={false} onToggle={noop} />);
    expect(html).toContain(`enforcement begins on ${formatDay("2026-11-13T12:00:00Z")}`);
    expect(html).toContain('checked=""');
  });
});

describe("enforce acknowledgement", () => {
  const start = new Date("2026-11-13T12:00:00Z");
  const confirm = (html: string) => /<button[^>]*type="submit"[^>]*>/.exec(html)?.[0] ?? "";

  it("requires the typed org name before confirming", () => {
    const props = { orgName: "Acme SOC", onTypedChange: noop, enforcementStart: start, pending: false, onConfirm: noop, onCancel: noop };
    expect(confirm(render(<EnforceAcknowledgement {...props} typed="" />))).toContain('disabled=""');
    expect(confirm(render(<EnforceAcknowledgement {...props} typed="acme soc" />))).toContain('disabled=""');
    expect(confirm(render(<EnforceAcknowledgement {...props} typed="  Acme SOC " />))).not.toContain('disabled=""');
  });

  it("states when enforcement begins and what is and is not purged", () => {
    const html = render(
      <EnforceAcknowledgement orgName="Acme" typed="" onTypedChange={noop} enforcementStart={start} pending={false} onConfirm={noop} onCancel={noop} />,
    );
    expect(html).toContain(`Enforcement begins on ${formatDay(start)}`);
    expect(html).toContain("Purged when enforced");
    expect(html).toContain("evidence bytes");
    expect(html).toContain("Never purged by policy");
    for (const line of NEVER_PURGED) expect(html).toContain(line.replace(/&/g, "&amp;"));
  });

  it("renders a hostile org name as text", () => {
    const html = render(
      <EnforceAcknowledgement orgName={HOSTILE} typed="" onTypedChange={noop} enforcementStart={start} pending={false} onConfirm={noop} onCancel={noop} />,
    );
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
  });
});

describe("preview and runs", () => {
  const count = { candidates: 3, rows: 120, bytes: 2048, skipped_hold: 1, skipped_locked: 0, kept_cited: 2 };
  const preview: RetentionPreview = {
    generated_at: "2026-11-06T12:00:00Z",
    holds_active: 2,
    policy: { ti_results_days: 90, ai_runs_days: null, closed_case_days: 730 },
    counts: { ti_results: count, closed_case: count },
    sample: [
      { category: "closed_case", ref_table: HOSTILE, ref_id: HOSTILE, job_id: null, investigation_id: null, rows: 5, bytes: 1024 },
    ],
    truncated: true,
  };

  it("renders counts and bytes per category and the bounded sample", () => {
    const html = render(<PreviewResult preview={preview} includesPending />);
    expect(html).toContain("Threat-intel history");
    expect(html).toContain("Closed cases");
    expect(html).toContain("2.0 KiB");
    expect(html).toContain("4.0 KiB"); // total
    expect(html).toContain("includes pending values");
    expect(html).toContain("2 legal holds active");
    expect(html).toContain("(truncated)");
  });

  it("renders hostile labels in samples and items as text", () => {
    const html = render(<PreviewResult preview={preview} includesPending={false} />);
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
    const items = render(
      <RunItemsTable
        items={[
          {
            id: "i1",
            category: "ti_results",
            ref_table: HOSTILE,
            ref_id: HOSTILE,
            job_id: null,
            rows: 1,
            bytes: 10,
            outcome: "skipped_hold",
            created_at: "2026-11-06T12:00:00Z",
          },
        ]}
      />,
    );
    expect(items).not.toContain("<script>");
    expect(items).toContain("Skipped: legal hold");
  });

  it("lists runs with mode, trigger, status, counts and a link to the items", () => {
    const html = render(
      <RunsTable
        orgId={ORG}
        runs={[
          {
            id: "r1",
            mode: "dry_run",
            trigger: "schedule",
            status: "completed",
            counts: { ai_runs: count },
            policy: null,
            requested_by: null,
            error: null,
            created_at: "2026-11-06T02:30:00Z",
            started_at: "2026-11-06T02:30:01Z",
            finished_at: "2026-11-06T02:31:00Z",
          },
        ]}
      />,
    );
    expect(html).toContain("Dry run");
    expect(html).toContain("Scheduled");
    expect(html).toContain("Completed");
    expect(html).toContain(`href="/o/${ORG}/settings/retention/runs/r1"`);
  });
});
