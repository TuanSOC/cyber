"use client";

import { TriangleAlert } from "lucide-react";

import { ReportView } from "@/components/reports/report-view";
import { formatCount } from "@/lib/pcap-results";
import { sizeAgainstLimit, truncationNote, unitsAgainstBudget } from "@/lib/report-format";
import { type ReportPreview, asSnapshot, budgetRows, countRows } from "@/lib/reports";
import { cn } from "@/lib/utils";

/** Section counts with the truncation notes ("Showing 500 of 3,412."). */
export function SectionCountsTable({ counts }: { counts: ReportPreview["section_counts"] }) {
  const rows = countRows(counts);
  if (rows.length === 0) return null;
  return (
    <table className="w-full border-collapse text-xs">
      <caption className="sr-only">Section counts</caption>
      <thead>
        <tr>
          <th scope="col" className="border-b px-2 py-1 text-left font-medium text-muted-foreground">
            Section
          </th>
          <th scope="col" className="border-b px-2 py-1 text-right font-medium text-muted-foreground">
            Included
          </th>
          <th scope="col" className="border-b px-2 py-1 text-right font-medium text-muted-foreground">
            Available
          </th>
          <th scope="col" className="border-b px-2 py-1 text-left font-medium text-muted-foreground">
            Note
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key} className="border-b">
            <th scope="row" className="px-2 py-1 text-left font-normal">
              {row.label}
            </th>
            <td className="px-2 py-1 text-right tabular-nums">{formatCount(row.included)}</td>
            <td className="px-2 py-1 text-right tabular-nums">{formatCount(row.total)}</td>
            <td className="px-2 py-1 text-muted-foreground">{truncationNote(row.included, row.total)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Render units per section, largest first, with what to narrow (RT1). */
export function BudgetTable({ units, highlight }: { units: Record<string, number>; highlight: boolean }) {
  const rows = budgetRows(units);
  if (rows.length === 0) return null;
  return (
    <table className="w-full border-collapse text-xs">
      <caption className="sr-only">Render units per section</caption>
      <thead>
        <tr>
          <th scope="col" className="border-b px-2 py-1 text-left font-medium text-muted-foreground">
            Section
          </th>
          <th scope="col" className="border-b px-2 py-1 text-right font-medium text-muted-foreground">
            Render units
          </th>
          <th scope="col" className="border-b px-2 py-1 text-right font-medium text-muted-foreground">
            Share
          </th>
          <th scope="col" className="border-b px-2 py-1 text-left font-medium text-muted-foreground">
            To narrow
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={row.key} className={cn("border-b", highlight && index < 3 && "bg-amber-500/10")}>
            <th scope="row" className="px-2 py-1 text-left font-normal">
              {row.label}
            </th>
            <td className="px-2 py-1 text-right tabular-nums">{formatCount(row.units)}</td>
            <td className="px-2 py-1 text-right tabular-nums">{row.share} %</td>
            <td className="px-2 py-1 text-muted-foreground">{row.hint ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * The on-demand preview: size against the 8 MiB limit, render units against the budget, the
 * section counts and, below, the would-be snapshot in the same viewer as a signed version,
 * watermarked "PREVIEW, not finalized".
 */
export function PreviewPanel({ orgId, preview }: { orgId: string; preview: ReportPreview }) {
  const snapshot = asSnapshot(preview.snapshot);
  const overSize = preview.snapshot_bytes > preview.max_snapshot_bytes;
  return (
    <section aria-labelledby="report-preview-h" className="flex flex-col gap-4">
      <h2 id="report-preview-h" className="text-lg font-semibold">
        Preview
      </h2>
      <div className="grid gap-4 rounded-md border p-4 lg:grid-cols-2">
        <div className="flex flex-col gap-2 text-sm">
          <p>
            <span className="text-muted-foreground">Snapshot size: </span>
            <span className={cn(overSize && "font-semibold text-destructive")}>
              {sizeAgainstLimit(preview.snapshot_bytes, preview.max_snapshot_bytes)}
            </span>
          </p>
          <p>
            <span className="text-muted-foreground">Render budget: </span>
            <span className={cn(preview.over_budget && "font-semibold text-destructive")}>
              {unitsAgainstBudget(preview.render_units, preview.max_render_units)}
            </span>
          </p>
          {preview.over_budget || overSize ? (
            <p role="alert" className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/5 p-2 text-xs">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-destructive" aria-hidden />
              <span>
                {overSize
                  ? "This report is over the snapshot size limit and cannot be finalized. "
                  : "This report is over the render budget: finalize would be refused, because a signed version must always be renderable. "}
                Narrow the largest sections listed here.
              </span>
            </p>
          ) : null}
          <SectionCountsTable counts={preview.section_counts} />
        </div>
        <BudgetTable units={preview.section_units} highlight={preview.over_budget} />
      </div>
      {snapshot ? (
        <div className="rounded-md border p-4">
          <ReportView orgId={orgId} snapshot={snapshot} preview />
        </div>
      ) : (
        <p role="alert" className="text-sm text-destructive">
          The preview could not be shown: the API returned an unknown snapshot format.
        </p>
      )}
    </section>
  );
}
