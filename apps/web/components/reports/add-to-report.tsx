"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FilePlus2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { errorMessage } from "@/lib/api";
import { reportsHref, vis } from "@/lib/report-format";
import {
  type CitedRowRef,
  MAX_CITED_ROWS,
  addCitedRow,
  getReport,
  isStaleDraft,
  reportErrorText,
  updateReport,
} from "@/lib/reports";
import { reportKeys, useCaseReports } from "@/lib/use-reports";

/**
 * Append a cited row to a draft on the server: read the draft, add the row (deduplicated, at
 * most MAX_CITED_ROWS) and PATCH with its revision. A concurrent edit (`409 stale_draft`) is
 * retried once from a fresh read; it never overwrites another edit.
 */
export async function appendCitedRow(orgId: string, reportId: string, row: CitedRowRef): Promise<"added" | "duplicate" | "full"> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const detail = await getReport(orgId, reportId);
    const result = addCitedRow(detail.draft, row);
    if (!result.added) return result.reason ?? "duplicate";
    try {
      await updateReport(orgId, reportId, {
        revision: detail.report.revision,
        draft: result.draft,
        acknowledge_tlp_downgrade: false,
      });
      return "added";
    } catch (error) {
      if (!isStaleDraft(error) || attempt === 1) throw error;
    }
  }
  return "duplicate";
}

/**
 * "Add to report" for a case row (finding, alert, IOC…). With `onAdd` (inside the builder) the
 * row goes into the open draft; otherwise a dialog picks one of the case's drafts.
 */
export function AddToReportButton({
  orgId,
  investigationId,
  row,
  onAdd,
  disabled = false,
  label = "Add to report",
}: {
  orgId: string;
  investigationId: string;
  row: CitedRowRef;
  onAdd?: (row: CitedRowRef) => void;
  disabled?: boolean;
  label?: string;
}) {
  if (onAdd) {
    return (
      <Button size="sm" variant="ghost" className="h-7 gap-1 px-2 text-xs" disabled={disabled} onClick={() => onAdd(row)}>
        <FilePlus2 className="size-3.5" aria-hidden />
        {label}
      </Button>
    );
  }
  return <AddToReportDialog orgId={orgId} investigationId={investigationId} row={row} disabled={disabled} label={label} />;
}

function AddToReportDialog({
  orgId,
  investigationId,
  row,
  disabled,
  label,
}: {
  orgId: string;
  investigationId: string;
  row: CitedRowRef;
  disabled: boolean;
  label: string;
}) {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const reports = useCaseReports(orgId, investigationId, open);
  const drafts = (reports.data?.items ?? []).filter((report) => report.status === "draft");
  const add = useMutation({
    mutationFn: (reportId: string) => appendCitedRow(orgId, reportId, row),
    onSuccess: async (result, reportId) => {
      await queryClient.invalidateQueries({ queryKey: reportKeys.detail(orgId, reportId) });
      if (result === "added") toast.success("Added to the report's cited rows.");
      else if (result === "duplicate") toast.info("This row is already cited in that report.");
      else toast.error(`That report already cites ${MAX_CITED_ROWS} rows.`);
      setOpen(false);
    },
    onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)),
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="ghost" className="h-7 gap-1 px-2 text-xs" disabled={disabled}>
          <FilePlus2 className="size-3.5" aria-hidden />
          {label}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add to a report</DialogTitle>
          <DialogDescription>The row is cited in the next version of the draft you pick.</DialogDescription>
        </DialogHeader>
        {reports.isLoading ? <p className="text-sm text-muted-foreground">Loading reports…</p> : null}
        {reports.isError ? <p className="text-sm text-destructive">{reportErrorText(reports.error) ?? errorMessage(reports.error)}</p> : null}
        {reports.data && drafts.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            This case has no report draft yet. <Link href={reportsHref(orgId)} className="underline underline-offset-4">Create one</Link>.
          </p>
        ) : null}
        <ul className="flex flex-col gap-1">
          {drafts.map((report) => (
            <li key={report.id}>
              <Button
                variant="outline"
                className="w-full justify-start"
                disabled={add.isPending}
                onClick={() => add.mutate(report.id)}
              >
                <span className="truncate">{vis(report.title)}</span>
              </Button>
            </li>
          ))}
        </ul>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
