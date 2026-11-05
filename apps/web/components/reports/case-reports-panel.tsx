"use client";

import Link from "next/link";

import { NewReportDialog } from "@/components/reports/new-report-dialog";
import { ReportsTable } from "@/components/reports/reports-table";
import { errorMessage } from "@/lib/api";
import { reportErrorText } from "@/lib/reports";
import type { Permission } from "@/lib/roles";
import { useCaseReports } from "@/lib/use-reports";

/**
 * The reports of one case on its page (Reports tab), with "New report" for this case. `can`
 * comes from the case page's org membership (`useOrg`); an archived case gets no new report.
 */
export function CaseReportsPanel({
  orgId,
  investigationId,
  can,
  archived = false,
}: {
  orgId: string;
  investigationId: string;
  can: (permission: Permission) => boolean;
  archived?: boolean;
}) {
  const reports = useCaseReports(orgId, investigationId);
  const items = reports.data?.items ?? [];
  const all = `/o/${encodeURIComponent(orgId)}/reports?investigation=${encodeURIComponent(investigationId)}`;
  return (
    <section aria-labelledby="case-reports-h" className="flex flex-col gap-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="case-reports-h" className="text-sm font-semibold">
          Reports
        </h2>
        <div className="flex items-center gap-3">
          <Link href={all} className="text-sm underline underline-offset-4">
            All reports of this case
          </Link>
          <NewReportDialog orgId={orgId} investigationId={investigationId} disabled={archived || !can("investigation.write")} />
        </div>
      </div>
      {reports.isLoading ? <p className="text-sm text-muted-foreground">Loading reports…</p> : null}
      {reports.isError ? (
        <p className="text-sm text-muted-foreground">{reportErrorText(reports.error) ?? errorMessage(reports.error)}</p>
      ) : null}
      {reports.data && items.length === 0 ? <p className="text-sm text-muted-foreground">No reports for this case yet.</p> : null}
      {items.length ? <ReportsTable orgId={orgId} reports={items} showCase={false} /> : null}
    </section>
  );
}
