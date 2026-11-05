"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { NewReportDialog } from "@/components/reports/new-report-dialog";
import { ReportsTable } from "@/components/reports/reports-table";
import { Button } from "@/components/ui/button";
import { isUuid } from "@/lib/ai";
import { useOrg } from "@/lib/org-context";
import { reportsHref } from "@/lib/report-format";
import { reportErrorText } from "@/lib/reports";
import { useReportList } from "@/lib/use-reports";

/** The org's reports (drafts and their latest signed versions), filterable by case. */
export default function ReportsPage() {
  const { orgId, can } = useOrg();
  return (
    <>
      <PageHeader
        title="Reports"
        description="Investigation reports with evidence citations: drafts, previews and signed, immutable versions."
        actions={<NewReportDialog orgId={orgId} disabled={!can("investigation.write")} />}
      />
      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
        <ReportList orgId={orgId} />
      </Suspense>
    </>
  );
}

function ReportList({ orgId }: { orgId: string }) {
  const searchParams = useSearchParams();
  const raw = searchParams.get("investigation");
  const investigationId = raw && isUuid(raw) ? raw : null;
  const list = useReportList(orgId, investigationId);
  const items = list.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <div className="flex flex-col gap-4">
      {investigationId ? (
        <p className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">Showing the reports of one case.</span>
          <Link href={reportsHref(orgId)} className="underline underline-offset-4">
            Show all reports
          </Link>
          <Link
            href={`/o/${encodeURIComponent(orgId)}/investigations/${encodeURIComponent(investigationId)}`}
            className="underline underline-offset-4"
          >
            Open the case
          </Link>
        </p>
      ) : null}
      {list.isError ? (
        <div className="flex flex-col gap-2">
          {reportErrorText(list.error) ? <p className="text-sm text-muted-foreground">{reportErrorText(list.error)}</p> : null}
          <QueryError error={list.error} onRetry={() => void list.refetch()} />
        </div>
      ) : list.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading reports…</p>
      ) : items.length === 0 ? (
        <p className="rounded-md border p-6 text-center text-sm text-muted-foreground">
          No reports yet. Create one from a case with “New report”.
        </p>
      ) : (
        <ReportsTable orgId={orgId} reports={items} />
      )}
      {list.hasNextPage ? (
        <Button variant="outline" className="w-fit" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
          {list.isFetchingNextPage ? "Loading…" : "Load more"}
        </Button>
      ) : null}
    </div>
  );
}
