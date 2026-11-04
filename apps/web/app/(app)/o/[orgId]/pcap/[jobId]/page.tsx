"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Suspense } from "react";

import { AnalysisResults } from "@/components/analysis/analysis-results";
import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  type AnalysisJob,
  analysisErrorText,
  isActiveStatus,
  jobDurationText,
  justSucceeded,
  pollWhileActive,
} from "@/lib/analysis";
import { ApiError, api, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { formatCount, parseOverview } from "@/lib/pcap-results";
import { useNow } from "@/lib/use-now";

const HEADLINE_COUNTS = new Set(["findings", "alerts", "flows"]);

export default function AnalysisPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { orgId } = useOrg();
  const queryClient = useQueryClient();
  const key = ["org", orgId, "analysis", jobId];

  const job = useQuery({
    queryKey: key,
    queryFn: async () => {
      const previous = queryClient.getQueryData<AnalysisJob>(key);
      const next = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}", {
          params: { path: { org_id: orgId, job_id: jobId } },
        }),
      );
      if (justSucceeded(previous ? [previous] : undefined, [next])) {
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", next.evidence_id] });
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] });
      }
      return next;
    },
    refetchInterval: (query) => pollWhileActive(query.state.data ? [query.state.data] : undefined),
  });
  const now = useNow(job.data?.status === "running");

  const back = orgPath(orgId, "pcap");
  if (job.error instanceof ApiError && (job.error.status === 404 || job.error.status === 422)) {
    return <NotFoundCard title="Analysis not found" backHref={back} backLabel="PCAP Analyzer" />;
  }
  if (job.isError) return <QueryError error={job.error} onRetry={() => void job.refetch()} />;
  const j = job.data;
  if (!j) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;

  const error = analysisErrorText(j.error_code);
  const counts = parseOverview(j.summary).counts.filter((row) => HEADLINE_COUNTS.has(row.key));
  const active = isActiveStatus(j.status);
  const timings: [string, string | null][] = [
    ["Requested", j.created_at],
    ["Started", j.started_at],
    ["Finished", j.finished_at],
  ];

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> PCAP Analyzer
      </Link>
      <PageHeader
        title={j.evidence_filename}
        description={`PCAP analysis · ${j.auto ? "started automatically on upload" : `requested by ${j.requested_by_name}`}`}
        actions={<AnalysisStatusBadge status={j.status} />}
      />
      {j.status === "failed" && error && (
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Analysis failed</AlertTitle>
          <AlertDescription>
            {error}
            <span className="ml-1 font-mono text-xs">({j.error_code})</span>
          </AlertDescription>
        </Alert>
      )}
      {active && (
        <Alert className="mb-6">
          <AlertTitle>{j.status === "queued" ? "Waiting for an analyzer worker…" : "Analyzing the capture…"}</AlertTitle>
          <AlertDescription>This page updates automatically.</AlertDescription>
        </Alert>
      )}

      <Card className="mb-6">
        <CardContent className="grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
          <div className="min-w-0">
            <p className="text-xs text-muted-foreground">Evidence</p>
            <Link
              className="block truncate hover:underline"
              title={j.evidence_filename}
              href={orgPath(orgId, `evidence/${j.evidence_id}`)}
            >
              {j.evidence_filename}
            </Link>
            <Link
              className="text-xs underline underline-offset-4"
              href={orgPath(orgId, `investigations/${j.investigation_id}`)}
            >
              Open case
            </Link>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Timing</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-xs">
              {timings.map(([label, iso]) => {
                const when = iso ? formatDate(iso) : null;
                return (
                  <div key={label} className="contents">
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd title={when?.utc}>{when?.local ?? "—"}</dd>
                  </div>
                );
              })}
            </dl>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Duration</p>
            <p className="tabular-nums">{jobDurationText(j, now)}</p>
            <Badge variant={j.auto ? "secondary" : "outline"} className="mt-1">
              {j.auto ? "Auto" : "Manual"}
            </Badge>
          </div>
          <div className="min-w-0">
            <p className="text-xs text-muted-foreground">Results</p>
            {counts.length === 0 ? (
              <p className="text-muted-foreground">—</p>
            ) : (
              <p className="tabular-nums">
                {counts.map((row, index) => (
                  <span key={row.key}>
                    {index > 0 && <span className="text-muted-foreground"> · </span>}
                    {formatCount(row.stored)} {row.label.toLowerCase()}
                  </span>
                ))}
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading results…</p>}>
        <AnalysisResults orgId={orgId} job={j} />
      </Suspense>
    </>
  );
}
