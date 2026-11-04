"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Suspense } from "react";

import { AnalysisResults } from "@/components/analysis/analysis-results";
import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { JobFactsCard, JobStatusAlerts, WrongModuleNotice } from "@/components/analysis/job-header";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { ApiError } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { formatCount, parseOverview } from "@/lib/pcap-results";
import { useAnalysisJob } from "@/lib/use-analysis-job";
import { useNow } from "@/lib/use-now";

const HEADLINE_COUNTS = new Set(["findings", "alerts", "flows"]);

export default function AnalysisPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { orgId } = useOrg();
  const job = useAnalysisJob(orgId, jobId);
  const now = useNow(job.data?.status === "running");

  const back = orgPath(orgId, "pcap");
  if (job.error instanceof ApiError && (job.error.status === 404 || job.error.status === 422)) {
    return <NotFoundCard title="Analysis not found" backHref={back} backLabel="PCAP Analyzer" />;
  }
  if (job.isError) return <QueryError error={job.error} onRetry={() => void job.refetch()} />;
  const j = job.data;
  if (!j) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;
  if (j.analyzer !== "pcap") return <WrongModuleNotice orgId={orgId} job={j} />;

  const counts = parseOverview(j.summary).counts.filter((row) => HEADLINE_COUNTS.has(row.key));

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
      <JobStatusAlerts job={j} activeTitle="Analyzing the capture…" />
      <JobFactsCard
        orgId={orgId}
        job={j}
        now={now}
        results={
          counts.length === 0 ? (
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
          )
        }
      />

      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading results…</p>}>
        <AnalysisResults orgId={orgId} job={j} />
      </Suspense>
    </>
  );
}
