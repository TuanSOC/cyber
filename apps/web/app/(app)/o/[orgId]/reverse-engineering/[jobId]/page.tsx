"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Suspense } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { JobFactsCard, JobStatusAlerts, WrongModuleNotice } from "@/components/analysis/job-header";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { ReEngineLabel, StageStrip } from "@/components/reverse/re-overview";
import { ReResults } from "@/components/reverse/re-results";
import { RE_PROFILE_LABELS } from "@/lib/analysis";
import { ApiError } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { formatCount } from "@/lib/pcap-results";
import { useAnalysisJob } from "@/lib/use-analysis-job";
import { useNow } from "@/lib/use-now";
import { useReSummary } from "@/lib/use-re-job";

const COUNT_LABELS: [string, string][] = [
  ["functions", "functions"],
  ["decompiled", "decompiled"],
  ["findings", "findings"],
  ["iocs", "IOCs"],
];

/** One RE job: header, stage strip and the result tabs (M10 phase 10). */
export default function ReverseEngineeringJobPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { orgId } = useOrg();
  const job = useAnalysisJob(orgId, jobId);
  const j = job.data;
  const isRe = j?.analyzer === "reverse";
  // A failed job may still carry a partial or diagnostic result (stage strip, program facts).
  const summary = useReSummary(orgId, jobId, isRe && (j?.status === "succeeded" || j?.status === "failed"));
  const now = useNow(j?.status === "running");

  const back = orgPath(orgId, "reverse-engineering");
  if (job.error instanceof ApiError && (job.error.status === 404 || job.error.status === 422)) {
    return <NotFoundCard title="Analysis not found" backHref={back} backLabel="Reverse Engineering" />;
  }
  if (job.isError) return <QueryError error={job.error} onRetry={() => void job.refetch()} />;
  if (!j) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;
  if (j.analyzer !== "reverse") return <WrongModuleNotice orgId={orgId} job={j} />;

  const s = summary.data;
  const profile = j.profile === "quick" ? "quick" : "full";
  const counts = s ? COUNT_LABELS.filter(([key]) => typeof s.counts[key] === "number") : [];

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Reverse Engineering
      </Link>
      <PageHeader
        title={j.evidence_filename}
        description={`Reverse engineering (${RE_PROFILE_LABELS[profile].toLowerCase()}) · requested by ${j.requested_by_name} · offline, never executed`}
        actions={
          <>
            <ReEngineLabel engine={s?.engine} version={s?.engine_version} />
            <AnalysisStatusBadge status={j.status} />
          </>
        }
      />
      <JobStatusAlerts job={j} activeTitle="Reverse engineering the program… (this takes minutes, up to an hour)" />
      {summary.isError && !(summary.error instanceof ApiError && summary.error.status === 404) ? (
        <div className="mb-6">
          <QueryError error={summary.error} onRetry={() => void summary.refetch()} />
        </div>
      ) : null}
      <JobFactsCard
        orgId={orgId}
        job={j}
        now={now}
        results={
          counts.length === 0 || !s ? (
            <p className="text-muted-foreground">—</p>
          ) : (
            <p className="tabular-nums">
              {counts.map(([key, label], index) => (
                <span key={key}>
                  {index > 0 && <span className="text-muted-foreground"> · </span>}
                  {formatCount(s.counts[key])} {label}
                </span>
              ))}
            </p>
          )
        }
      />
      {s ? (
        <div className="mb-6">
          <StageStrip stages={s.stages} />
        </div>
      ) : null}
      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading results…</p>}>
        <ReResults orgId={orgId} job={j} summary={s} />
      </Suspense>
    </>
  );
}
