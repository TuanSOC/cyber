"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Suspense } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { JobFactsCard, JobStatusAlerts, WrongModuleNotice } from "@/components/analysis/job-header";
import { DiskResults } from "@/components/disk/disk-results";
import { DiskSensitivityBanner } from "@/components/disk/disk-sensitivity-banner";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { analysisKindLabel } from "@/lib/analysis";
import { ApiError } from "@/lib/api";
import { diskEnrichDisabledReason, diskRestriction, diskSummaryCounts } from "@/lib/disk";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { formatCount } from "@/lib/pcap-results";
import { useAnalysisJob } from "@/lib/use-analysis-job";
import { useDiskSummary, useEvidenceRecord, useSegmentSensitivity } from "@/lib/use-disk-job";
import { useNow } from "@/lib/use-now";

export default function DiskAnalysisJobPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { orgId, can } = useOrg();
  const job = useAnalysisJob(orgId, jobId);
  const j = job.data;
  const isDisk = j?.analyzer === "disk";
  const isExtract = isDisk && j?.profile === "extract";
  const summary = useDiskSummary(orgId, jobId, isDisk && !isExtract && j?.status === "succeeded");
  const s = summary.data;
  // Every segment's sensitivity (RT20); the job's evidence (segment 0) until the summary lists them.
  const segments = s?.segments ?? (j ? [{ evidence_id: j.evidence_id, original_filename: j.evidence_filename }] : []);
  const segmentIds = isDisk ? segments.map((segment) => segment.evidence_id) : [];
  const sensitivity = useSegmentSensitivity(orgId, segmentIds);
  const evidence = useEvidenceRecord(orgId, isDisk ? j?.evidence_id : undefined);
  const now = useNow(j?.status === "running");

  const back = orgPath(orgId, "forensics");
  if (job.error instanceof ApiError && (job.error.status === 404 || job.error.status === 422)) {
    return <NotFoundCard title="Analysis not found" backHref={back} backLabel="Forensics" />;
  }
  if (job.isError) return <QueryError error={job.error} onRetry={() => void job.refetch()} />;
  if (!j) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;
  if (j.analyzer !== "disk") return <WrongModuleNotice orgId={orgId} job={j} />;

  const restriction = diskRestriction(sensitivity.map((q) => q.data?.state));
  const e = evidence.data;
  const counts = s ? diskSummaryCounts(s.counts) : [];

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Forensics
      </Link>
      <PageHeader
        title={j.evidence_filename}
        description={`${analysisKindLabel(j)} · requested by ${j.requested_by_name} · offline`}
        actions={
          <>
            {restriction === "restricted" ? <Badge variant="destructive">Restricted (TLP:RED)</Badge> : null}
            <AnalysisStatusBadge status={j.status} />
          </>
        }
      />
      <DiskSensitivityBanner
        orgId={orgId}
        jobId={j.id}
        evidenceId={j.evidence_id}
        investigationId={j.investigation_id}
        segments={segments.map((segment) => ({ evidenceId: segment.evidence_id, filename: segment.original_filename }))}
        restriction={restriction}
        canRelease={can("org.update")}
      />
      <JobStatusAlerts job={j} activeTitle="Analyzing the disk image… (downloading and verifying every segment first)" />
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
          counts.length === 0 ? (
            <p className="text-muted-foreground">—</p>
          ) : (
            <p className="tabular-nums">
              {counts.map((row, index) => (
                <span key={row.key}>
                  {index > 0 && <span className="text-muted-foreground"> · </span>}
                  {formatCount(row.value)} {row.label}
                </span>
              ))}
            </p>
          )
        }
      />
      {isExtract ? (
        <Alert>
          <AlertTitle>File export job</AlertTitle>
          <AlertDescription>
            This job copied files out of a disk image. Its exports are listed, with their state, on the Exports tab of the
            disk analysis they were requested from.
          </AlertDescription>
        </Alert>
      ) : (
        <Suspense fallback={<p className="text-sm text-muted-foreground">Loading results…</p>}>
          <DiskResults
            orgId={orgId}
            job={j}
            summary={s}
            restricted={restriction !== "released" && restriction !== "none"}
            canWrite={can("evidence.write")}
            enrichDisabledReason={diskEnrichDisabledReason(restriction, e ? e.ti_excluded : null)}
          />
        </Suspense>
      )}
    </>
  );
}
