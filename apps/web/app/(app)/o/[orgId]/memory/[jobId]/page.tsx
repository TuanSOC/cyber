"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { Suspense } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { JobFactsCard, JobStatusAlerts, WrongModuleNotice } from "@/components/analysis/job-header";
import { EngineLabel } from "@/components/memory/memory-overview";
import { MemoryResults } from "@/components/memory/memory-results";
import { PluginStrip } from "@/components/memory/plugin-strip";
import { SensitivityBanner } from "@/components/memory/sensitivity-banner";
import { SymbolsMissing } from "@/components/memory/symbols-missing";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { MEMORY_PROFILE_LABELS, type MemoryProfile, type OsHint } from "@/lib/analysis";
import { ApiError } from "@/lib/api";
import { memoryRunErrorText, summaryCounts } from "@/lib/memory";
import { enrichDisabledReason, restrictionOf } from "@/lib/memory-sensitivity";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { formatCount } from "@/lib/pcap-results";
import { useAnalysisJob } from "@/lib/use-analysis-job";
import { useEvidenceRecord, useMemorySensitivity, useMemorySummary, useRunMemory } from "@/lib/use-memory-job";
import { useNow } from "@/lib/use-now";

export default function MemoryAnalysisJobPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { orgId, can } = useOrg();
  const router = useRouter();
  const job = useAnalysisJob(orgId, jobId);
  const j = job.data;
  const isMemory = j?.analyzer === "memory";
  const symbolsMissing = j?.status === "failed" && j.error_code === "symbols_missing";
  const summary = useMemorySummary(orgId, jobId, isMemory && (j?.status === "succeeded" || symbolsMissing));
  const evidence = useEvidenceRecord(orgId, isMemory ? j?.evidence_id : undefined);
  const sensitivity = useMemorySensitivity(orgId, isMemory ? j?.evidence_id : undefined);
  const rerun = useRunMemory(orgId, j?.evidence_id ?? "");
  const now = useNow(j?.status === "running");

  const back = orgPath(orgId, "memory");
  if (job.error instanceof ApiError && (job.error.status === 404 || job.error.status === 422)) {
    return <NotFoundCard title="Analysis not found" backHref={back} backLabel="Memory Analysis" />;
  }
  if (job.isError) return <QueryError error={job.error} onRetry={() => void job.refetch()} />;
  if (!j) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;
  if (j.analyzer !== "memory") return <WrongModuleNotice orgId={orgId} job={j} />;

  const s = summary.data;
  const profile: MemoryProfile = j.profile === "full" ? "full" : "triage";
  const osHint: OsHint = j.os_hint === "windows" || j.os_hint === "linux" ? j.os_hint : "auto";
  const restriction = restrictionOf(sensitivity.data?.state, evidence.data?.memory_sensitivity);
  const e = evidence.data;
  const canRerun = can("evidence.write") && Boolean(e) && !e?.purged_at && e?.status !== "archived";
  const counts = s ? summaryCounts(s.counts).filter((row) => ["processes", "findings", "iocs"].includes(row.key)) : [];

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Memory Analysis
      </Link>
      <PageHeader
        title={j.evidence_filename}
        description={`Memory analysis (${MEMORY_PROFILE_LABELS[profile].toLowerCase()}) · requested by ${j.requested_by_name} · offline`}
        actions={
          <>
            <EngineLabel engine={s?.engine} />
            <AnalysisStatusBadge status={j.status} />
          </>
        }
      />
      <SensitivityBanner
        orgId={orgId}
        evidenceId={j.evidence_id}
        filename={j.evidence_filename}
        restriction={restriction}
        canRelease={can("org.update")}
      />
      {symbolsMissing ? (
        <SymbolsMissing
          symbols={s?.symbols}
          canOperate={can("org.update")}
          canRerun={canRerun}
          rerunPending={rerun.isPending}
          rerunError={rerun.error ? memoryRunErrorText(rerun.error) : null}
          onRerun={() =>
            rerun.mutate(
              { profile, osHint },
              { onSuccess: (next) => router.push(orgPath(orgId, `memory/${next.id}`)) },
            )
          }
        />
      ) : (
        <JobStatusAlerts job={j} activeTitle="Analyzing the memory image… (this can take minutes to an hour)" />
      )}
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
          symbolsMissing ? (
            <p className="font-medium">Not analyzed (symbols missing)</p>
          ) : counts.length === 0 ? (
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
      {s && !symbolsMissing ? (
        <div className="mb-6">
          <PluginStrip summary={s} />
        </div>
      ) : null}
      {symbolsMissing ? null : (
        <Suspense fallback={<p className="text-sm text-muted-foreground">Loading results…</p>}>
          <MemoryResults
            orgId={orgId}
            job={j}
            summary={s}
            enrichDisabledReason={enrichDisabledReason(restriction, e ? e.ti_excluded : null)}
          />
        </Suspense>
      )}
    </>
  );
}
