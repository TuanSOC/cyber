"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { AiOffNotice, NoRunPermissionNote, type ProviderChoice, ProviderOverride, useAiAccess } from "@/components/ai/ai-access";
import { AiBanner } from "@/components/ai/ai-banner";
import { ContextPreviewDialog, aiErrorMessage } from "@/components/ai/context-preview-dialog";
import { RunHistory } from "@/components/ai/run-history";
import { AiRunStatusBadge } from "@/components/ai/run-status";
import { RunView } from "@/components/ai/run-view";
import { useInvestigationAnalyses } from "@/components/analysis/investigation-analyses";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  type AiChildRun,
  type AiRunCreate,
  type AiRunDetail,
  aiErrorText,
  childFlags,
  digestProgress,
  failedChildren,
  flagText,
  formatAccuracy,
} from "@/lib/ai";
import { type AnalysisJob, analysisKindLabel, analysisSegment } from "@/lib/analysis";
import { orgPath } from "@/lib/nav";
import { useAiRuns, useCreateAiRun } from "@/lib/use-ai";

/**
 * Incident card of an investigation: "Generate incident summary" (preview first), the parent
 * status with per-job digest progress, the summary (claims, timeline from the cited records,
 * recommendations) and the collapsible per-job digests with their flags (RT23).
 */
export function IncidentCard({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const access = useAiAccess(orgId);
  const [choice, setChoice] = useState<ProviderChoice>({});
  const [selected, setSelected] = useState<{ id: string; deduplicated: boolean; request?: AiRunCreate } | null>(null);
  const runs = useAiRuns(orgId, { investigation_id: investigationId, task: "incident_summary", limit: 20 });
  const analyses = useInvestigationAnalyses(orgId, investigationId);
  const create = useCreateAiRun(orgId);
  const items = runs.data?.items ?? [];
  const shownId = selected?.id ?? items[0]?.id ?? null;
  const jobs = new Map((analyses.data?.items ?? []).map((job) => [job.id, job]));

  const request = (regenerate = false): AiRunCreate => ({
    task: "incident_summary",
    investigation_id: investigationId,
    ...(choice.provider ? { provider: choice.provider } : {}),
    ...(choice.model ? { model: choice.model } : {}),
    ...(regenerate ? { regenerate: true } : {}),
  });
  const start = (body: AiRunCreate) =>
    create.mutate(body, {
      onSuccess: (created) => setSelected({ id: created.run.id, deduplicated: created.deduplicated, request: body }),
      onError: (error) => toast.error(aiErrorMessage(error)),
    });

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Incident summary (AI)</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <AiBanner />
        {access.settings.isError ? (
          <QueryError error={access.settings.error} onRetry={() => void access.settings.refetch()} />
        ) : access.enabled === undefined ? null : !access.enabled ? (
          <AiOffNotice orgId={orgId} canManage={access.canManage} platformOff={access.platformOff} />
        ) : !access.canRun ? (
          <NoRunPermissionNote />
        ) : (
          <div className="flex flex-col gap-2">
            <div>
              <ContextPreviewDialog
                orgId={orgId}
                request={request()}
                canManage={access.canManage}
                pending={create.isPending}
                onRun={() => start(request())}
                title="Incident summary"
              >
                Generate incident summary
              </ContextPreviewDialog>
            </div>
            <ProviderOverride
              orgId={orgId}
              value={choice}
              onChange={setChoice}
              defaultProvider={access.settings.data?.default_provider}
            />
            <p className="text-[11px] text-muted-foreground">
              One digest per latest succeeded analysis of each evidence, then a summary over the verified digest
              statements and the case timeline.
            </p>
          </div>
        )}
        {runs.isError && <QueryError error={runs.error} onRetry={() => void runs.refetch()} />}
        {runs.isSuccess && items.length === 0 && !selected && (
          <p className="text-sm text-muted-foreground">No incident summary for this case yet.</p>
        )}
        {shownId && (
          <RunView
            key={shownId}
            orgId={orgId}
            runId={shownId}
            banner={false}
            variant="incident"
            deduplicated={selected?.id === shownId && selected.deduplicated}
            regenerating={create.isPending}
            onRegenerate={
              selected?.request && access.canRun && access.enabled
                ? () => start({ ...selected.request!, regenerate: true })
                : undefined
            }
            extraFlags={(run) => childFlags(run.child_runs)}
          >
            {(run) => <Digests orgId={orgId} run={run} jobs={jobs} />}
          </RunView>
        )}
        <RunHistory runs={items} selected={shownId} onSelect={(id) => setSelected({ id, deduplicated: false })} />
      </CardContent>
    </Card>
  );
}

function DigestProgress({ run }: { run: AiRunDetail | undefined }) {
  if (!run || run.child_runs.length === 0) return null;
  const { done, total } = digestProgress(run.child_runs);
  return (
    <span className="text-xs text-muted-foreground tabular-nums">
      {done} of {total} digests finished
    </span>
  );
}

function jobName(job: AnalysisJob | undefined, child: AiChildRun): string {
  return job ? `${job.evidence_filename} (${analysisKindLabel(job)})` : `Analysis ${child.job_id?.slice(0, 8) ?? "?"}`;
}

/** Per-job digests: progress, the jobs that failed, and each digest collapsible. */
function Digests({ orgId, run, jobs }: { orgId: string; run: AiRunDetail; jobs: Map<string, AnalysisJob> }) {
  if (run.child_runs.length === 0) return null;
  const failed = failedChildren(run.child_runs);
  return (
    <section className="flex flex-col gap-2">
      <h3 className="flex items-center gap-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        Per-job digests <DigestProgress run={run} />
      </h3>
      {failed.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Not covered by the summary:{" "}
          {failed.map((child) => jobName(child.job_id ? jobs.get(child.job_id) : undefined, child)).join(", ")}.
        </p>
      )}
      <ul className="flex flex-col divide-y rounded-md border">
        {run.child_runs.map((child) => (
          <DigestRow key={child.id} orgId={orgId} child={child} job={child.job_id ? jobs.get(child.job_id) : undefined} />
        ))}
      </ul>
    </section>
  );
}

function DigestRow({ orgId, child, job }: { orgId: string; child: AiChildRun; job: AnalysisJob | undefined }) {
  const [open, setOpen] = useState(false);
  const problem =
    child.status === "failed"
      ? aiErrorText(child.error_code)
      : child.status === "refused"
        ? `The provider declined this digest (category: ${child.refusal_category || "unspecified"}).`
        : null;
  return (
    <li className="flex flex-col gap-2 px-3 py-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          className="size-6"
          aria-expanded={open}
          aria-label={open ? "Hide digest" : "Show digest"}
          onClick={() => setOpen(!open)}
        >
          {open ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
        </Button>
        {job ? (
          <Link href={orgPath(orgId, analysisSegment(job))} className="max-w-80 truncate hover:underline" title={jobName(job, child)}>
            {jobName(job, child)}
          </Link>
        ) : (
          <span>{jobName(job, child)}</span>
        )}
        <AiRunStatusBadge status={child.status} />
        <span className="text-muted-foreground">citations checked {formatAccuracy(child.citation_accuracy)}</span>
      </div>
      {problem && <p className="text-muted-foreground">{problem}</p>}
      {child.flags.map((flag) => (
        <p key={flag} className="text-muted-foreground">
          {flagText(flag)}
        </p>
      ))}
      {open && (
        <div className="border-l pl-3">
          <RunView orgId={orgId} runId={child.id} banner={false} />
        </div>
      )}
    </li>
  );
}
