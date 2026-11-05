"use client";

import { useState } from "react";
import { toast } from "sonner";

import { AiOffNotice, NoRunPermissionNote, type ProviderChoice, ProviderOverride, useAiAccess } from "@/components/ai/ai-access";
import { AiBanner } from "@/components/ai/ai-banner";
import { ContextPreviewDialog, aiErrorMessage } from "@/components/ai/context-preview-dialog";
import { RunHistory } from "@/components/ai/run-history";
import { RunView } from "@/components/ai/run-view";
import { QueryError } from "@/components/query-error";
import { type AiRunCreate, type AiTask, JOB_TASKS, TASK_LABELS } from "@/lib/ai";
import type { AnalysisJob } from "@/lib/analysis";
import { useAiRuns, useCreateAiRun } from "@/lib/use-ai";

const HISTORY = 50;

/**
 * "AI Analyst" tab of a PCAP or static job: task buttons (each previews what will be sent
 * first), the selected run's output and the job's previous runs.
 */
export function AiAnalystTab({ orgId, job }: { orgId: string; job: AnalysisJob }) {
  const variant = job.analyzer === "static" ? "static" : "pcap";
  const access = useAiAccess(orgId);
  const [choice, setChoice] = useState<ProviderChoice>({});
  const [selected, setSelected] = useState<{ id: string; deduplicated: boolean; request?: AiRunCreate } | null>(null);
  const runs = useAiRuns(orgId, { job_id: job.id, limit: HISTORY });
  const create = useCreateAiRun(orgId);
  const items = runs.data?.items ?? [];
  // Job-level runs only; explanations of single rows live in their row drawers (still listed).
  const shownId = selected?.id ?? items.find((run) => !run.target_id)?.id ?? items[0]?.id ?? null;

  const request = (task: AiTask, regenerate = false): AiRunCreate => ({
    task,
    job_id: job.id,
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
    <div className="flex min-w-0 flex-col gap-4">
      <AiBanner />
      {access.settings.isError ? (
        <QueryError error={access.settings.error} onRetry={() => void access.settings.refetch()} />
      ) : access.enabled === undefined ? (
        <p className="text-sm text-muted-foreground">Loading AI settings…</p>
      ) : !access.enabled ? (
        <AiOffNotice orgId={orgId} canManage={access.canManage} platformOff={access.platformOff} />
      ) : !access.canRun ? (
        <NoRunPermissionNote />
      ) : (
        <div className="flex flex-col gap-2 rounded-md border p-3">
          <div className="flex flex-wrap gap-2">
            {JOB_TASKS[variant].map((task) => (
              <ContextPreviewDialog
                key={task}
                orgId={orgId}
                request={request(task)}
                canManage={access.canManage}
                pending={create.isPending}
                onRun={() => start(request(task))}
              >
                {TASK_LABELS[task]}
              </ContextPreviewDialog>
            ))}
          </div>
          <ProviderOverride
            orgId={orgId}
            value={choice}
            onChange={setChoice}
            defaultProvider={access.settings.data?.default_provider}
          />
          <p className="text-[11px] text-muted-foreground">
            Each task first shows what will be sent to the provider. Nothing is sent until you confirm.
          </p>
        </div>
      )}
      {runs.isError && <QueryError error={runs.error} onRetry={() => void runs.refetch()} />}
      {runs.isSuccess && items.length === 0 && !selected && (
        <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">No AI analysis of this job yet.</p>
      )}
      {shownId && (
        <RunView
          key={shownId}
          orgId={orgId}
          runId={shownId}
          banner={false}
          deduplicated={selected?.id === shownId && selected.deduplicated}
          regenerating={create.isPending}
          onRegenerate={
            selected?.request && access.canRun && access.enabled
              ? () => start({ ...selected.request!, regenerate: true })
              : undefined
          }
        />
      )}
      <RunHistory runs={items} selected={shownId} onSelect={(id) => setSelected({ id, deduplicated: false })} />
    </div>
  );
}
