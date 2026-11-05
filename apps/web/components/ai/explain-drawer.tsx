"use client";

import { Sparkles } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { AiOffNotice, NoRunPermissionNote, useAiAccess } from "@/components/ai/ai-access";
import { AiBanner } from "@/components/ai/ai-banner";
import { ContextPreviewDialog, aiErrorMessage } from "@/components/ai/context-preview-dialog";
import { RunView } from "@/components/ai/run-view";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { type AiRunCreate, type AiTask, isActiveAiRun } from "@/lib/ai";
import { useAiRuns, useAiSettings, useCreateAiRun } from "@/lib/use-ai";

/**
 * Row action "Explain": a drawer with the AI explanation of one finding or alert. It reuses
 * the newest completed (or still active) run for the row and only offers to start one when
 * there is none.
 */
export function ExplainButton({
  orgId,
  jobId,
  target,
  targetId,
  title,
}: {
  orgId: string;
  jobId: string;
  target: "finding" | "alert";
  targetId: string;
  /** Row title (analyzer text, shown as plain text in the drawer header). */
  title: string;
}) {
  const [open, setOpen] = useState(false);
  const settings = useAiSettings(orgId);
  // Nothing to explain with and nothing to read: keep the rows uncluttered when AI is off.
  if (settings.data && !settings.data.ai_enabled) return null;
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 gap-1 px-1.5 text-xs" title={`Explain this ${target} with AI`}>
          <Sparkles className="size-3.5" aria-hidden />
          Explain
        </Button>
      </SheetTrigger>
      <SheetContent className="w-full overflow-y-auto data-[side=right]:sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>Explain {target}</SheetTitle>
          <SheetDescription className="truncate" title={title}>
            {title}
          </SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">
          {open && <ExplainBody orgId={orgId} jobId={jobId} task={target === "finding" ? "explain_finding" : "explain_alert"} targetId={targetId} />}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function ExplainBody({ orgId, jobId, task, targetId }: { orgId: string; jobId: string; task: AiTask; targetId: string }) {
  const access = useAiAccess(orgId);
  const runs = useAiRuns(orgId, { job_id: jobId, task, target_id: targetId, limit: 10 });
  const create = useCreateAiRun(orgId);
  const [created, setCreated] = useState<{ id: string; deduplicated: boolean; request: AiRunCreate } | null>(null);
  const existing =
    runs.data?.items.find((run) => run.status === "completed") ??
    runs.data?.items.find((run) => isActiveAiRun(run.status)) ??
    runs.data?.items[0];
  const runId = created?.id ?? existing?.id ?? null;
  const request: AiRunCreate = { task, job_id: jobId, target_id: targetId };

  const start = (body: AiRunCreate) =>
    create.mutate(body, {
      onSuccess: (result) => setCreated({ id: result.run.id, deduplicated: result.deduplicated, request: body }),
      onError: (error) => toast.error(aiErrorMessage(error)),
    });

  const controls =
    access.enabled === undefined ? null : !access.enabled ? (
      <AiOffNotice orgId={orgId} canManage={access.canManage} platformOff={access.platformOff} />
    ) : !access.canRun ? (
      <NoRunPermissionNote />
    ) : (
      <ContextPreviewDialog
        orgId={orgId}
        request={request}
        canManage={access.canManage}
        pending={create.isPending}
        onRun={() => start(runId ? { ...request, regenerate: true } : request)}
      >
        {runId ? "Run a new explanation" : "Explain with AI"}
      </ContextPreviewDialog>
    );

  if (runs.isError) return <QueryError error={runs.error} onRetry={() => void runs.refetch()} />;
  if (!runs.data) return <p className="text-sm text-muted-foreground">Loading…</p>;
  return (
    <div className="flex flex-col gap-4">
      <AiBanner />
      {runId ? (
        <RunView
          key={runId}
          orgId={orgId}
          runId={runId}
          banner={false}
          deduplicated={created?.id === runId && created.deduplicated}
          regenerating={create.isPending}
          onRegenerate={created && access.canRun ? () => start({ ...created.request, regenerate: true }) : undefined}
        />
      ) : (
        <p className="text-sm text-muted-foreground">No AI explanation of this row yet.</p>
      )}
      {controls}
    </div>
  );
}
