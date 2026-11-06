"use client";

import { Sparkles } from "lucide-react";
import { useState } from "react";

import { AiOffNotice, NoRunPermissionNote, useAiAccess } from "@/components/ai/ai-access";
import { AiBanner } from "@/components/ai/ai-banner";
import { ContextPreviewDialog, aiErrorMessage } from "@/components/ai/context-preview-dialog";
import { PolicyBlocked } from "@/components/ai/policy-blocked";
import { RunView } from "@/components/ai/run-view";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { type AiRunCreate, isActiveAiRun } from "@/lib/ai";
import { isPolicyBlocked } from "@/lib/case";
import { inertText } from "@/lib/disk";
import { useAiRuns, useAiSettings, useCreateAiRun } from "@/lib/use-ai";

/**
 * "Explain function" (M10 phase 10 fills the phase-1 slot; used inside the RE pages only): the
 * `explain_function` AI run of phase 9 over one `re_functions` row (its facts, its decompiled
 * code capped and transformed by the API, its capabilities, findings and callees). Reuses the
 * newest run of the function; a run refused by the case / evidence share policy shows the M6
 * reason instead of an output. Hidden while AI is off for the org.
 */
export function ExplainFunctionButton({
  orgId,
  jobId,
  functionId,
  name,
}: {
  orgId: string;
  jobId: string;
  functionId: string;
  /** The function name (attacker-influenced, shown as inert text). */
  name?: string;
}) {
  const [open, setOpen] = useState(false);
  const settings = useAiSettings(orgId);
  if (settings.data && !settings.data.ai_enabled) return null;
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1" title="Explain this function with AI (facts and decompiled code)">
          <Sparkles className="size-3.5" aria-hidden />
          Explain function
        </Button>
      </SheetTrigger>
      <SheetContent className="w-full overflow-y-auto data-[side=right]:sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>Explain function</SheetTitle>
          <SheetDescription className="truncate font-mono" title={inertText(name ?? "")}>
            {inertText(name ?? "", 200)}
          </SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">{open && <ExplainFunctionBody orgId={orgId} jobId={jobId} functionId={functionId} />}</div>
      </SheetContent>
    </Sheet>
  );
}

function ExplainFunctionBody({ orgId, jobId, functionId }: { orgId: string; jobId: string; functionId: string }) {
  const access = useAiAccess(orgId);
  const runs = useAiRuns(orgId, { job_id: jobId, task: "explain_function", target_id: functionId, limit: 10 });
  const create = useCreateAiRun(orgId);
  const [created, setCreated] = useState<{ id: string; deduplicated: boolean; request: AiRunCreate } | null>(null);
  const existing =
    runs.data?.items.find((run) => run.status === "completed") ??
    runs.data?.items.find((run) => isActiveAiRun(run.status)) ??
    runs.data?.items[0];
  const runId = created?.id ?? existing?.id ?? null;
  const request: AiRunCreate = { task: "explain_function", job_id: jobId, target_id: functionId };
  const start = (body: AiRunCreate) =>
    create.mutate(body, {
      onSuccess: (result) => setCreated({ id: result.run.id, deduplicated: result.deduplicated, request: body }),
    });

  if (runs.isError) return <QueryError error={runs.error} onRetry={() => void runs.refetch()} />;
  if (!runs.data) return <p className="text-sm text-muted-foreground">Loading…</p>;
  const blocked = create.isError && isPolicyBlocked(create.error);
  return (
    <div className="flex flex-col gap-4">
      <AiBanner />
      <p className="text-xs text-muted-foreground">
        The AI receives this function&apos;s facts and its decompiled code (capped, with internal names replaced) and must cite
        them. Decompiled code is untrusted data from the binary: the explanation is an interpretation to verify, never a
        verdict.
      </p>
      {blocked ? (
        <PolicyBlocked orgId={orgId} error={create.error} jobId={jobId} what="Explaining this function" />
      ) : create.isError ? (
        <p role="alert" className="text-sm text-destructive">
          {aiErrorMessage(create.error)}
        </p>
      ) : null}
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
        <p className="text-sm text-muted-foreground">No AI explanation of this function yet.</p>
      )}
      {access.enabled === undefined ? null : !access.enabled ? (
        <AiOffNotice orgId={orgId} canManage={access.canManage} platformOff={access.platformOff} />
      ) : !access.canRun ? (
        <NoRunPermissionNote />
      ) : blocked ? null : (
        <ContextPreviewDialog
          orgId={orgId}
          request={request}
          canManage={access.canManage}
          pending={create.isPending}
          onRun={() => start(runId ? { ...request, regenerate: true } : request)}
        >
          {runId ? "Run a new explanation" : "Explain with AI"}
        </ContextPreviewDialog>
      )}
    </div>
  );
}
