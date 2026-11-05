"use client";

import { RefreshCw } from "lucide-react";
import { type ReactNode, useState } from "react";

import { AiBanner } from "@/components/ai/ai-banner";
import { AnalysisOutput, OutputNotes } from "@/components/ai/analysis-output";
import { RunFooter } from "@/components/ai/run-footer";
import { AiRunStatusBadge, RunStateNotice } from "@/components/ai/run-status";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  type AiRunDetail,
  DEDUPLICATED_TEXT,
  type OutputFlag,
  contextTruncationNotes,
  hasOutput,
  pseudonymizationText,
  taskLabel,
} from "@/lib/ai";
import { useAiRun } from "@/lib/use-ai";

/**
 * One run: banner, state (spinner / waiting / refused / failure), the truncation and
 * pseudonymization notes, the output with a "names as sent" toggle, and the footer.
 */
export function RunView({
  orgId,
  runId,
  deduplicated = false,
  onRegenerate,
  regenerating,
  variant = "job",
  extraFlags,
  header,
  banner = true,
  children,
}: {
  orgId: string;
  runId: string;
  deduplicated?: boolean;
  onRegenerate?: () => void;
  regenerating?: boolean;
  variant?: "job" | "incident";
  extraFlags?: (run: AiRunDetail) => OutputFlag[];
  header?: ReactNode;
  /** Off where the surrounding view already shows the AI banner. */
  banner?: boolean;
  /** Extra content between the output and the footer (e.g. per-job digests). */
  children?: (run: AiRunDetail) => ReactNode;
}) {
  const [keep, setKeep] = useState(false);
  const query = useAiRun(orgId, runId, keep);
  const run = query.data;

  if (query.isError) return <QueryError error={query.error} onRetry={() => void query.refetch()} />;
  if (!run) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;

  const notes = [
    ...contextTruncationNotes(run.context_stats),
    ...(pseudonymizationText(run.context_stats) ? [pseudonymizationText(run.context_stats) as string] : []),
  ];

  return (
    <div className="flex min-w-0 flex-col gap-4" data-run-id={run.id}>
      {banner && <AiBanner />}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{taskLabel(run.task)}</span>
        <AiRunStatusBadge status={run.status} />
        {header}
      </div>
      {deduplicated && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm">
          <span>{DEDUPLICATED_TEXT}</span>
          {onRegenerate && (
            <Button variant="outline" size="sm" className="ml-auto" disabled={regenerating} onClick={onRegenerate}>
              <RefreshCw className="size-3.5" aria-hidden /> Regenerate
            </Button>
          )}
        </div>
      )}
      <RunStateNotice run={run} />
      {run.output_withheld && (
        <p className="rounded-md border border-destructive/40 px-3 py-2 text-sm" role="alert">
          Output withheld: the answer echoed a hidden request marker, a sign of prompt injection in the evidence.
        </p>
      )}
      <OutputNotes notes={notes} />
      {hasOutput(run.status) && run.output && (
        <>
          <div className="flex items-center gap-2 text-xs">
            <input
              id={`keep-${run.id}`}
              type="checkbox"
              checked={keep}
              onChange={(event) => setKeep(event.target.checked)}
            />
            <Label htmlFor={`keep-${run.id}`} className="text-xs font-normal">
              Show internal names as pseudonyms (as sent to the provider)
            </Label>
          </div>
          <AnalysisOutput
            orgId={orgId}
            output={run.output}
            variant={variant}
            extraFlags={extraFlags ? extraFlags(run) : []}
          />
        </>
      )}
      {children?.(run)}
      <RunFooter orgId={orgId} run={run} />
    </div>
  );
}
