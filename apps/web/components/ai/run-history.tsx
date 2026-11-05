"use client";

import { When } from "@/components/analysis/result-parts";
import { AiRunStatusBadge } from "@/components/ai/run-status";
import { Button } from "@/components/ui/button";
import { type AiRun, formatAccuracy, supersededIds, taskLabel } from "@/lib/ai";
import { cn } from "@/lib/utils";

/** Previous runs (newest first) with a superseded marker; "Show" selects one. */
export function RunHistory({
  runs,
  selected,
  onSelect,
}: {
  runs: readonly AiRun[];
  selected: string | null;
  onSelect: (runId: string) => void;
}) {
  if (runs.length === 0) return null;
  const superseded = supersededIds(runs);
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">Previous runs ({runs.length})</h3>
      <ul className="flex flex-col divide-y rounded-md border">
        {runs.map((run) => (
          <li
            key={run.id}
            className={cn("flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5 text-xs", run.id === selected && "bg-muted/50")}
          >
            <span className="font-medium">{taskLabel(run.task)}</span>
            <AiRunStatusBadge status={run.status} />
            {superseded.has(run.id) && <span className="text-muted-foreground">superseded</span>}
            <span className="text-muted-foreground">
              {run.provider} · {run.model}
            </span>
            <span className="text-muted-foreground">citations checked {formatAccuracy(run.citation_accuracy)}</span>
            <When iso={run.created_at} />
            <Button
              variant="ghost"
              size="sm"
              className="ml-auto h-6 px-2 text-xs"
              disabled={run.id === selected}
              onClick={() => onSelect(run.id)}
            >
              {run.id === selected ? "Shown" : "Show"}
            </Button>
          </li>
        ))}
      </ul>
    </section>
  );
}
