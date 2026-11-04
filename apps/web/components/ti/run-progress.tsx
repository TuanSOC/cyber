"use client";

import { CheckCircle2, Clock, Loader2, PauseCircle, XCircle } from "lucide-react";

import { When } from "@/components/analysis/result-parts";
import {
  RUN_STATUS_LABELS,
  type RunStatus,
  type TiRun,
  isActiveRun,
  itemReasonText,
  providerLabel,
  runItemTotal,
  runOutcomeNotes,
  runProviderRows,
  runSkipped,
  skipReasonText,
  waitingText,
} from "@/lib/ti";
import { useRunDetail } from "@/lib/use-ti";
import { cn } from "@/lib/utils";

const ICONS: Record<RunStatus, { icon: typeof Clock; spin?: boolean }> = {
  queued: { icon: Clock },
  running: { icon: Loader2, spin: true },
  waiting: { icon: PauseCircle },
  completed: { icon: CheckCircle2 },
  partial: { icon: CheckCircle2 },
  failed: { icon: XCircle },
};

export function RunStatusBadge({ status }: { status: RunStatus }) {
  const style = ICONS[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        status === "failed" ? "border-destructive/40 text-destructive" : "border-border",
      )}
    >
      <style.icon className={cn("size-3", style.spin && "animate-spin motion-reduce:animate-none")} aria-hidden />
      {RUN_STATUS_LABELS[status]}
    </span>
  );
}

/**
 * Progress strip of one enrichment run: status, lookups done / planned, per-provider counts,
 * "waiting for rate limit until hh:mm" and, once final, why a run is partial.
 */
export function RunProgress({ orgId, run }: { orgId: string; run: TiRun }) {
  const active = isActiveRun(run.status);
  // Pending items (one-row page: only `total` is used) while the run is active.
  const pending = useRunDetail(orgId, active ? run.id : null, { state: "pending", limit: 1 });
  const total = runItemTotal(run.summary);
  const remaining = active ? pending.data?.items.total : 0;
  const done = remaining === undefined ? null : Math.max(0, total - remaining);
  const rows = runProviderRows(run.summary);
  const skipped = runSkipped(run.summary);
  const notes = runOutcomeNotes(run);
  const waiting = waitingText(run);

  return (
    <div className="flex flex-col gap-2 rounded-lg border p-3 text-sm" aria-live="polite">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <RunStatusBadge status={run.status} />
        <span className="tabular-nums">
          {done === null ? `${total} lookups planned` : `${done} of ${total} lookups done`}
        </span>
        {waiting && <span className="text-muted-foreground">{waiting}</span>}
        <span className="text-xs text-muted-foreground">
          requested by {run.requested_by_name} · <When iso={run.created_at} />
        </span>
      </div>
      {total > 0 && done !== null && (
        <div
          className="h-1.5 overflow-hidden rounded bg-muted"
          role="progressbar"
          aria-label="Lookups done"
          aria-valuenow={done}
          aria-valuemin={0}
          aria-valuemax={total}
        >
          <div className="h-full bg-primary transition-all" style={{ width: `${(done / total) * 100}%` }} />
        </div>
      )}
      {rows.length > 0 && (
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          {rows.map((row) => (
            <li key={row.provider}>
              <span className="font-medium text-foreground">{providerLabel(row.provider)}</span>{" "}
              {active
                ? `${row.planned} planned`
                : [
                    `${row.answered} answered`,
                    row.notFound ? `${row.notFound} no record` : null,
                    row.cached ? `${row.cached} from cache` : null,
                    row.errors ? `${row.errors} errors` : null,
                    row.authFailed ? `${row.authFailed} key rejected` : null,
                    ...row.abandoned.map((a) => `${a.count} ${itemReasonText(a.reason) ?? a.reason}`),
                  ]
                    .filter(Boolean)
                    .join(" · ")}
            </li>
          ))}
        </ul>
      )}
      {skipped.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Not sent to any provider:{" "}
          {skipped.map((s) => `${s.count} ${skipReasonText(s.reason)?.replace(/ — not sent$/, "") ?? s.reason}`).join(", ")}
        </p>
      )}
      {notes.length > 0 && (
        <ul className="list-disc pl-5 text-xs text-muted-foreground">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
