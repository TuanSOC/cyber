"use client";

import { Ban, CheckCircle2, CircleDashed, Clock, Loader2, PauseCircle, XCircle } from "lucide-react";

import {
  AI_STATUS_LABELS,
  type AiRun,
  type AiRunStatus,
  isActiveAiRun,
  runDurationText,
  runStateView,
} from "@/lib/ai";
import { formatDate } from "@/lib/format";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";

const ICONS: Record<AiRunStatus, { icon: typeof Clock; spin?: boolean }> = {
  queued: { icon: Clock },
  running: { icon: Loader2, spin: true },
  waiting: { icon: PauseCircle },
  completed: { icon: CheckCircle2 },
  partial: { icon: CircleDashed },
  failed: { icon: XCircle },
  refused: { icon: Ban },
};

export function AiRunStatusBadge({ status }: { status: AiRunStatus }) {
  const style = ICONS[status] ?? ICONS.queued;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        status === "failed" ? "border-destructive/40 text-destructive" : "border-border",
      )}
    >
      <style.icon className={cn("size-3", style.spin && "animate-spin motion-reduce:animate-none")} aria-hidden />
      {AI_STATUS_LABELS[status] ?? status}
    </span>
  );
}

/** Spinner with elapsed time, rate-limit wait, refusal or the mapped failure message. */
export function RunStateNotice({
  run,
}: {
  run: Pick<AiRun, "status" | "error_code" | "refusal_category" | "resume_at" | "created_at" | "started_at" | "finished_at">;
}) {
  const active = isActiveAiRun(run.status);
  const now = useNow(active);
  const view = runStateView(run, (iso) => formatDate(iso).local);
  if (!view) return null;
  return (
    <div
      className={cn(
        "flex flex-col gap-0.5 rounded-md border px-3 py-2 text-sm",
        view.tone === "error" && "border-destructive/40",
      )}
      role={view.tone === "error" ? "alert" : "status"}
    >
      <span className="flex items-center gap-2">
        {active && <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden />}
        <span className={cn("font-medium", view.tone === "error" && "text-destructive")}>{view.title}</span>
        {active && <span className="text-xs text-muted-foreground tabular-nums">{runDurationText(run, now)}</span>}
      </span>
      {view.detail && <span className="text-xs text-muted-foreground">{view.detail}</span>}
    </div>
  );
}
