import { CheckCircle2, Clock, Loader2, XCircle } from "lucide-react";

import { ANALYSIS_STATUS_LABELS, type AnalysisStatus } from "@/lib/analysis";
import { cn } from "@/lib/utils";

const STYLES: Record<AnalysisStatus, { className: string; icon: typeof Clock; spin?: boolean }> = {
  queued: { className: "border-border text-muted-foreground", icon: Clock },
  running: { className: "border-primary/40 bg-primary/10 text-primary", icon: Loader2, spin: true },
  succeeded: { className: "border-sev-low/40 bg-sev-low/15 text-sev-low", icon: CheckCircle2 },
  failed: { className: "border-destructive/40 bg-destructive/15 text-destructive", icon: XCircle },
};

export function AnalysisStatusBadge({ status, className }: { status: AnalysisStatus; className?: string }) {
  const style = STYLES[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        style.className,
        className,
      )}
    >
      <style.icon className={cn("size-3", style.spin && "animate-spin motion-reduce:animate-none")} aria-hidden />
      {ANALYSIS_STATUS_LABELS[status]}
    </span>
  );
}
