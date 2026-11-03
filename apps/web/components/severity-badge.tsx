import { cn } from "@/lib/utils";

export type Severity = "low" | "medium" | "high" | "critical";

const STYLES: Record<Severity, string> = {
  low: "border-sev-low/40 bg-sev-low/15 text-sev-low",
  medium: "border-sev-medium/40 bg-sev-medium/15 text-sev-medium",
  high: "border-sev-high/40 bg-sev-high/15 text-sev-high",
  critical: "border-sev-critical/50 bg-sev-critical/20 text-sev-critical",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        STYLES[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}
