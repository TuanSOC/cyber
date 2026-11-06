import { Badge } from "@/components/ui/badge";
import { formatDuration } from "@/lib/analysis";
import { formatCount } from "@/lib/pcap-results";
import { type MemorySummary, PLUGIN_STATE_LABELS, completeness } from "@/lib/memory";
import { cn } from "@/lib/utils";

const STATE_STYLE: Record<string, string> = {
  ok: "border-border",
  failed: "border-destructive/50 text-destructive",
  timeout: "border-destructive/50 text-destructive",
  skipped: "border-amber-500/60",
  unsupported: "border-amber-500/60",
};

/**
 * Every plugin of the run with its outcome and `truncated` marker, so a partial result is never
 * shown as complete. Plugin names are allow-listed identifiers from the contract, shown as text.
 */
export function PluginStrip({ summary }: { summary: Pick<MemorySummary, "plugins" | "truncated"> }) {
  const state = completeness(summary);
  return (
    <div className="flex flex-col gap-2" data-testid="plugin-strip">
      <p className={cn("text-sm", state.complete ? "text-muted-foreground" : "font-medium text-amber-700 dark:text-amber-400")}>
        {state.complete
          ? "Every analysis step finished; no result was cut at a limit."
          : summary.plugins.length === 0
            ? "No analysis step ran."
            : `Partial result: ${[
                state.incomplete.length > 0 ? `${state.incomplete.length} step(s) did not finish` : null,
                state.truncatedPlugins.length > 0 ? `${state.truncatedPlugins.length} step(s) were cut at a row limit` : null,
                state.truncatedKinds.length > 0 ? `stored ${state.truncatedKinds.join(", ")} were cut at a limit` : null,
              ]
                .filter(Boolean)
                .join("; ")}. Missing rows are not evidence of absence.`}
      </p>
      <ul className="flex flex-wrap gap-1.5" aria-label="Analysis steps">
        {summary.plugins.map((p) => (
          <li key={p.plugin}>
            <Badge
              variant="outline"
              className={cn("gap-1 font-mono text-[11px] font-normal", STATE_STYLE[p.status])}
              title={`${PLUGIN_STATE_LABELS[p.status] ?? p.status} · ${formatCount(p.rows)} rows · ${formatDuration(p.duration_ms)}${p.error_code ? ` · ${p.error_code}` : ""}`}
            >
              <span>{p.plugin}</span>
              <span className="font-sans">{PLUGIN_STATE_LABELS[p.status] ?? p.status}</span>
              {p.truncated ? <span className="font-sans font-medium">· truncated</span> : null}
            </Badge>
          </li>
        ))}
      </ul>
    </div>
  );
}
