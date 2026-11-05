"use client";

import { ContextSummary } from "@/components/ai/context-summary";
import { ContextViewer } from "@/components/ai/context-viewer";
import { type AiRunDetail, formatCost, formatTokens, isActiveAiRun, runDurationText, shortSha } from "@/lib/ai";
import { useNow } from "@/lib/use-now";

/** Provenance of one run: provider, models, prompt version, tokens, cost, context hash, time. */
export function RunFooter({ orgId, run }: { orgId: string; run: AiRunDetail }) {
  const now = useNow(isActiveAiRun(run.status));
  const served = run.served_model && run.served_model !== run.model ? run.served_model : null;
  const facts: [string, string, string?][] = [
    ["Provider", run.provider],
    ["Model", run.model],
    ...(served ? ([["Served model", served]] as [string, string][]) : []),
    ["Prompt version", run.prompt_version],
    [
      "Tokens",
      `${formatTokens(run.usage.total_tokens)} (in ${formatTokens(run.usage.input_tokens)}, out ${formatTokens(run.usage.output_tokens)})`,
    ],
    ["Cost", `${formatCost(run.cost_micros)}${run.cost_estimated ? " (estimated)" : ""}`],
    ["Context", shortSha(run.context_sha256), run.context_sha256],
    ["Run time", runDurationText(run, now)],
    ["Requested by", run.requested_by_name],
  ];
  return (
    <footer className="flex flex-col gap-3 border-t pt-3 text-xs">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 sm:grid-cols-[auto_1fr_auto_1fr]">
        {facts.map(([label, value, title]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="min-w-0 truncate font-mono" title={title ?? value}>
              {value}
            </dd>
          </div>
        ))}
      </dl>
      <details>
        <summary className="cursor-pointer text-muted-foreground">Context sent: counts, truncation, pseudonyms</summary>
        <div className="mt-2">
          <ContextSummary orgId={orgId} stats={run.context_stats} />
        </div>
      </details>
      <ContextViewer orgId={orgId} runId={run.id} />
    </footer>
  );
}
