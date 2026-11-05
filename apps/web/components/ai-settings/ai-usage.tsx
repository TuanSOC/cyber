"use client";

import { type AiProvider, type AiUsage, formatCostMicros, formatTokens, usedPercent } from "@/lib/ai-settings";

/** Today's (UTC) tokens and estimated cost per provider, against the daily budget. */
export function AiUsageView({ usage, providers = [] }: { usage: AiUsage; providers?: readonly AiProvider[] }) {
  const percent = usedPercent(usage.total_tokens, usage.daily_token_budget);
  const label = (name: string) => providers.find((p) => p.name === name)?.label ?? name;
  return (
    <div className="flex flex-col gap-3 text-sm" data-testid="ai-usage">
      <div className="flex flex-col gap-1">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <span>
            <span className="font-medium">{formatTokens(usage.total_tokens)}</span> of{" "}
            {formatTokens(usage.daily_token_budget)} tokens used today ({usage.day}, UTC)
          </span>
          <span className="text-muted-foreground">{formatTokens(usage.remaining_tokens)} left</span>
        </div>
        <div
          className="h-2 w-full overflow-hidden rounded-full bg-muted"
          role="meter"
          aria-label="Daily token budget used"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent}
        >
          <div className="h-full bg-primary" style={{ width: `${percent}%` }} />
        </div>
      </div>
      {usage.providers.length === 0 ? (
        <p className="text-muted-foreground">No analysis has run today.</p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted-foreground">
            <tr>
              <th className="py-1 font-normal">Provider</th>
              <th className="py-1 text-right font-normal">Runs</th>
              <th className="py-1 text-right font-normal">Tokens</th>
              <th className="py-1 text-right font-normal">Est. cost</th>
            </tr>
          </thead>
          <tbody>
            {usage.providers.map((row) => (
              <tr key={row.provider} className="border-t">
                <td className="py-1">{label(row.provider)}</td>
                <td className="py-1 text-right tabular-nums">{formatTokens(row.runs)}</td>
                <td className="py-1 text-right tabular-nums">{formatTokens(row.usage.total_tokens)}</td>
                <td className="py-1 text-right tabular-nums">{formatCostMicros(row.cost_micros)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="text-xs text-muted-foreground">
        Total {formatCostMicros(usage.cost_micros)} today. Costs are estimates from the price table; the provider&apos;s
        invoice is authoritative.
      </p>
    </div>
  );
}
