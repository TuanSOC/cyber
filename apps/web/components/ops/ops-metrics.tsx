"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { QueryError } from "@/components/query-error";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDate } from "@/lib/format";
import {
  KINDS,
  KIND_LABELS,
  type OpsWindow,
  type OrgOpsMetrics,
  PLATFORM_METRICS_NOTE,
  type RecentFailure,
  WINDOWS,
  activeTotal,
  errorClassSummary,
  errorClassText,
  errorCodeText,
  failureHref,
  failureKindLabel,
  fetchOpsMetrics,
  formatCount,
  formatDuration,
  formatRatio,
  kindLabel,
  opsKeys,
  recentFailures,
  sortedItems,
} from "@/lib/ops-metrics";

/** The window selector (24 h / 7 d). */
export function WindowSelector({ value, onChange }: { value: OpsWindow; onChange: (value: OpsWindow) => void }) {
  return (
    <div className="flex gap-1" role="group" aria-label="Time window">
      {WINDOWS.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          className={
            value === option.value
              ? "rounded-md border border-primary px-3 py-1 text-sm"
              : "rounded-md border px-3 py-1 text-sm text-muted-foreground hover:text-foreground"
          }
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/** Per analyzer numbers, as a plain table (pure). */
export function OpsMetricsTable({ metrics }: { metrics: OrgOpsMetrics }) {
  const items = sortedItems(metrics.items);
  if (items.length === 0) return <p className="text-sm text-muted-foreground">No jobs finished in this window.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Analyzer</TableHead>
          <TableHead className="text-right">Finished</TableHead>
          <TableHead className="text-right">Succeeded</TableHead>
          <TableHead className="text-right">Failed</TableHead>
          <TableHead className="text-right">Failure rate</TableHead>
          <TableHead className="text-right">Run p50 / p95</TableHead>
          <TableHead className="text-right">Queue p50 / p95</TableHead>
          <TableHead className="text-right">Parse success</TableHead>
          <TableHead>Error classes</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((item) => (
          <TableRow key={`${item.kind}:${item.subkind ?? ""}`}>
            <TableCell>{kindLabel(item)}</TableCell>
            <TableCell className="text-right tabular-nums">{formatCount(item.total)}</TableCell>
            <TableCell className="text-right tabular-nums">{formatCount(item.succeeded)}</TableCell>
            <TableCell className="text-right tabular-nums">{formatCount(item.failed)}</TableCell>
            <TableCell className="text-right tabular-nums">{formatRatio(item.failure_ratio)}</TableCell>
            <TableCell className="text-right whitespace-nowrap tabular-nums">
              {formatDuration(item.run_p50_ms)} / {formatDuration(item.run_p95_ms)}
            </TableCell>
            <TableCell className="text-right whitespace-nowrap tabular-nums">
              {formatDuration(item.queue_p50_ms)} / {formatDuration(item.queue_p95_ms)}
            </TableCell>
            <TableCell className="text-right tabular-nums">{formatRatio(item.parse_success_ratio)}</TableCell>
            <TableCell className="text-xs text-muted-foreground">{errorClassSummary(item.error_classes)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/** Queued or running now, per kind (pure). */
export function ActiveCounts({ active }: { active: OrgOpsMetrics["active"] }) {
  return (
    <p className="text-sm">
      <span className="text-muted-foreground">Queued or running now:</span> {formatCount(activeTotal(active))}
      {KINDS.filter((kind) => Object.hasOwn(active, kind) && active[kind] > 0).map((kind) => (
        <span key={kind} className="ml-3 text-muted-foreground">
          {KIND_LABELS[kind]} {formatCount(active[kind])}
        </span>
      ))}
    </p>
  );
}

/** The most recent failed analyses with their error class and a deep link (pure). */
export function RecentFailures({ orgId, failures }: { orgId: string; failures: readonly RecentFailure[] }) {
  if (failures.length === 0) return <p className="text-sm text-muted-foreground">No failed analyses.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Analysis</TableHead>
          <TableHead>Error</TableHead>
          <TableHead>Class</TableHead>
          <TableHead>Finished</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {failures.map((failure) => {
          const href = failureHref(orgId, failure);
          return (
            <TableRow key={failure.job_id}>
              <TableCell>
                {href ? (
                  <Link className="hover:underline" href={href}>
                    {failureKindLabel(failure)}
                  </Link>
                ) : (
                  failureKindLabel(failure)
                )}
              </TableCell>
              <TableCell className="font-mono text-xs">{errorCodeText(failure.error_code)}</TableCell>
              <TableCell>{errorClassText(failure.error_class)}</TableCell>
              <TableCell className="whitespace-nowrap">
                {failure.finished_at ? formatDate(failure.finished_at).local : "—"}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

/** The operations page body (`audit.read`). */
export function OperationsPanel({
  orgId,
  range,
  onRangeChange,
}: {
  orgId: string;
  range: OpsWindow;
  onRangeChange: (value: OpsWindow) => void;
}) {
  const metrics = useQuery({
    queryKey: opsKeys.metrics(orgId, range),
    queryFn: () => fetchOpsMetrics(orgId, range),
    refetchInterval: 60_000,
  });

  return (
    <div className="flex max-w-6xl flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Job metrics</CardTitle>
          <CardDescription>
            This organization&apos;s analyses, enrichments, AI runs and report renders.{" "}
            {metrics.data ? `Computed ${formatDate(metrics.data.generated_at).local}.` : null}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <WindowSelector value={range} onChange={onRangeChange} />
          {metrics.isError ? (
            <QueryError error={metrics.error} onRetry={() => void metrics.refetch()} />
          ) : metrics.data ? (
            <>
              <ActiveCounts active={metrics.data.active} />
              <OpsMetricsTable metrics={metrics.data} />
            </>
          ) : (
            <p className="text-sm text-muted-foreground">Loading metrics…</p>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Recent failures</CardTitle>
          <CardDescription>The five most recent failed analyses.</CardDescription>
        </CardHeader>
        <CardContent>
          {metrics.isError ? (
            <QueryError error={metrics.error} onRetry={() => void metrics.refetch()} />
          ) : metrics.data ? (
            <RecentFailures orgId={orgId} failures={recentFailures(metrics.data)} />
          ) : (
            <p className="text-sm text-muted-foreground">Loading failures…</p>
          )}
        </CardContent>
      </Card>
      <p className="text-xs text-muted-foreground">{PLATFORM_METRICS_NOTE}</p>
    </div>
  );
}
