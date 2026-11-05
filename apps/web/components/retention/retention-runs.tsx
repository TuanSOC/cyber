"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { errorMessage } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { apiErrorText } from "@/lib/http-errors";
import { orgPath } from "@/lib/nav";
import {
  MODE_LABELS,
  RUN_STATUS_LABELS,
  TRIGGER_LABELS,
  type RetentionRun,
  countTotals,
  fetchRuns,
  formatDayTime,
  isActiveRun,
  retentionKeys,
  startDryRun,
} from "@/lib/retention";

const RUNS_PAGE = 20;

export function runHref(orgId: string, runId: string): string {
  return orgPath(orgId, `settings/retention/runs/${encodeURIComponent(runId)}`);
}

export function RunStatusBadge({ status }: { status: RetentionRun["status"] }) {
  const variant = status === "failed" ? "destructive" : status === "completed" ? "secondary" : "outline";
  return <Badge variant={variant}>{RUN_STATUS_LABELS[status]}</Badge>;
}

/** The runs table (pure). */
export function RunsTable({ orgId, runs }: { orgId: string; runs: readonly RetentionRun[] }) {
  if (runs.length === 0) {
    return <p className="text-sm text-muted-foreground">No retention runs yet. Scheduled runs start daily at 02:30 UTC.</p>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Mode</TableHead>
          <TableHead>Trigger</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Candidates</TableHead>
          <TableHead className="text-right">Bytes</TableHead>
          <TableHead>Started</TableHead>
          <TableHead>Finished</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {runs.map((run) => {
          const total = countTotals(run.counts);
          return (
            <TableRow key={run.id}>
              <TableCell>
                <Link className="hover:underline" href={runHref(orgId, run.id)}>
                  {MODE_LABELS[run.mode]}
                </Link>
              </TableCell>
              <TableCell>{TRIGGER_LABELS[run.trigger]}</TableCell>
              <TableCell>
                <RunStatusBadge status={run.status} />
                {run.error ? <span className="ml-2 font-mono text-xs text-muted-foreground">{run.error.slice(0, 64)}</span> : null}
              </TableCell>
              <TableCell className="text-right tabular-nums">{total.candidates.toLocaleString("en-US")}</TableCell>
              <TableCell className="text-right tabular-nums">{formatBytes(total.bytes)}</TableCell>
              <TableCell className="whitespace-nowrap">{run.started_at ? formatDayTime(run.started_at) : "—"}</TableCell>
              <TableCell className="whitespace-nowrap">{run.finished_at ? formatDayTime(run.finished_at) : "—"}</TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

/** Retention runs (`audit.read`), with a manual dry run for `org.update`. */
export function RetentionRunsCard({ orgId, canStart }: { orgId: string; canStart: boolean }) {
  const queryClient = useQueryClient();
  const [offset, setOffset] = useState(0);
  const runs = useQuery({
    queryKey: [...retentionKeys.runs(orgId), offset],
    queryFn: () => fetchRuns(orgId, RUNS_PAGE, offset),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => (query.state.data?.items.some(isActiveRun) ? 5_000 : false),
  });
  const start = useMutation({
    mutationFn: () => startDryRun(orgId),
    onSuccess: async () => {
      setOffset(0);
      await queryClient.invalidateQueries({ queryKey: retentionKeys.runs(orgId) });
      toast.success("Dry run queued");
    },
    onError: (error) => toast.error(apiErrorText(error) ?? errorMessage(error)),
  });
  const busy = runs.data?.items.some(isActiveRun) ?? false;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Runs</CardTitle>
        <CardDescription>
          Every run records what it selected and what it did. A dry run deletes nothing.
        </CardDescription>
        {canStart && (
          <CardAction>
            <Button size="sm" variant="outline" disabled={start.isPending || busy} onClick={() => start.mutate()}>
              <Play className="size-4" aria-hidden /> Start a dry run
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {runs.isError ? (
          <QueryError error={runs.error} onRetry={() => void runs.refetch()} />
        ) : runs.data ? (
          <RunsTable orgId={orgId} runs={runs.data.items} />
        ) : (
          <p className="text-sm text-muted-foreground">Loading runs…</p>
        )}
        <Pager offset={offset} total={runs.data?.total ?? 0} pageSize={RUNS_PAGE} onChange={setOffset} />
      </CardContent>
    </Card>
  );
}
