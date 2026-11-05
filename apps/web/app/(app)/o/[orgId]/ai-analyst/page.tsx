"use client";

import { useQueries } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { AiBanner } from "@/components/ai/ai-banner";
import { AiRunStatusBadge } from "@/components/ai/run-status";
import { ALL, FilterSelect, When } from "@/components/analysis/result-parts";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AI_RUN_STATUSES,
  AI_STATUS_LABELS,
  type AiRun,
  type AiRunStatus,
  type AiTask,
  type JobRoute,
  LISTED_TASKS,
  formatAccuracy,
  formatCost,
  formatTokens,
  routeForTask,
  runTargetHref,
  runTargetText,
  taskLabel,
} from "@/lib/ai";
import { api, unwrap } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useAiRuns } from "@/lib/use-ai";

const COLUMNS = 10;
const TASK_OPTIONS = LISTED_TASKS.map((task) => [task, taskLabel(task)] as const);
const STATUS_OPTIONS = AI_RUN_STATUSES.map((status) => [status, AI_STATUS_LABELS[status]] as const);

/** The org's AI runs (top level), newest first, with task / status filters. */
export default function AiRunsPage() {
  const { orgId } = useOrg();
  const [task, setTask] = useState<AiTask | typeof ALL>(ALL);
  const [status, setStatus] = useState<AiRunStatus | typeof ALL>(ALL);
  const [page, setPage] = useState({ key: "", offset: 0 });
  const filterKey = `${task}:${status}`;
  const offset = page.key === filterKey ? page.offset : 0;
  const runs = useAiRuns(orgId, {
    task: task === ALL ? undefined : task,
    status: status === ALL ? undefined : status,
    limit: PAGE_SIZE,
    offset,
  });
  const items = runs.data?.items;
  const routes = useJobRoutes(orgId, items ?? []);

  return (
    <>
      <PageHeader
        title="AI Analyst"
        description="Evidence-cited explanations, timelines and recommendations, and how well their citations checked out."
      />
      <div className="flex flex-col gap-3">
        <AiBanner />
        <div className="flex flex-wrap gap-2">
          <FilterSelect
            value={task}
            onChange={setTask}
            options={TASK_OPTIONS}
            allLabel="All tasks"
            label="Task filter"
            className="w-52"
          />
          <FilterSelect
            value={status}
            onChange={setStatus}
            options={STATUS_OPTIONS}
            allLabel="All statuses"
            label="Status filter"
            className="w-40"
          />
        </div>
        {runs.isError && <QueryError error={runs.error} onRetry={() => void runs.refetch()} />}
        <div className="min-w-0 rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Task</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Provider / model</TableHead>
                <TableHead className="w-28">Status</TableHead>
                <TableHead className="w-24 text-right" title="Verified citations / all citations">
                  Citations checked
                </TableHead>
                <TableHead className="w-24 text-right">Hidden statements</TableHead>
                <TableHead className="w-24 text-right">Tokens</TableHead>
                <TableHead className="w-24 text-right">Cost</TableHead>
                <TableHead>Requested by</TableHead>
                <TableHead className="w-40">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.isPending && (
                <TableRow>
                  <TableCell colSpan={COLUMNS} className="py-8 text-center text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              )}
              {items?.length === 0 && (
                <TableRow>
                  <TableCell colSpan={COLUMNS} className="py-10 text-center whitespace-normal text-muted-foreground">
                    {task !== ALL || status !== ALL ? "No AI runs match these filters." : "No AI runs yet."}
                  </TableCell>
                </TableRow>
              )}
              {items?.map((run) => (
                <RunRow key={run.id} orgId={orgId} run={run} route={run.job_id ? routes.get(run.job_id) ?? null : null} />
              ))}
            </TableBody>
          </Table>
        </div>
        <Pager offset={offset} total={runs.data?.total ?? 0} onChange={(next) => setPage({ key: filterKey, offset: next })} />
      </div>
    </>
  );
}

function RunRow({ orgId, run, route }: { orgId: string; run: AiRun; route: JobRoute | null }) {
  const target = runTargetHref(orgId, run, route);
  return (
    <TableRow>
      <TableCell>
        <Link href={orgPath(orgId, `ai-analyst/${run.id}`)} className="font-medium text-primary underline-offset-4 hover:underline">
          {taskLabel(run.task)}
        </Link>
      </TableCell>
      <TableCell>
        {target ? (
          <Link href={target} className="underline-offset-4 hover:underline">
            {runTargetText(run)}
          </Link>
        ) : (
          <span className="text-muted-foreground">{runTargetText(run)}</span>
        )}
      </TableCell>
      <TableCell className="text-xs">
        {run.provider} · <span className="font-mono">{run.model}</span>
      </TableCell>
      <TableCell>
        <AiRunStatusBadge status={run.status} />
      </TableCell>
      <TableCell className="text-right tabular-nums">{formatAccuracy(run.citation_accuracy)}</TableCell>
      <TableCell className="text-right tabular-nums">{run.claims_unsupported ?? "—"}</TableCell>
      <TableCell className="text-right tabular-nums">{formatTokens(run.usage.total_tokens)}</TableCell>
      <TableCell className="text-right tabular-nums">{formatCost(run.cost_micros)}</TableCell>
      <TableCell>{run.requested_by_name}</TableCell>
      <TableCell>
        <When iso={run.created_at} />
      </TableCell>
    </TableRow>
  );
}

/**
 * Job route (pcap / malware) per job of the listed runs whose task does not determine it: one
 * cached lookup per distinct job (an analyzer never changes).
 */
function useJobRoutes(orgId: string, runs: readonly AiRun[]): Map<string, JobRoute> {
  const known = new Map<string, JobRoute>();
  const unknown = new Set<string>();
  for (const run of runs) {
    if (!run.job_id) continue;
    const route = routeForTask(run.task);
    if (route) known.set(run.job_id, route);
    else unknown.add(run.job_id);
  }
  const lookups = [...unknown].filter((id) => !known.has(id));
  const results = useQueries({
    queries: lookups.map((jobId) => ({
      queryKey: ["org", orgId, "analysis", jobId],
      queryFn: async () =>
        unwrap(
          await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}", {
            params: { path: { org_id: orgId, job_id: jobId } },
          }),
        ),
      staleTime: 5 * 60_000,
    })),
  });
  results.forEach((result, index) => {
    const analyzer = result.data?.analyzer;
    if (analyzer) known.set(lookups[index], analyzer === "static" ? "malware" : "pcap");
  });
  return known;
}
