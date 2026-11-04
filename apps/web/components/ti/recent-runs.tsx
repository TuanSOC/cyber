"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { When } from "@/components/analysis/result-parts";
import { QueryError } from "@/components/query-error";
import { RunStatusBadge } from "@/components/ti/run-progress";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { isActiveRun, providerLabel, runItemTotal, runPollMs } from "@/lib/ti";
import { tiKeys } from "@/lib/use-ti";

const RECENT = 10;

/** The org's latest enrichment runs (manual lookups and analysis jobs). */
export function RecentRuns({
  orgId,
  selected,
  onSelect,
}: {
  orgId: string;
  selected: string | null;
  onSelect: (runId: string) => void;
}) {
  const runs = useQuery({
    queryKey: [...tiKeys.runs(orgId), { limit: RECENT }],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ti/runs", {
          params: { path: { org_id: orgId }, query: { limit: RECENT } },
        }),
      ),
    refetchInterval: (query) =>
      runPollMs(
        query.state.data?.items.find((r) => isActiveRun(r.status))?.status,
        query.state.dataUpdateCount,
      ),
  });

  if (runs.isError) return <QueryError error={runs.error} onRetry={() => void runs.refetch()} />;
  const items = runs.data?.items;
  return (
    <div className="min-w-0 rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-44">Started</TableHead>
            <TableHead className="w-28">Status</TableHead>
            <TableHead>Scope</TableHead>
            <TableHead>Providers</TableHead>
            <TableHead className="w-20 text-right">Lookups</TableHead>
            <TableHead>Requested by</TableHead>
            <TableHead className="w-20" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {runs.isPending && (
            <TableRow>
              <TableCell colSpan={7} className="py-6 text-center text-muted-foreground">
                Loading…
              </TableCell>
            </TableRow>
          )}
          {items?.length === 0 && (
            <TableRow>
              <TableCell colSpan={7} className="py-6 text-center text-muted-foreground">
                No enrichment runs yet.
              </TableCell>
            </TableRow>
          )}
          {items?.map((run) => (
            <TableRow key={run.id} data-state={run.id === selected ? "selected" : undefined}>
              <TableCell>
                <When iso={run.created_at} />
              </TableCell>
              <TableCell>
                <RunStatusBadge status={run.status} />
              </TableCell>
              <TableCell>
                {run.scope === "job" && run.job_id ? (
                  <Link
                    href={orgPath(orgId, `pcap/${run.job_id}?tab=iocs`)}
                    className="text-primary underline-offset-4 hover:underline"
                  >
                    Analysis IOCs
                  </Link>
                ) : (
                  "Manual lookup"
                )}
              </TableCell>
              <TableCell className="text-xs">{run.providers.map(providerLabel).join(", ")}</TableCell>
              <TableCell className="text-right tabular-nums">{runItemTotal(run.summary)}</TableCell>
              <TableCell>{run.requested_by_name}</TableCell>
              <TableCell>
                <Button variant="ghost" size="sm" onClick={() => onSelect(run.id)}>
                  Show
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
