"use client";

import type { Schemas } from "@cyberlab/contracts";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, RotateCw } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  type AnalysisJob,
  analysisErrorText,
  anyActive,
  jobDurationText,
  justSucceeded,
  pollWhileActive,
} from "@/lib/analysis";
import { ApiError, api, errorMessage, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useNow } from "@/lib/use-now";

const PAGE = 10;
// Refusals the API explains itself (already active, queue full / rate limited, too large, archived).
const EXPLAINED = new Set([409, 413, 429]);

type Page = Schemas["AnalysisJobPage"];

export function EvidenceAnalysesCard({
  orgId,
  evidence,
  canWrite,
  investigationArchived,
}: {
  orgId: string;
  evidence: Schemas["EvidenceOut"];
  canWrite: boolean;
  investigationArchived: boolean;
}) {
  const queryClient = useQueryClient();
  const [offset, setOffset] = useState(0);
  const evidenceKey = ["org", orgId, "evidence", evidence.id];
  const listKey = [...evidenceKey, "analyses", offset];
  const path = { org_id: orgId, evidence_id: evidence.id };

  const refreshCustody = () => queryClient.invalidateQueries({ queryKey: [...evidenceKey, "custody"] });

  const jobs = useQuery({
    queryKey: listKey,
    queryFn: async () => {
      const previous = queryClient.getQueryData<Page>(listKey);
      const page = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path, query: { limit: PAGE, offset } },
        }),
      );
      // The worker recorded an `analyzed` custody event: show it without a reload.
      if (justSucceeded(previous?.items, page.items)) {
        void refreshCustody();
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] });
      }
      return page;
    },
    placeholderData: keepPreviousData,
    refetchInterval: (query) => pollWhileActive(query.state.data?.items),
  });

  const run = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path },
          body: { analyzer: "pcap" },
        }),
      ),
    onSuccess: async (job) => {
      if (job.status === "failed") toast.error(analysisErrorText(job.error_code) ?? "Analysis failed");
      else toast.success("Analysis queued");
      setOffset(0);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [...evidenceKey, "analyses"] }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] }),
        refreshCustody(),
      ]);
    },
    onError: async (error) => {
      toast.error(errorMessage(error));
      // 409 analysis_active: someone else started one; show it.
      await queryClient.invalidateQueries({ queryKey: [...evidenceKey, "analyses"] });
    },
  });

  const items = jobs.data?.items;
  const active = anyActive(items);
  const now = useNow(items?.some((job) => job.status === "running") ?? false);
  const runnable = canWrite && !investigationArchived && evidence.status !== "archived";
  const refusal = run.error instanceof ApiError && EXPLAINED.has(run.error.status) ? run.error : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Analyses
          {jobs.data && (
            <span className="ml-2 text-xs font-normal text-muted-foreground">{jobs.data.total} runs</span>
          )}
        </CardTitle>
        {runnable && (
          <CardAction>
            <Button
              size="sm"
              variant={jobs.data?.total ? "outline" : "default"}
              disabled={run.isPending || active || !jobs.data}
              title={active ? "An analysis of this evidence is already queued or running" : undefined}
              onClick={() => run.mutate()}
            >
              {jobs.data?.total ? <RotateCw className="size-4" aria-hidden /> : <Play className="size-4" aria-hidden />}
              {run.isPending ? "Requesting…" : jobs.data?.total ? "Re-run" : "Run analysis"}
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {refusal && (
          <Alert variant="destructive">
            <AlertTitle>Analysis not started</AlertTitle>
            <AlertDescription>{errorMessage(refusal)}</AlertDescription>
          </Alert>
        )}
        {jobs.isError ? (
          <QueryError error={jobs.error} onRetry={() => void jobs.refetch()} />
        ) : !items ? (
          <p className="text-sm text-muted-foreground">Loading analyses…</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Not analyzed. Packet captures (pcap / pcapng) are analyzed automatically when uploaded
            {runnable ? "; you can also run an analysis manually." : "."}
          </p>
        ) : (
          <ul className="flex flex-col divide-y">
            {items.map((job) => (
              <JobRow key={job.id} orgId={orgId} job={job} now={now} />
            ))}
          </ul>
        )}
        <Pager offset={offset} total={jobs.data?.total ?? 0} pageSize={PAGE} onChange={setOffset} />
      </CardContent>
    </Card>
  );
}

function JobRow({ orgId, job, now }: { orgId: string; job: AnalysisJob; now: number }) {
  const created = formatDate(job.created_at);
  const error = analysisErrorText(job.error_code);
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
      <AnalysisStatusBadge status={job.status} />
      <span className="text-muted-foreground" title={created.utc}>
        {created.local}
      </span>
      <span className="text-muted-foreground">
        {job.auto ? "automatic" : <>by {job.requested_by_name}</>}
      </span>
      <span className="text-muted-foreground tabular-nums">{jobDurationText(job, now)}</span>
      {job.status === "succeeded" && <FindingCount job={job} />}
      <Link className="ml-auto text-xs underline underline-offset-4" href={orgPath(orgId, `pcap/${job.id}`)}>
        Details
      </Link>
      {error && (
        <p className="w-full text-xs text-destructive" title={job.error_code ?? undefined}>
          {error}
        </p>
      )}
    </li>
  );
}
