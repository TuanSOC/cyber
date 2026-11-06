"use client";

import type { Schemas } from "@cyberlab/contracts";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Play } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { AnalyzerBadge } from "@/components/analysis/analyzer-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { SignatureCount } from "@/components/malware/signature-count";
import { RunMemoryAnalysis } from "@/components/memory/run-memory-analysis";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  type AnalysisJob,
  RUN_KINDS,
  type RunKind,
  analysisErrorText,
  analysisSegment,
  evidenceKind,
  isActiveStatus,
  jobDurationText,
  justSucceeded,
  offeredRuns,
  pollWhileActive,
} from "@/lib/analysis";
import { ApiError, api, errorMessage, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { apiErrorText } from "@/lib/http-errors";
import { orgPath } from "@/lib/nav";
import { useNow } from "@/lib/use-now";

const PAGE = 10;
// Refusals the API explains itself (already active, queue full / rate limited, too large, archived).
const EXPLAINED = new Set([409, 413, 429]);
export const PURGED_NOTE = "Evidence purged by retention; new analyses cannot run.";

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
    mutationFn: async (kind: RunKind) => {
      const { analyzer, profile } = RUN_KINDS[kind];
      return unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path },
          body: profile ? { analyzer, profile } : { analyzer },
        }),
      );
    },
    onSuccess: async (job, kind) => {
      if (job.status === "failed") toast.error(analysisErrorText(job.error_code) ?? "Analysis failed");
      else toast.success(`${RUN_KINDS[kind].label} queued`);
      setOffset(0);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [...evidenceKey, "analyses"] }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] }),
        refreshCustody(),
      ]);
    },
    onError: async (error) => {
      toast.error(apiErrorText(error) ?? errorMessage(error));
      // 409 analysis_active: someone else started one; show it.
      await queryClient.invalidateQueries({ queryKey: [...evidenceKey, "analyses"] });
    },
  });

  const items = jobs.data?.items;
  const now = useNow(items?.some((job) => job.status === "running") ?? false);
  // M7: purged bytes cannot be analyzed again (the API answers 410 evidence_purged).
  const purged = Boolean(evidence.purged_at);
  const runnable = canWrite && !investigationArchived && evidence.status !== "archived" && !purged;
  const refusal = run.error instanceof ApiError && EXPLAINED.has(run.error.status) ? run.error : null;
  const { primary, more } = offeredRuns(evidenceKind(evidence));
  // One active job per analyzer and evidence (the API refuses a second one with 409).
  const activeAnalyzers = new Set(items?.filter((job) => isActiveStatus(job.status)).map((job) => job.analyzer));
  const blocked = (kind: RunKind) => activeAnalyzers.has(RUN_KINDS[kind].analyzer);
  const disabled = run.isPending || !jobs.data;

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
          <CardAction className="flex flex-wrap justify-end gap-2">
            {/* M8: the memory run dialog (phase 9); never automatic. */}
            <RunMemoryAnalysis
              orgId={orgId}
              evidence={evidence}
              canRun={runnable && !disabled}
              active={activeAnalyzers.has("memory")}
              onRequested={() => {
                setOffset(0);
                void queryClient.invalidateQueries({ queryKey: [...evidenceKey, "analyses"] });
                void queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] });
                void refreshCustody();
              }}
            />
            {primary.map((kind, index) => (
              <Button
                key={kind}
                size="sm"
                variant={index === 0 && !jobs.data?.total ? "default" : "outline"}
                disabled={disabled || blocked(kind)}
                title={blocked(kind) ? "An analysis of this kind is already queued or running" : RUN_KINDS[kind].hint}
                onClick={() => run.mutate(kind)}
              >
                <Play className="size-4" aria-hidden />
                {run.isPending && run.variables === kind ? "Requesting…" : RUN_KINDS[kind].label}
              </Button>
            ))}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm" variant="ghost" disabled={disabled} aria-label="Other analyses">
                  More <ChevronDown className="size-4" aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-72">
                <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                  Run any analyzer on this file
                </DropdownMenuLabel>
                {more.map((kind) => (
                  <DropdownMenuItem
                    key={kind}
                    disabled={blocked(kind)}
                    onSelect={() => run.mutate(kind)}
                    className="flex flex-col items-start gap-0"
                  >
                    <span>{RUN_KINDS[kind].label}</span>
                    <span className="text-xs text-muted-foreground">{RUN_KINDS[kind].hint}</span>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
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
        {purged && <p className="text-sm text-muted-foreground">{PURGED_NOTE}</p>}
        {jobs.isError ? (
          <QueryError error={jobs.error} onRetry={() => void jobs.refetch()} />
        ) : !items ? (
          <p className="text-sm text-muted-foreground">Loading analyses…</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Not analyzed. Uploads are analyzed automatically: packet captures by the PCAP analyzer, executables
            (PE / ELF) by static analysis, and other files by an AV scan
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
      <AnalyzerBadge job={job} />
      <span className="text-muted-foreground" title={created.utc}>
        {created.local}
      </span>
      <span className="text-muted-foreground">
        {job.auto ? "automatic" : <>by {job.requested_by_name}</>}
      </span>
      <span className="text-muted-foreground tabular-nums">{jobDurationText(job, now)}</span>
      {job.status === "succeeded" && <FindingCount job={job} />}
      {job.status === "succeeded" && job.analyzer === "static" && <SignatureCount job={job} hideZero />}
      <Link className="ml-auto text-xs underline underline-offset-4" href={orgPath(orgId, analysisSegment(job))}>
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
