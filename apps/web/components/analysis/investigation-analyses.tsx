"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { AnalyzerBadge } from "@/components/analysis/analyzer-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { analysisErrorText, analysisSegment, pollWhileActive } from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";

const PAGE = 50;

/**
 * Latest analysis per evidence and kind of run (PCAP, full static, AV scan) of one case, filtered
 * on the server (`investigation_id` + `latest_per_evidence`). Shared with the incident card.
 */
export function useInvestigationAnalyses(orgId: string, investigationId: string, offset = 0) {
  const params = { investigation_id: investigationId, latest_per_evidence: true, limit: PAGE, offset };
  return useQuery({
    queryKey: ["org", orgId, "analyses", params],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses", {
          params: { path: { org_id: orgId }, query: params },
        }),
      ),
    refetchInterval: (query) => pollWhileActive(query.state.data?.items),
  });
}

export function InvestigationAnalyses({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const [offset, setOffset] = useState(0);
  const analyses = useInvestigationAnalyses(orgId, investigationId, offset);

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Analyses</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {analyses.isError ? (
          <QueryError error={analyses.error} onRetry={() => void analyses.refetch()} />
        ) : !analyses.data ? (
          <p className="text-sm text-muted-foreground">Loading analyses…</p>
        ) : analyses.data.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No analyses for this case yet. Uploads are analyzed automatically: packet captures by the PCAP analyzer,
            executables by static analysis and other files by an AV scan.
          </p>
        ) : (
          <ul className="flex flex-col divide-y">
            {analyses.data.items.map((job) => {
              const created = formatDate(job.created_at);
              const error = analysisErrorText(job.error_code);
              return (
                <li key={job.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
                  <AnalysisStatusBadge status={job.status} />
                  <AnalyzerBadge job={job} />
                  <Link
                    className="max-w-80 min-w-0 truncate hover:underline"
                    title={job.evidence_filename}
                    href={orgPath(orgId, `evidence/${job.evidence_id}`)}
                  >
                    {job.evidence_filename}
                  </Link>
                  <span className="text-xs text-muted-foreground" title={created.utc}>
                    {created.local}
                  </span>
                  {job.status === "succeeded" && <FindingCount job={job} />}
                  <Link className="ml-auto text-xs underline underline-offset-4" href={orgPath(orgId, analysisSegment(job))}>
                    Details
                  </Link>
                  {error && <p className="w-full text-xs text-destructive">{error}</p>}
                </li>
              );
            })}
          </ul>
        )}
        <Pager offset={offset} total={analyses.data?.total ?? 0} pageSize={PAGE} onChange={setOffset} />
      </CardContent>
    </Card>
  );
}
