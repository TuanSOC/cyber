"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { AnalyzerBadge } from "@/components/analysis/analyzer-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { QueryError } from "@/components/query-error";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { analysisErrorText, analysisSegment, latestPerEvidence, pollWhileActive } from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";

// One request, never one per evidence: the newest org-wide jobs, filtered to this case.
const RECENT = 100;

/**
 * Latest analysis per evidence and kind of run (PCAP, full static, AV scan) of this investigation,
 * among the org's most recent jobs.
 */
export function InvestigationAnalyses({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const params = { limit: RECENT, offset: 0 };
  const recent = useQuery({
    queryKey: ["org", orgId, "analyses", params],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses", {
          params: { path: { org_id: orgId }, query: params },
        }),
      ),
    select: (page) => ({
      items: latestPerEvidence(page.items.filter((job) => job.investigation_id === investigationId)),
      partial: page.total > page.items.length,
    }),
    refetchInterval: (query) =>
      pollWhileActive(query.state.data?.items.filter((job) => job.investigation_id === investigationId)),
  });

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Analyses</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {recent.isError ? (
          <QueryError error={recent.error} onRetry={() => void recent.refetch()} />
        ) : !recent.data ? (
          <p className="text-sm text-muted-foreground">Loading analyses…</p>
        ) : recent.data.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No recent analyses for this case. Uploads are analyzed automatically: packet captures by the
            PCAP analyzer, executables by static analysis and other files by an AV scan.
          </p>
        ) : (
          <ul className="flex flex-col divide-y">
            {recent.data.items.map((job) => {
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
        {recent.data?.partial && (
          <p className="text-xs text-muted-foreground">
            Showing the latest analysis per evidence among the organization&apos;s {RECENT} most recent runs.{" "}
            <Link className="underline underline-offset-4" href={orgPath(orgId, "pcap")}>
              PCAP analyses
            </Link>
            {" · "}
            <Link className="underline underline-offset-4" href={orgPath(orgId, "malware")}>
              Malware Lab
            </Link>
          </p>
        )}
      </CardContent>
    </Card>
  );
}
