"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { AnalysisOverview } from "@/components/analysis/analysis-overview";
import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  type AnalysisJob,
  analysisErrorText,
  isActiveStatus,
  jobDurationText,
  justSucceeded,
  pollWhileActive,
  toolVersions,
} from "@/lib/analysis";
import { ApiError, api, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useNow } from "@/lib/use-now";

// Result views arrive with the read API (phase 4); no requests are made for them yet.
const RESULT_TABS = [
  ["findings", "Findings"],
  ["alerts", "Alerts"],
  ["flows", "Flows"],
  ["dns", "DNS"],
  ["http", "HTTP"],
  ["tls", "TLS"],
  ["iocs", "IOCs"],
  ["timeline", "Timeline"],
] as const;

export default function AnalysisPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { orgId } = useOrg();
  const queryClient = useQueryClient();
  const key = ["org", orgId, "analysis", jobId];

  const job = useQuery({
    queryKey: key,
    queryFn: async () => {
      const previous = queryClient.getQueryData<AnalysisJob>(key);
      const next = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}", {
          params: { path: { org_id: orgId, job_id: jobId } },
        }),
      );
      if (justSucceeded(previous ? [previous] : undefined, [next])) {
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", next.evidence_id] });
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] });
      }
      return next;
    },
    refetchInterval: (query) => pollWhileActive(query.state.data ? [query.state.data] : undefined),
  });
  const now = useNow(job.data?.status === "running");

  const back = orgPath(orgId, "pcap");
  if (job.error instanceof ApiError && (job.error.status === 404 || job.error.status === 422)) {
    return <NotFoundCard title="Analysis not found" backHref={back} backLabel="PCAP Analyzer" />;
  }
  if (job.isError) return <QueryError error={job.error} onRetry={() => void job.refetch()} />;
  const j = job.data;
  if (!j) return <p className="text-sm text-muted-foreground">Loading analysis…</p>;

  const error = analysisErrorText(j.error_code);
  const versions = toolVersions(j.summary);
  const active = isActiveStatus(j.status);
  const timings: [string, string | null][] = [
    ["Requested", j.created_at],
    ["Started", j.started_at],
    ["Finished", j.finished_at],
  ];

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> PCAP Analyzer
      </Link>
      <PageHeader
        title={j.evidence_filename}
        description={`PCAP analysis · ${j.auto ? "started automatically on upload" : `requested by ${j.requested_by_name}`}`}
        actions={<AnalysisStatusBadge status={j.status} />}
      />
      {j.status === "failed" && error && (
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Analysis failed</AlertTitle>
          <AlertDescription>
            {error}
            <span className="ml-1 font-mono text-xs">({j.error_code})</span>
          </AlertDescription>
        </Alert>
      )}
      {active && (
        <Alert className="mb-6">
          <AlertTitle>{j.status === "queued" ? "Waiting for an analyzer worker…" : "Analyzing the capture…"}</AlertTitle>
          <AlertDescription>This page updates automatically.</AlertDescription>
        </Alert>
      )}

      <Card className="mb-6">
        <CardContent className="grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
          <div className="min-w-0">
            <p className="text-xs text-muted-foreground">Evidence</p>
            <Link
              className="block truncate hover:underline"
              title={j.evidence_filename}
              href={orgPath(orgId, `evidence/${j.evidence_id}`)}
            >
              {j.evidence_filename}
            </Link>
            <Link
              className="text-xs underline underline-offset-4"
              href={orgPath(orgId, `investigations/${j.investigation_id}`)}
            >
              Open case
            </Link>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Timing</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-xs">
              {timings.map(([label, iso]) => {
                const when = iso ? formatDate(iso) : null;
                return (
                  <div key={label} className="contents">
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd title={when?.utc}>{when?.local ?? "—"}</dd>
                  </div>
                );
              })}
            </dl>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Duration</p>
            <p className="tabular-nums">{jobDurationText(j, now)}</p>
            <Badge variant={j.auto ? "secondary" : "outline"} className="mt-1">
              {j.auto ? "Auto" : "Manual"}
            </Badge>
          </div>
          <div className="min-w-0">
            <p className="text-xs text-muted-foreground">Tool versions</p>
            {versions.length === 0 ? (
              <p className="text-muted-foreground">—</p>
            ) : (
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-xs">
                {versions.map(([name, version]) => (
                  <div key={name} className="contents">
                    <dt className="truncate text-muted-foreground" title={name}>
                      {name}
                    </dt>
                    <dd className="truncate font-mono" title={version}>
                      {version}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="overview">
        <TabsList aria-label="Analysis results">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {RESULT_TABS.map(([value, label]) => (
            <TabsTrigger key={value} value={value}>
              {label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="overview">
          <AnalysisOverview job={j} />
        </TabsContent>
        {RESULT_TABS.map(([value, label]) => (
          <TabsContent key={value} value={value}>
            <Card>
              <CardHeader>
                <CardTitle>{label}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  The {label} view is coming in the next step of the PCAP Analyzer.
                </p>
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>
    </>
  );
}
