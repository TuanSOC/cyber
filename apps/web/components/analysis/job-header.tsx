"use client";

import Link from "next/link";
import type { ReactNode } from "react";

import { AnalyzerBadge } from "@/components/analysis/analyzer-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { type AnalysisJob, analysisErrorText, ANALYZER_MODULES, analysisSegment, isActiveStatus, jobDurationText } from "@/lib/analysis";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";

/** Failure / in-progress banners of a job detail page. */
export function JobStatusAlerts({ job, activeTitle }: { job: AnalysisJob; activeTitle: string }) {
  const error = analysisErrorText(job.error_code);
  return (
    <>
      {job.status === "failed" && error && (
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Analysis failed</AlertTitle>
          <AlertDescription>
            {error}
            <span className="ml-1 font-mono text-xs">({job.error_code})</span>
          </AlertDescription>
        </Alert>
      )}
      {isActiveStatus(job.status) && (
        <Alert className="mb-6">
          <AlertTitle>{job.status === "queued" ? "Waiting for an analyzer worker…" : activeTitle}</AlertTitle>
          <AlertDescription>This page updates automatically.</AlertDescription>
        </Alert>
      )}
    </>
  );
}

/** Evidence, timing, duration / trigger and a results cell: the facts card of a job page. */
export function JobFactsCard({
  orgId,
  job,
  now,
  results,
}: {
  orgId: string;
  job: AnalysisJob;
  now: number;
  results: ReactNode;
}) {
  const timings: [string, string | null][] = [
    ["Requested", job.created_at],
    ["Started", job.started_at],
    ["Finished", job.finished_at],
  ];
  return (
    <Card className="mb-6">
      <CardContent className="grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">Evidence</p>
          <Link
            className="block truncate hover:underline"
            title={job.evidence_filename}
            href={orgPath(orgId, `evidence/${job.evidence_id}`)}
          >
            {job.evidence_filename}
          </Link>
          <Link
            className="text-xs underline underline-offset-4 print:hidden"
            href={orgPath(orgId, `investigations/${job.investigation_id}`)}
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
          <p className="tabular-nums">{jobDurationText(job, now)}</p>
          <div className="mt-1 flex flex-wrap gap-1">
            <Badge variant={job.auto ? "secondary" : "outline"}>{job.auto ? "Auto" : "Manual"}</Badge>
            <AnalyzerBadge job={job} />
          </div>
        </div>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">Results</p>
          {results}
        </div>
      </CardContent>
    </Card>
  );
}

/** Shown when a job id is opened under the other analyzer's module. */
export function WrongModuleNotice({ orgId, job }: { orgId: string; job: AnalysisJob }) {
  return (
    <Alert className="mb-6">
      <AlertTitle>
        This is {ANALYZER_MODULES[job.analyzer].article} of {job.evidence_filename}
      </AlertTitle>
      <AlertDescription>
        <Link className="underline underline-offset-4" href={orgPath(orgId, analysisSegment(job))}>
          Open it in {ANALYZER_MODULES[job.analyzer].module}
        </Link>
      </AlertDescription>
    </Alert>
  );
}
