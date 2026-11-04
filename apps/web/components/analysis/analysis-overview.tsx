import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { type AnalysisJob, hasSummary, isActiveStatus, summaryEntries } from "@/lib/analysis";

/**
 * Overview of the analysis summary. Every value is untrusted analyzer output: it is rendered as
 * plain text only, truncated with the full value in the title tooltip.
 */
export function AnalysisOverview({ job }: { job: AnalysisJob }) {
  const entries = summaryEntries(job.summary);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Overview</CardTitle>
      </CardHeader>
      <CardContent>
        {!hasSummary(job.summary) || entries.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {job.status === "failed"
              ? "This analysis failed; no results were recorded."
              : isActiveStatus(job.status)
                ? "Results will appear here once the analysis finishes and has been ingested."
                : "Results will appear here once the analysis has been ingested."}
          </p>
        ) : (
          <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2 xl:grid-cols-3">
            {entries.map((entry) => (
              <div key={entry.key} className="min-w-0">
                <dt className="truncate text-xs text-muted-foreground" title={entry.key}>
                  {entry.label}
                </dt>
                <dd className="truncate" title={entry.value}>
                  {entry.value}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </CardContent>
    </Card>
  );
}
