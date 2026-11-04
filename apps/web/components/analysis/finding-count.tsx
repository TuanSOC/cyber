import { Badge } from "@/components/ui/badge";
import type { AnalysisJob } from "@/lib/analysis";
import { findingCount, formatCount } from "@/lib/pcap-results";

/**
 * Total findings of a succeeded job (`summary.counts.findings`, computed at ingest). The summary
 * has no per-severity breakdown, so only the total is shown.
 */
export function FindingCount({ job, empty = "—" }: { job: Pick<AnalysisJob, "status" | "summary">; empty?: string }) {
  const count = job.status === "succeeded" ? findingCount(job.summary) : null;
  if (count === null) return <span className="text-muted-foreground">{empty}</span>;
  return (
    <Badge variant={count > 0 ? "secondary" : "outline"} className="tabular-nums">
      {formatCount(count)} {count === 1 ? "finding" : "findings"}
    </Badge>
  );
}
