import { Badge } from "@/components/ui/badge";
import { type AnalysisJob, analysisKindLabel } from "@/lib/analysis";

/** Which analyzer (and static profile) produced a job: "PCAP", "Static (full)", "AV scan". */
export function AnalyzerBadge({ job, className }: { job: Pick<AnalysisJob, "analyzer" | "profile">; className?: string }) {
  return (
    <Badge variant="outline" className={className}>
      {analysisKindLabel(job)}
    </Badge>
  );
}
