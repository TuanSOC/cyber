import { Badge } from "@/components/ui/badge";
import { PROCESS_FLAG_HINTS, PROCESS_FLAG_LABELS, type ProcessFlag } from "@/lib/memory";

/** Observations about a process (never verdicts): text badges with their meaning in the title. */
export function ProcessFlags({ flags }: { flags: readonly ProcessFlag[] }) {
  if (flags.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {flags.map((flag) => (
        <Badge
          key={flag}
          variant={flag === "terminated" ? "outline" : "secondary"}
          className="text-[11px] font-normal"
          title={PROCESS_FLAG_HINTS[flag]}
        >
          {PROCESS_FLAG_LABELS[flag]}
        </Badge>
      ))}
    </span>
  );
}
