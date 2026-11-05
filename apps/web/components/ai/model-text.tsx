import { displayText } from "@/lib/ai";
import { cn } from "@/lib/utils";

/**
 * Model-derived text: a React text node only (never HTML, markdown or a link), isolated for
 * bidi with its control characters made visible, wrapped and shown in full.
 */
export function ModelText({ value, className }: { value: string | null | undefined; className?: string }) {
  return (
    <span dir="auto" className={cn("break-words whitespace-pre-wrap [unicode-bidi:isolate]", className)}>
      {displayText(value)}
    </span>
  );
}
