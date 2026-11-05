import { Sparkles } from "lucide-react";

import { AI_BANNER } from "@/lib/ai";
import { cn } from "@/lib/utils";

/** The notice on every AI view (fixed text, never model-derived). */
export function AiBanner({ className }: { className?: string }) {
  return (
    <p
      className={cn("flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground", className)}
      role="note"
    >
      <Sparkles className="mt-0.5 size-3.5 shrink-0" aria-hidden />
      <span>{AI_BANNER}</span>
    </p>
  );
}
