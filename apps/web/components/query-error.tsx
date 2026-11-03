import { Button } from "@/components/ui/button";
import { errorMessage } from "@/lib/api";

/** Error state with Retry for a failed query (never shown as "loading" or "empty"). */
export function QueryError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-destructive/40 p-3 text-sm" role="alert">
      <span className="text-destructive">{errorMessage(error)}</span>
      <Button variant="outline" size="sm" onClick={onRetry}>
        Retry
      </Button>
    </div>
  );
}
