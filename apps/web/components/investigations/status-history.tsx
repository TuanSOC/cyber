"use client";

import { Button } from "@/components/ui/button";
import { type StatusEvent, caseErrorMessage, visText } from "@/lib/case";
import { STATUS_LABELS, formatDate } from "@/lib/format";
import { useStatusEvents } from "@/lib/use-case";

/** Status history of a case, newest first (cursor-paged). */
export function StatusHistory({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const events = useStatusEvents(orgId, investigationId);
  const items = events.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <section aria-labelledby="status-history-title" className="flex flex-col gap-2">
      <h3 id="status-history-title" className="text-sm font-semibold">
        Status history
      </h3>
      {events.isError ? (
        <p className="text-sm text-muted-foreground" role="alert">
          {caseErrorMessage(events.error)}
        </p>
      ) : events.isPending ? (
        <p className="text-sm text-muted-foreground">Loading history…</p>
      ) : (
        <StatusEventList events={items} />
      )}
      {events.hasNextPage && (
        <Button variant="outline" size="sm" className="w-fit" disabled={events.isFetchingNextPage} onClick={() => void events.fetchNextPage()}>
          Load older changes
        </Button>
      )}
    </section>
  );
}

/** Presentational list (reasons are plain text with invisible characters made visible). */
export function StatusEventList({ events }: { events: readonly StatusEvent[] }) {
  if (events.length === 0) return <p className="text-sm text-muted-foreground">No status changes yet.</p>;
  return (
    <ol className="flex flex-col divide-y rounded-md border">
      {events.map((e) => {
        const when = formatDate(e.occurred_at);
        return (
          <li key={e.id} className="flex flex-col gap-1 px-3 py-2 text-sm">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium">
                {e.from_status ? `${STATUS_LABELS[e.from_status]} → ` : ""}
                {STATUS_LABELS[e.to_status]}
              </span>
              <span className="text-xs text-muted-foreground">
                by {e.actor_name} · <time dateTime={e.occurred_at} title={when.utc}>{when.local}</time>
              </span>
            </div>
            {e.reason ? <p className="text-xs whitespace-pre-wrap break-words">{visText(e.reason)}</p> : null}
          </li>
        );
      })}
    </ol>
  );
}
