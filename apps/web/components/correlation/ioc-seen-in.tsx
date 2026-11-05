"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { type KeyTarget, SeenInList } from "@/components/correlation/correlation-parts";
import { KeyDrawer } from "@/components/correlation/key-drawer";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";
import {
  type JobCorrelations,
  correlationKeys,
  fetchJobCorrelations,
  rowsFirst,
  seenInSummary,
  sortSeenIn,
} from "@/lib/correlation";

const COLLAPSED_ROWS = 5;

/** The IOC rows of the visible page (only their ids are read). */
export type SeenInRowRef = { id: string };

/**
 * "Also seen in" on the IOC tab of pcap and static jobs (slot from phase 1, RT16): the job's
 * observables that other jobs of the org share, fetched once per tab (no per-row request; more
 * pages through the cursor), each with a "seen in N other cases" chip that opens the key drawer.
 * With `rows` (the IOC rows on screen) the keys carried by those rows come first, joined by the
 * IOC row id in each key's `source_ids` (RT8: never by re-normalizing values in the browser).
 */
export function IocSeenIn({ orgId, jobId, rows }: { orgId: string; jobId: string; rows?: readonly SeenInRowRef[] }) {
  const [target, setTarget] = useState<KeyTarget | null>(null);
  const [expanded, setExpanded] = useState(false);
  const query = useInfiniteQuery({
    queryKey: correlationKeys.job(orgId, jobId),
    queryFn: ({ pageParam }) => fetchJobCorrelations(orgId, jobId, { cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last: JobCorrelations) => last.next_cursor ?? null,
  });
  const rowIds = useMemo(() => (rows ?? []).map((row) => row.id), [rows]);
  const pages = query.data?.pages;
  const sorted = useMemo(() => sortSeenIn((pages ?? []).flatMap((page) => page.items)), [pages]);
  const { onPage, others } = useMemo(() => rowsFirst(sorted, rowIds), [sorted, rowIds]);

  if (query.isError) {
    // Until the correlation routes ship the panel stays out of the way.
    if (query.error instanceof ApiError && query.error.code === "not_implemented") return null;
    return <QueryError error={query.error} onRetry={() => void query.refetch()} />;
  }
  const first = pages?.[0];
  if (!first) return null;

  const ordered = [...onPage, ...others];
  const summary = seenInSummary({ items: ordered, total_keys: first.total_keys });
  return (
    <section aria-labelledby={`seen-in-${jobId}`} className="flex flex-col gap-1 rounded-lg border p-3">
      <h3 id={`seen-in-${jobId}`} className="text-sm font-semibold">
        Also seen in
      </h3>
      {!first.indexed ? (
        <p className="text-xs text-muted-foreground">This job is not indexed for cross-case matching yet.</p>
      ) : (
        <>
          <p className="text-xs text-muted-foreground" aria-live="polite">
            {summary}
            {rows && onPage.length > 0 && ` ${onPage.length} of them on the rows shown below.`}
            {first.truncated && " Only part of this job's observables were indexed."}
          </p>
          {ordered.length > 0 && (
            <SeenInList
              items={ordered}
              onOpen={setTarget}
              limit={expanded ? undefined : Math.max(COLLAPSED_ROWS, onPage.length)}
              onPageCount={rows ? onPage.length : 0}
            />
          )}
          <div className="flex flex-wrap gap-2">
            {ordered.length > Math.max(COLLAPSED_ROWS, onPage.length) && (
              <Button variant="ghost" size="xs" className="w-fit" aria-expanded={expanded} onClick={() => setExpanded((v) => !v)}>
                {expanded ? "Show fewer" : `Show all ${ordered.length}`}
              </Button>
            )}
            {query.hasNextPage && (
              <Button
                variant="ghost"
                size="xs"
                className="w-fit"
                disabled={query.isFetchingNextPage}
                onClick={() => {
                  setExpanded(true);
                  void query.fetchNextPage();
                }}
              >
                {query.isFetchingNextPage ? "Loading…" : "Load more observables"}
              </Button>
            )}
          </div>
        </>
      )}
      <KeyDrawer orgId={orgId} target={target} onClose={() => setTarget(null)} />
    </section>
  );
}
