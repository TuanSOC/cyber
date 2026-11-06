"use client";

import { useId, useMemo, useState } from "react";

import { ALL, FilterSelect } from "@/components/analysis/result-parts";
import { InertText } from "@/components/disk/inert-text";
import { WindowedRows } from "@/components/disk/windowed-rows";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  type HourBucket,
  SOURCE_LABELS,
  TIME_COLUMN_LABELS,
  type TimeColumn,
  type TimelineItem,
  artifactLabel,
  hourHistogram,
  invalidRange,
  isoToLocalInput,
  kindLabel,
  localInputToIso,
  mergeWindow,
  rowKey,
  timelineQuery,
} from "@/lib/disk-timeline";
import { formatDate } from "@/lib/format";
import { formatCount } from "@/lib/pcap-results";
import { useDebounced } from "@/lib/use-debounced";
import { useDiskTimeline } from "@/lib/use-disk-job";
import { cn } from "@/lib/utils";

const ROW = 36;
const VIEWPORT = 520;
const GRID = "grid grid-cols-[11rem_6rem_10rem_minmax(14rem,2fr)_minmax(10rem,1fr)] items-center gap-2 px-2";
const TIME_OPTIONS = Object.entries(TIME_COLUMN_LABELS) as [TimeColumn, string][];

/**
 * Rows per hour of the loaded window (pure). Bars are `<li>` with an accessible label; the
 * heading says the counts cover the loaded rows only (no full-scan aggregate).
 */
export function HourHistogram({ items, loadedAll }: { items: readonly Pick<TimelineItem, "ts">[]; loadedAll: boolean }) {
  const { buckets, width } = useMemo(() => hourHistogram(items), [items]);
  if (buckets.length === 0) return null;
  const max = Math.max(...buckets.map((b) => b.count));
  const hours = width / 3_600_000;
  const label = (b: HourBucket) => `${new Date(b.start).toISOString().slice(0, 13).replace("T", " ")}:00 UTC: ${formatCount(b.count)}`;
  return (
    <figure className="flex flex-col gap-1" data-testid="hour-histogram">
      <figcaption className="text-xs text-muted-foreground">
        Rows per {hours === 1 ? "hour" : `${hours} hours`} (UTC) of the {formatCount(items.length)} loaded rows
        {loadedAll ? "" : " only: scroll to load more"}.
      </figcaption>
      <ol className="flex h-16 items-end gap-px" aria-label="Rows over time">
        {buckets.map((b) => (
          <li
            key={b.start}
            className="min-w-[2px] flex-1 rounded-t-sm bg-primary/70"
            style={{ height: `${b.count === 0 ? 0 : Math.max(4, (b.count / max) * 100)}%` }}
            title={label(b)}
            aria-label={label(b)}
          />
        ))}
      </ol>
    </figure>
  );
}

/** One merged row (pure): time, source, kind, description and path, all as text. */
export function TimelineRow({ item, onOpenFile }: { item: TimelineItem; onOpenFile?: (fileId: string) => void }) {
  const when = formatDate(item.ts);
  const fileId = item.file_id;
  return (
    <div role="row" className={cn(GRID, "h-9 border-b text-sm")}>
      <span role="cell" className="truncate text-xs tabular-nums" title={when.utc}>
        {when.local}
      </span>
      <span role="cell">
        <Badge variant="outline" className="text-[10px] font-normal">
          {SOURCE_LABELS[item.source]}
        </Badge>
      </span>
      <span role="cell" className="truncate text-xs text-muted-foreground" title={kindLabel(item)}>
        {kindLabel(item)}
      </span>
      <span role="cell" className="min-w-0">
        <InertText value={item.description} />
      </span>
      <span role="cell" className="flex min-w-0 items-center gap-1">
        <InertText value={item.path} mono className="min-w-0 flex-1" />
        {fileId && onOpenFile ? (
          <Button type="button" variant="ghost" size="sm" className="h-6 shrink-0 px-1.5 text-xs" onClick={() => onOpenFile(fileId)}>
            File
          </Button>
        ) : null}
      </span>
    </div>
  );
}

function TimelineHeader() {
  return (
    <div role="row" className={cn(GRID, "h-9 text-xs font-medium text-muted-foreground")}>
      <span role="columnheader">Time</span>
      <span role="columnheader">Source</span>
      <span role="columnheader">Kind</span>
      <span role="columnheader">Description</span>
      <span role="columnheader">Path</span>
    </div>
  );
}

/**
 * The merged timeline of a disk job: file-system MACB times and parsed events, with source
 * toggles, a time-column and artifact filter, a time range (also set by deep links: `from` /
 * `to`), windowed rows and the per-hour histogram of the loaded window.
 */
export function DiskTimelineTab({
  orgId,
  jobId,
  artifacts,
  initialRange,
  onOpenFile,
}: {
  orgId: string;
  jobId: string;
  /** The artifact categories of the job (from the summary), for the filter. */
  artifacts: readonly string[];
  initialRange?: { from?: string; to?: string };
  onOpenFile: (fileId: string) => void;
}) {
  const id = useId();
  const [file, setFile] = useState(true);
  const [event, setEvent] = useState(true);
  const [time, setTime] = useState<TimeColumn | typeof ALL>(ALL);
  const [artifact, setArtifact] = useState<string>(ALL);
  const [from, setFrom] = useState(isoToLocalInput(initialRange?.from));
  const [to, setTo] = useState(isoToLocalInput(initialRange?.to));
  const range = useDebounced({ from: localInputToIso(from), to: localInputToIso(to) });
  const badRange = invalidRange(range.from, range.to);
  const query = timelineQuery({
    file,
    event,
    time: time === ALL ? undefined : time,
    artifact: artifact === ALL ? undefined : artifact,
    from: badRange ? undefined : range.from,
    to: badRange ? undefined : range.to,
  });
  const timeline = useDiskTimeline(orgId, jobId, query, true);
  const items = useMemo(() => mergeWindow(timeline.data?.pages ?? []), [timeline.data]);
  const total = timeline.data?.pages[0]?.total ?? null;
  const artifactOptions = artifacts.map((a) => [a, artifactLabel(a)] as const);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <fieldset className="flex items-center gap-3">
          <legend className="sr-only">Sources</legend>
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={file} disabled={artifact !== ALL} onChange={(e) => setFile(e.target.checked)} />
            {SOURCE_LABELS.file}
          </label>
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={event} onChange={(e) => setEvent(e.target.checked)} />
            {SOURCE_LABELS.event}
          </label>
        </fieldset>
        <FilterSelect value={time} onChange={setTime} options={TIME_OPTIONS} allLabel="All file times" label="File time filter" />
        <FilterSelect
          value={artifact}
          onChange={setArtifact}
          options={artifactOptions}
          allLabel="All artifacts"
          label="Artifact filter"
          className="w-52"
        />
        <label className="flex items-center gap-1 text-xs" htmlFor={`${id}-from`}>
          From
          <Input id={`${id}-from`} type="datetime-local" className="h-8 w-52" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label className="flex items-center gap-1 text-xs" htmlFor={`${id}-to`}>
          to
          <Input id={`${id}-to`} type="datetime-local" className="h-8 w-52" value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
      </div>
      {artifact !== ALL ? <p className="text-xs text-muted-foreground">An artifact filter shows events only.</p> : null}
      {badRange ? <p className="text-xs text-destructive">The start of the range is after its end.</p> : null}
      {query === null ? (
        <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">Turn on at least one source.</p>
      ) : timeline.isError ? (
        <QueryError error={timeline.error} onRetry={() => void timeline.refetch()} />
      ) : (
        <>
          <HourHistogram items={items} loadedAll={!timeline.hasNextPage} />
          <div className="overflow-x-auto">
            <div className="min-w-[56rem]">
              <WindowedRows
                key={JSON.stringify(query)}
                label="Merged timeline"
                items={items}
                rowHeight={ROW}
                height={VIEWPORT}
                header={<TimelineHeader />}
                renderRow={(item) => <TimelineRow key={rowKey(item)} item={item} onOpenFile={onOpenFile} />}
                onNearEnd={
                  timeline.hasNextPage
                    ? () => {
                        if (!timeline.isFetchingNextPage) void timeline.fetchNextPage();
                      }
                    : undefined
                }
                footer={
                  timeline.isPending
                    ? "Loading…"
                    : total === 0
                      ? "No rows in this range."
                      : `${formatCount(items.length)} rows loaded${timeline.hasNextPage ? " (more load as you scroll)" : ""}.`
                }
              />
            </div>
          </div>
        </>
      )}
    </div>
  );
}
