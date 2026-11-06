/**
 * The merged disk timeline (M9 phase 11): file-system MACB times and parsed artifact events in
 * time order (`GET /analyses/{job}/disk/timeline`). Pure helpers: query building, the paging
 * cursor (offset pages, then a time seek past the API's offset cap), the per-hour histogram of
 * the loaded window, and the `datetime-local` ↔ ISO conversions of the range picker.
 *
 * The histogram counts only the rows already loaded in the browser (no full-scan aggregate):
 * it is labelled as such.
 */
import type { Schemas } from "@cyberlab/contracts";

import { DISK_MAX_OFFSET, DISK_PAGE } from "@/lib/disk";

export type TimelineItem = Schemas["TimelineItemOut"];
export type TimelineSource = TimelineItem["source"];
export type TimeColumn = "mtime" | "atime" | "ctime" | "crtime";

export const TIME_COLUMN_LABELS: Record<TimeColumn, string> = {
  mtime: "Modified (M)",
  atime: "Accessed (A)",
  ctime: "Metadata changed (C)",
  crtime: "Created (B)",
};

export const SOURCE_LABELS: Record<TimelineSource, string> = { file: "File system", event: "Events" };

export const ARTIFACT_LABELS: Readonly<Record<string, string>> = {
  evtx: "Windows event logs",
  registry_system: "Registry (system)",
  registry_user: "Registry (user)",
  prefetch: "Prefetch",
  lnk: "Shortcuts (LNK)",
  mft: "$MFT",
  amcache: "Amcache",
  browser: "Browser history",
  recycle_bin: "Recycle Bin",
  syslog: "Syslog",
  auth_log: "Authentication log",
  utmp: "Logins (utmp / wtmp)",
  shell_history: "Shell history",
  cron: "Cron",
  systemd_journal: "systemd journal",
  packages: "Packages",
};

export function artifactLabel(artifact: string): string {
  return Object.hasOwn(ARTIFACT_LABELS, artifact) ? ARTIFACT_LABELS[artifact] : artifact.replaceAll("_", " ");
}

/** The `kind` column: a MACB letter for file rows, the artifact for events. */
export function kindLabel(item: Pick<TimelineItem, "source" | "kind">): string {
  if (item.source === "file" && Object.hasOwn(TIME_COLUMN_LABELS, item.kind)) return TIME_COLUMN_LABELS[item.kind as TimeColumn];
  return artifactLabel(item.kind);
}

export type TimelineFilters = {
  /** Both sources when both toggles are on; one when the other is off. */
  file: boolean;
  event: boolean;
  time?: TimeColumn;
  artifact?: string;
  from?: string;
  to?: string;
};

export type TimelineQuery = {
  source?: TimelineSource;
  time?: TimeColumn;
  artifact?: string;
  from?: string;
  to?: string;
};

const ARTIFACT = /^[a-z_]{1,32}$/;

/**
 * The API query of the filters, or null when both sources are off (nothing to ask for). An
 * artifact filter implies events only (the API's rule), so it drops the file toggle.
 */
export function timelineQuery(filters: TimelineFilters): TimelineQuery | null {
  const artifact = filters.artifact && ARTIFACT.test(filters.artifact) ? filters.artifact : undefined;
  const file = filters.file && !artifact;
  if (!file && !filters.event) return null;
  const query: TimelineQuery = {};
  if (file && !filters.event) query.source = "file";
  if (!file && filters.event) query.source = "event";
  if (file && filters.time) query.time = filters.time;
  if (artifact) query.artifact = artifact;
  if (filters.from) query.from = filters.from;
  if (filters.to) query.to = filters.to;
  return query;
}

/**
 * Where the next page starts. Offset pages of `DISK_PAGE` until the API's offset cap; past it,
 * a time seek: the same query from the last loaded timestamp (rows at that very instant come
 * again and are dropped by `mergeWindow`). Undefined at the end.
 */
export type TimelineCursor = { offset: number; from?: string };

export function nextTimelineCursor(
  cursor: TimelineCursor,
  page: { items: readonly Pick<TimelineItem, "ts">[]; total: number },
): TimelineCursor | undefined {
  const loadedInWindow = cursor.offset + page.items.length;
  if (page.items.length === 0 || loadedInWindow >= page.total) return undefined;
  const next = cursor.offset + DISK_PAGE;
  if (next <= DISK_MAX_OFFSET) return { offset: next, from: cursor.from };
  const last = page.items[page.items.length - 1]?.ts;
  if (!last || last === cursor.from) return undefined; // one instant holds > 10 000 rows: stop
  return { offset: 0, from: last };
}

/** A stable identity of a merged row (file rows repeat per time column). */
export function rowKey(item: TimelineItem): string {
  return `${item.source}:${item.event_id ?? item.file_id ?? ""}:${item.kind}:${item.ts}`;
}

/** The loaded pages as one list, without the rows a time seek fetched again. */
export function mergeWindow(pages: readonly { items: readonly TimelineItem[] }[]): TimelineItem[] {
  const seen = new Set<string>();
  const out: TimelineItem[] = [];
  for (const page of pages) {
    for (const item of page.items) {
      const key = rowKey(item);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(item);
    }
  }
  return out;
}

const HOUR = 3_600_000;

export type HourBucket = { start: number; count: number };

/**
 * Rows per UTC hour over the loaded window only, with empty hours filled between the first
 * and last (at most `maxBuckets`; a wider span is grouped into larger, equal buckets).
 */
export function hourHistogram(items: readonly Pick<TimelineItem, "ts">[], maxBuckets = 96): { buckets: HourBucket[]; width: number } {
  const times = items.map((i) => Date.parse(i.ts)).filter((t) => Number.isFinite(t));
  if (times.length === 0) return { buckets: [], width: HOUR };
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (const t of times) {
    if (t < min) min = t;
    if (t > max) max = t;
  }
  const first = Math.floor(min / HOUR) * HOUR;
  const hours = Math.floor((max - first) / HOUR) + 1;
  const factor = Math.max(1, Math.ceil(hours / Math.max(1, maxBuckets)));
  const width = HOUR * factor;
  const count = Math.floor((max - first) / width) + 1;
  const buckets: HourBucket[] = Array.from({ length: count }, (_, i) => ({ start: first + i * width, count: 0 }));
  for (const t of times) buckets[Math.floor((t - first) / width)].count += 1;
  return { buckets, width };
}

/** A `datetime-local` value (local wall time) as an aware ISO instant, or undefined. */
export function localInputToIso(value: string): string | undefined {
  if (!value) return undefined;
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
}

/** An ISO instant as a `datetime-local` value in the browser's zone ("" when invalid). */
export function isoToLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const d = new Date(t);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** True when both ends are set and `from` is after `to` (the API answers 422). */
export function invalidRange(from: string | undefined, to: string | undefined): boolean {
  return Boolean(from && to && Date.parse(from) > Date.parse(to));
}

/** A window of `minutes` around an instant (deep link from a finding or a file time). */
export function aroundInstant(iso: string, minutes = 30): { from: string; to: string } | null {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  return { from: new Date(t - minutes * 60_000).toISOString(), to: new Date(t + minutes * 60_000).toISOString() };
}
