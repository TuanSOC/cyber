import { describe, expect, it } from "vitest";

import {
  aroundInstant,
  hourHistogram,
  invalidRange,
  isoToLocalInput,
  kindLabel,
  localInputToIso,
  mergeWindow,
  nextTimelineCursor,
  timelineQuery,
  type TimelineItem,
} from "@/lib/disk-timeline";

const item = (ts: string, over: Partial<TimelineItem> = {}): TimelineItem =>
  ({ ts, source: "event", kind: "evtx", description: "d", path: "/p", file_id: null, event_id: `e-${ts}`, ...over }) as TimelineItem;

describe("timeline query", () => {
  it("maps the source toggles and filters", () => {
    expect(timelineQuery({ file: true, event: true })).toEqual({});
    expect(timelineQuery({ file: true, event: false, time: "mtime" })).toEqual({ source: "file", time: "mtime" });
    expect(timelineQuery({ file: false, event: true, time: "mtime" })).toEqual({ source: "event" });
    expect(timelineQuery({ file: false, event: false })).toBeNull();
  });

  it("treats an artifact filter as events only and drops invalid artifacts", () => {
    expect(timelineQuery({ file: true, event: true, artifact: "evtx" })).toEqual({ source: "event", artifact: "evtx" });
    expect(timelineQuery({ file: true, event: false, artifact: "evtx" })).toBeNull();
    expect(timelineQuery({ file: true, event: true, artifact: "../x" })).toEqual({});
  });
});

describe("timeline cursor", () => {
  it("pages by offset, then seeks by time past the offset cap", () => {
    const page = { items: [item("2026-01-01T00:00:00Z"), item("2026-01-01T01:00:00Z")], total: 50_000 };
    expect(nextTimelineCursor({ offset: 0 }, page)).toEqual({ offset: 100, from: undefined });
    expect(nextTimelineCursor({ offset: 9_900 }, page)).toEqual({ offset: 10_000, from: undefined });
    expect(nextTimelineCursor({ offset: 10_000 }, page)).toEqual({ offset: 0, from: "2026-01-01T01:00:00Z" });
    // The same instant again (more than 10 000 rows at one time): stop.
    expect(nextTimelineCursor({ offset: 10_000, from: "2026-01-01T01:00:00Z" }, page)).toBeUndefined();
    expect(nextTimelineCursor({ offset: 0 }, { items: page.items, total: 2 })).toBeUndefined();
    expect(nextTimelineCursor({ offset: 0 }, { items: [], total: 9 })).toBeUndefined();
  });

  it("drops rows a time seek fetched again", () => {
    const a = item("2026-01-01T00:00:00Z");
    const b = item("2026-01-01T01:00:00Z");
    expect(mergeWindow([{ items: [a, b] }, { items: [b, item("2026-01-01T02:00:00Z")] }])).toHaveLength(3);
    // File rows of one file at the same instant but different time columns are distinct.
    const m = item("2026-01-01T00:00:00Z", { source: "file", kind: "mtime", file_id: "f", event_id: null });
    const c = item("2026-01-01T00:00:00Z", { source: "file", kind: "ctime", file_id: "f", event_id: null });
    expect(mergeWindow([{ items: [m, c] }])).toHaveLength(2);
  });
});

describe("histogram of the loaded window", () => {
  it("counts rows per hour and fills empty hours", () => {
    const { buckets, width } = hourHistogram([item("2026-01-01T00:10:00Z"), item("2026-01-01T00:50:00Z"), item("2026-01-01T03:05:00Z")]);
    expect(width).toBe(3_600_000);
    expect(buckets.map((b) => b.count)).toEqual([2, 0, 0, 1]);
  });

  it("groups a long span into at most maxBuckets buckets", () => {
    const { buckets, width } = hourHistogram([item("2026-01-01T00:00:00Z"), item("2026-01-31T00:00:00Z")], 24);
    expect(buckets.length).toBeLessThanOrEqual(24);
    expect(width % 3_600_000).toBe(0);
    expect(buckets.reduce((n, b) => n + b.count, 0)).toBe(2);
    expect(hourHistogram([]).buckets).toEqual([]);
    expect(hourHistogram([item("not a date")]).buckets).toEqual([]);
  });
});

describe("range helpers", () => {
  it("round-trips datetime-local values", () => {
    const iso = localInputToIso("2026-03-04T05:06");
    expect(iso).toMatch(/^2026-03-0\dT\d\d:06:00\.000Z$/);
    expect(isoToLocalInput(iso)).toBe("2026-03-04T05:06");
    expect(localInputToIso("")).toBeUndefined();
    expect(isoToLocalInput("nope")).toBe("");
  });

  it("detects inverted ranges and builds a window around an instant", () => {
    expect(invalidRange("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")).toBe(true);
    expect(invalidRange("2026-01-01T00:00:00Z", undefined)).toBe(false);
    expect(aroundInstant("2026-01-01T12:00:00Z", 30)).toEqual({ from: "2026-01-01T11:30:00.000Z", to: "2026-01-01T12:30:00.000Z" });
    expect(aroundInstant("x")).toBeNull();
  });

  it("labels kinds", () => {
    expect(kindLabel({ source: "file", kind: "crtime" })).toBe("Created (B)");
    expect(kindLabel({ source: "event", kind: "auth_log" })).toBe("Authentication log");
    expect(kindLabel({ source: "event", kind: "new_thing" })).toBe("new thing");
  });
});
