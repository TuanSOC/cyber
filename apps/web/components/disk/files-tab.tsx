"use client";

import { ChevronDown, ChevronRight, Folder, HardDrive } from "lucide-react";
import { useId, useMemo, useState } from "react";

import { CitedRefBar } from "@/components/ai/cited-ref-bar";
import { ALL, FilterSelect } from "@/components/analysis/result-parts";
import { FILE_ROW_HEIGHT, FileHeader, FileRow } from "@/components/disk/file-row";
import { InertText } from "@/components/disk/inert-text";
import { WindowedRows } from "@/components/disk/windowed-rows";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DISK_EXPORT_MAX_FILES,
  DISK_MAX_OFFSET,
  type DiskFile,
  type DiskPartition,
  FILE_FLAG_FILTERS,
  type FileFilters,
  type FileFlagFilter,
  HIDE_KNOWN_HINT,
  HIDE_KNOWN_LABEL,
  MAGIC_FILTERS,
  type MagicFilter,
  extTerm,
  fileQuery,
  hashTerm,
  pastOffsetCap,
} from "@/lib/disk";
import { localInputToIso } from "@/lib/disk-timeline";
import { formatCount, parseRowRef } from "@/lib/pcap-results";
import { useDebounced } from "@/lib/use-debounced";
import { useDiskDir, useDiskFiles, useDiskPartitions } from "@/lib/use-disk-job";
import { cn } from "@/lib/utils";

const VIEWPORT = 560;

export type DirSelection = { partition: number; parent: string | null; path: string };

/** One directory of the lazy tree: its subdirectories load when it is expanded. */
function DirNode({
  orgId,
  jobId,
  partition,
  addr,
  name,
  path,
  depth,
  selected,
  onSelect,
}: {
  orgId: string;
  jobId: string;
  partition: number;
  addr: string | null;
  name: string;
  path: string;
  depth: number;
  selected: DirSelection | null;
  onSelect: (dir: DirSelection) => void;
}) {
  const [open, setOpen] = useState(false);
  const dir = useDiskDir(orgId, jobId, partition, addr, open);
  const children = (dir.data?.pages ?? []).flatMap((page) => page.items).filter((f) => f.type === "dir" && f.name !== "." && f.name !== "..");
  const isSelected = selected?.partition === partition && selected.parent === addr;
  return (
    <li role="treeitem" aria-expanded={open} aria-selected={isSelected}>
      <div className="flex items-center gap-0.5" style={{ paddingLeft: depth * 12 }}>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-6 shrink-0"
          aria-label={open ? `Collapse ${name}` : `Expand ${name}`}
          onClick={() => setOpen(!open)}
        >
          {open ? <ChevronDown className="size-3.5" aria-hidden /> : <ChevronRight className="size-3.5" aria-hidden />}
        </Button>
        <button
          type="button"
          className={cn("flex min-w-0 flex-1 items-center gap-1 rounded px-1 py-0.5 text-left text-xs hover:bg-muted/60", isSelected && "bg-muted font-medium")}
          onClick={() => onSelect({ partition, parent: addr, path })}
        >
          {depth === 0 ? <HardDrive className="size-3.5 shrink-0" aria-hidden /> : <Folder className="size-3.5 shrink-0" aria-hidden />}
          <InertText value={name} />
        </button>
      </div>
      {open ? (
        <ul role="group">
          {dir.isError ? (
            <li className="pl-8 text-xs text-destructive">Could not list this directory.</li>
          ) : dir.isPending ? (
            <li className="pl-8 text-xs text-muted-foreground">Loading…</li>
          ) : (
            children.map((child) => (
              <DirNode
                key={child.id}
                orgId={orgId}
                jobId={jobId}
                partition={partition}
                addr={child.meta_addr}
                name={child.name}
                path={child.path}
                depth={depth + 1}
                selected={selected}
                onSelect={onSelect}
              />
            ))
          )}
          {dir.hasNextPage ? (
            <li style={{ paddingLeft: (depth + 1) * 12 + 24 }}>
              <Button type="button" variant="link" size="sm" className="h-6 px-0 text-xs" onClick={() => void dir.fetchNextPage()}>
                More entries…
              </Button>
            </li>
          ) : null}
        </ul>
      ) : null}
    </li>
  );
}

/** The directory tree: one root per partition with a listed file system. */
export function DirTree({
  orgId,
  jobId,
  partitions,
  selected,
  onSelect,
}: {
  orgId: string;
  jobId: string;
  partitions: readonly DiskPartition[];
  selected: DirSelection | null;
  onSelect: (dir: DirSelection | null) => void;
}) {
  const listed = partitions.filter((p) => p.fs_status === "ok" || p.fs_status === "truncated");
  return (
    <nav aria-label="Directories" className="flex flex-col gap-1">
      <button
        type="button"
        className={cn("rounded px-2 py-1 text-left text-xs hover:bg-muted/60", selected === null && "bg-muted font-medium")}
        onClick={() => onSelect(null)}
      >
        All files (filters)
      </button>
      {listed.length === 0 ? <p className="px-2 text-xs text-muted-foreground">No file system was listed.</p> : null}
      <ul role="tree" aria-label="Partitions and directories" className="flex flex-col">
        {listed.map((p) => (
          <DirNode
            key={p.id}
            orgId={orgId}
            jobId={jobId}
            partition={p.index}
            addr={null}
            name={`Partition ${p.index}${p.fs_type ? ` (${p.fs_type})` : ""}${p.fs_label ? ` ${p.fs_label}` : ""}`}
            path="/"
            depth={0}
            selected={selected}
            onSelect={onSelect}
          />
        ))}
      </ul>
    </nav>
  );
}

type Draft = {
  q: string;
  partition: string;
  flag: FileFlagFilter | typeof ALL;
  magic: MagicFilter | typeof ALL;
  hash: string;
  ext: string;
  from: string;
  to: string;
  hideKnown: boolean;
};

const EMPTY: Draft = { q: "", partition: ALL, flag: ALL, magic: ALL, hash: "", ext: "", from: "", to: "", hideKnown: true };

/** The draft filter inputs as the API's filters (invalid hash / range values dropped). */
export function draftFilters(draft: Draft): { filters: FileFilters; hashInvalid: boolean } {
  const hash = draft.hash.trim();
  const partition = draft.partition === ALL ? undefined : Number(draft.partition);
  return {
    filters: {
      q: draft.q.trim() || undefined,
      partition: Number.isInteger(partition) ? partition : undefined,
      flag: draft.flag === ALL ? undefined : draft.flag,
      magic: draft.magic === ALL ? undefined : draft.magic,
      hash: hash && hashTerm(hash) ? hash : undefined,
      ext: extTerm(draft.ext),
      from: localInputToIso(draft.from),
      to: localInputToIso(draft.to),
      hideKnown: draft.hideKnown,
    },
    hashInvalid: hash !== "" && hashTerm(hash) === null,
  };
}

function useFileFilters() {
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const debounced = useDebounced(draft);
  const parsed = useMemo(() => draftFilters(debounced), [debounced]);
  return { draft, setDraft, ...parsed };
}

function FileFilterBar({
  draft,
  setDraft,
  partitions,
  hashInvalid,
}: {
  draft: Draft;
  setDraft: (draft: Draft) => void;
  partitions: readonly DiskPartition[];
  hashInvalid: boolean;
}) {
  const id = useId();
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft({ ...draft, [key]: value });
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          aria-label="Search in paths"
          placeholder="Path contains…"
          className="w-56"
          maxLength={128}
          value={draft.q}
          onChange={(e) => set("q", e.target.value)}
        />
        <Input
          aria-label="Hash (md5, sha1 or sha256)"
          aria-invalid={hashInvalid}
          placeholder="md5 / sha1 / sha256"
          className="w-64 font-mono text-xs"
          maxLength={64}
          value={draft.hash}
          onChange={(e) => set("hash", e.target.value)}
        />
        <Input
          aria-label="Extension"
          placeholder="Extension (exe)"
          className="w-36"
          maxLength={32}
          value={draft.ext}
          onChange={(e) => set("ext", e.target.value)}
        />
        <FilterSelect
          value={draft.partition}
          onChange={(v) => set("partition", v)}
          options={partitions.map((p) => [String(p.index), `Partition ${p.index}`] as const)}
          allLabel="All partitions"
          label="Partition filter"
          className="w-40"
        />
        <FilterSelect value={draft.flag} onChange={(v) => set("flag", v)} options={FILE_FLAG_FILTERS} allLabel="Any flag" label="Flag filter" />
        <FilterSelect value={draft.magic} onChange={(v) => set("magic", v)} options={MAGIC_FILTERS} allLabel="Any content type" label="Content type filter" />
      </div>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-1 text-xs" htmlFor={`${id}-from`}>
          Any time from
          <Input id={`${id}-from`} type="datetime-local" className="h-8 w-52" value={draft.from} onChange={(e) => set("from", e.target.value)} />
        </label>
        <label className="flex items-center gap-1 text-xs" htmlFor={`${id}-to`}>
          to
          <Input id={`${id}-to`} type="datetime-local" className="h-8 w-52" value={draft.to} onChange={(e) => set("to", e.target.value)} />
        </label>
        <label className="flex items-center gap-2 text-xs" htmlFor={`${id}-known`}>
          <input id={`${id}-known`} type="checkbox" checked={draft.hideKnown} onChange={(e) => set("hideKnown", e.target.checked)} />
          <span>
            {HIDE_KNOWN_LABEL} <span className="text-muted-foreground">({HIDE_KNOWN_HINT})</span>
          </span>
        </label>
        <Button type="button" variant="ghost" size="sm" onClick={() => setDraft(EMPTY)}>
          Reset
        </Button>
      </div>
      {hashInvalid ? <p className="text-xs text-destructive">A hash is 32 (md5), 40 (sha1) or 64 (sha256) hexadecimal characters.</p> : null}
    </div>
  );
}

function FileList({
  items,
  total,
  loading,
  error,
  onRetry,
  hasMore,
  onMore,
  onOpen,
  openId,
  label,
  listKey,
}: {
  items: readonly DiskFile[];
  total: number | null;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  hasMore: boolean;
  onMore: () => void;
  onOpen: (id: string) => void;
  openId: string | null;
  label: string;
  listKey: string;
}) {
  if (error) return <QueryError error={error} onRetry={onRetry} />;
  const capped = total !== null && pastOffsetCap(items.length, total);
  return (
    <WindowedRows
      key={listKey}
      label={label}
      items={items}
      rowHeight={FILE_ROW_HEIGHT}
      height={VIEWPORT}
      header={<FileHeader />}
      renderRow={(file) => <FileRow file={file} onOpen={onOpen} selected={file.id === openId} />}
      onNearEnd={hasMore ? onMore : undefined}
      footer={
        loading && items.length === 0
          ? "Loading…"
          : total === 0
            ? "No files match."
            : `${formatCount(items.length)} of ${formatCount(total ?? items.length)} loaded${hasMore ? " (more load as you scroll)" : ""}.${
                capped ? ` The list can page through ${formatCount(DISK_MAX_OFFSET)} rows: narrow the filters to see the rest.` : ""
              }`
      }
    />
  );
}

/**
 * The file browser: a lazy directory tree beside a windowed table. "All files" applies the
 * filters to `/files` (known files hidden by default, RT18); a directory lists `/dirs`. A row
 * opens the detail drawer (owned by the results component, shared with the export flow).
 */
export function FilesTab({
  orgId,
  jobId,
  citedRef,
  onClearRef,
  openId,
  onOpen,
  batch,
  onExportBatch,
  onClearBatch,
  exportPending,
}: {
  orgId: string;
  jobId: string;
  citedRef?: string | null;
  onClearRef?: () => void;
  openId: string | null;
  onOpen: (id: string) => void;
  batch: readonly string[];
  onExportBatch: () => void;
  onClearBatch: () => void;
  exportPending: boolean;
}) {
  const cited = parseRowRef(citedRef);
  const partitions = useDiskPartitions(orgId, jobId, true);
  const [dir, setDir] = useState<DirSelection | null>(null);
  const { draft, setDraft, filters, hashInvalid } = useFileFilters();
  const query = cited.ref ? { include_known: true, ref: cited.ref } : fileQuery(filters);
  const files = useDiskFiles(orgId, jobId, query, dir === null);
  const listing = useDiskDir(orgId, jobId, dir?.partition ?? null, dir?.parent ?? null, dir !== null);
  const pages: readonly { items: DiskFile[]; total: number }[] = (dir === null ? files.data?.pages : listing.data?.pages) ?? [];
  const items = pages.flatMap((page) => page.items);
  const total = pages[0]?.total ?? null;
  const active =
    dir === null
      ? { isPending: files.isPending, isError: files.isError, error: files.error, hasNextPage: files.hasNextPage, busy: files.isFetchingNextPage, refetch: files.refetch, more: files.fetchNextPage }
      : { isPending: listing.isPending, isError: listing.isError, error: listing.error, hasNextPage: listing.hasNextPage, busy: listing.isFetchingNextPage, refetch: listing.refetch, more: listing.fetchNextPage };
  const parts = partitions.data?.items ?? [];

  return (
    <div className="flex flex-col gap-3">
      {(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
      {dir === null && !cited.ref ? <FileFilterBar draft={draft} setDraft={setDraft} partitions={parts} hashInvalid={hashInvalid} /> : null}
      {batch.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-primary/40 bg-primary/5 p-2 text-sm" data-testid="export-batch">
          <span>
            {batch.length} of at most {DISK_EXPORT_MAX_FILES} files selected for export.
          </span>
          <Button type="button" size="sm" disabled={exportPending} onClick={onExportBatch}>
            {exportPending ? "Requesting…" : "Export selected"}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onClearBatch}>
            Clear
          </Button>
        </div>
      ) : null}
      <div className="grid gap-3 lg:grid-cols-[16rem_1fr]">
        <aside className="max-h-[640px] min-w-0 overflow-y-auto rounded-lg border p-2">
          {partitions.isError ? (
            <QueryError error={partitions.error} onRetry={() => void partitions.refetch()} />
          ) : (
            <DirTree orgId={orgId} jobId={jobId} partitions={parts} selected={dir} onSelect={setDir} />
          )}
        </aside>
        <div className="flex min-w-0 flex-col gap-2 overflow-x-auto">
          {dir ? (
            <p className="text-xs text-muted-foreground">
              Directory listing of partition {dir.partition}: <InertText value={dir.path} mono className="inline" /> (filters apply to
              “All files”).
            </p>
          ) : null}
          <div className="min-w-[56rem]">
            <FileList
              listKey={JSON.stringify([dir, query])}
              label={dir ? "Directory entries" : "Files"}
              items={items}
              total={total}
              loading={active.isPending}
              error={active.isError ? active.error : null}
              onRetry={() => void active.refetch()}
              hasMore={Boolean(active.hasNextPage)}
              onMore={() => {
                if (!active.busy) void active.more();
              }}
              onOpen={onOpen}
              openId={openId}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
