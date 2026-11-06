"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";

import { CITED_ROW, CitedRefBar, useScrollToCited } from "@/components/ai/cited-ref-bar";
import { PAGE_SIZE, ResultTable, Trunc, When, usePageOffset } from "@/components/analysis/result-parts";
import { ProcessFlags } from "@/components/memory/process-flags";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import {
  EMPTY_FLAGS,
  type FlagContext,
  type MemoryProcess,
  TREE_MAX_NODES,
  type TreeRow,
  buildProcessTree,
  flagContext,
  flattenTree,
  processFlags,
  searchKeep,
} from "@/lib/memory";
import { citedQuery, formatCount, parseRowRef, searchTerm } from "@/lib/pcap-results";
import { useAllProcesses, useFlagSources } from "@/lib/use-memory-job";
import { useDebounced } from "@/lib/use-debounced";
import { cn } from "@/lib/utils";

const COLUMNS = 7;
/** Tree rows rendered per page (the tree itself is held in memory, at most 5 000 nodes). */
export const TREE_ROWS_PER_PAGE = 200;

function ProcessHead() {
  return (
    <>
      <TableHead>Process</TableHead>
      <TableHead className="w-20">PPID</TableHead>
      <TableHead className="w-48">Observations</TableHead>
      <TableHead className="w-40">Started</TableHead>
      <TableHead className="w-20 text-right">Threads</TableHead>
      <TableHead className="w-28">Seen by</TableHead>
      <TableHead>Command line</TableHead>
    </>
  );
}

function ProcessCells({ p, flags }: { p: MemoryProcess; flags: FlagContext }) {
  return (
    <>
      <TableCell>
        <ProcessFlags flags={processFlags(p, flags)} />
      </TableCell>
      <TableCell>
        <When iso={p.create_time} />
      </TableCell>
      <TableCell className="text-right tabular-nums">{formatCount(p.threads)}</TableCell>
      <TableCell className="text-xs text-muted-foreground">{p.sources.join(", ")}</TableCell>
      <TableCell>
        <Trunc value={p.cmdline} mono className="max-w-[28rem]" />
      </TableCell>
    </>
  );
}

function NameButton({ p, onSelect }: { p: MemoryProcess; onSelect: (pid: number) => void }) {
  return (
    <button
      type="button"
      className="min-w-0 truncate text-left underline-offset-4 hover:underline"
      title={`Show pid ${p.pid}`}
      onClick={() => onSelect(p.pid)}
    >
      <span className="tabular-nums text-muted-foreground">{p.pid}</span> <span>{p.name}</span>
    </button>
  );
}

/** One row of the tree: indentation by depth, a disclosure button when it has children. */
export function TreeRowView({
  row,
  flags,
  onToggle,
  onSelect,
}: {
  row: TreeRow;
  flags: FlagContext;
  onToggle: (id: string) => void;
  onSelect: (pid: number) => void;
}) {
  const p = row.node.process;
  return (
    <TableRow aria-level={row.depth + 1} aria-expanded={row.hasChildren ? row.expanded : undefined}>
      <TableCell>
        <div className="flex min-w-0 items-center gap-1" style={{ paddingLeft: `${Math.min(row.depth, 24) * 1.25}rem` }}>
          {row.hasChildren ? (
            <Button
              variant="ghost"
              size="icon"
              className="size-6 shrink-0"
              aria-expanded={row.expanded}
              aria-label={`${row.expanded ? "Collapse" : "Expand"} ${p.name} (${p.pid})`}
              onClick={() => onToggle(p.id)}
            >
              {row.expanded ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
            </Button>
          ) : (
            <span className="inline-block size-6 shrink-0" aria-hidden />
          )}
          <NameButton p={p} onSelect={onSelect} />
        </div>
      </TableCell>
      <TableCell className="tabular-nums">
        {p.ppid ?? "—"}
        {row.node.parentMissing ? <span className="ml-1 text-xs text-muted-foreground" title="No process with this pid is in the image">(not in image)</span> : null}
        {row.node.cycle ? <span className="ml-1 text-xs text-muted-foreground" title="This parent link closed a loop and was cut">(loop)</span> : null}
      </TableCell>
      <ProcessCells p={p} flags={flags} />
    </TableRow>
  );
}

/** The process tree (client-built from every row, ≤ 5 000), searchable and collapsible. */
export function ProcessTree({
  processes,
  flags,
  query,
  onSelect,
}: {
  processes: readonly MemoryProcess[];
  flags: FlagContext;
  query: string;
  onSelect: (pid: number) => void;
}) {
  const roots = useMemo(() => buildProcessTree(processes), [processes]);
  const keep = useMemo(() => searchKeep(roots, query), [roots, query]);
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set());
  const [offset, setOffset] = usePageOffset(query);
  const rows = flattenTree(roots, keep ? new Set() : collapsed, keep);
  const toggle = (id: string) =>
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="ghost" disabled={Boolean(keep)} onClick={() => setCollapsed(new Set())}>
          Expand all
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={Boolean(keep)}
          onClick={() => setCollapsed(new Set(roots.map((root) => root.process.id)))}
        >
          Collapse all
        </Button>
      </div>
      <div className="min-w-0 rounded-lg border">
        <Table role="treegrid" aria-label="Process tree">
          <TableHeader>
            <TableRow>
              <ProcessHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.slice(offset, offset + TREE_ROWS_PER_PAGE).map((row) => (
              <TreeRowView key={row.node.process.id} row={row} flags={flags} onToggle={toggle} onSelect={onSelect} />
            ))}
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={COLUMNS} className="py-10 text-center text-muted-foreground">
                  {query ? "No process matches this search." : "No processes were recovered from this image."}
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </div>
      <Pager offset={offset} total={rows.length} pageSize={TREE_ROWS_PER_PAGE} onChange={setOffset} />
    </div>
  );
}

function ProcessList({
  orgId,
  jobId,
  q,
  flags,
  citedRef,
  onClearRef,
  onSelect,
}: {
  orgId: string;
  jobId: string;
  q: string | undefined;
  flags: FlagContext;
  citedRef?: string | null;
  onClearRef?: () => void;
  onSelect: (pid: number) => void;
}) {
  const cited = parseRowRef(citedRef);
  const [hiddenOnly, setHiddenOnly] = useState(false);
  const filters = { q, hidden: hiddenOnly ? true : undefined };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = citedQuery(cited.ref, filters, { limit: PAGE_SIZE, offset });
  const rows = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "memory", "processes", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/processes", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  useScrollToCited(Boolean(cited.ref), rows.isSuccess);
  return (
    <ResultTable
      query={rows}
      offset={cited.ref ? 0 : offset}
      onOffset={setOffset}
      columns={COLUMNS}
      empty={q || hiddenOnly ? "No process matches these filters." : "No processes were recovered from this image."}
      note={(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
      filters={
        cited.ref ? undefined : (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={hiddenOnly} onChange={(event) => setHiddenOnly(event.target.checked)} />
            Only processes not in the active list
          </label>
        )
      }
      head={<ProcessHead />}
    >
      {(items) =>
        items.map((p) => (
          <TableRow key={p.id} className={cn(p.id === cited.ref && CITED_ROW)}>
            <TableCell>
              <NameButton p={p} onSelect={onSelect} />
            </TableCell>
            <TableCell className="tabular-nums">{p.ppid ?? "—"}</TableCell>
            <ProcessCells p={p} flags={flags} />
          </TableRow>
        ))
      }
    </ResultTable>
  );
}

/** Per-pid observation flags from the first page of findings and memory regions. */
export function useProcessFlags(orgId: string, jobId: string): { flags: FlagContext; partial: boolean } {
  const sources = useFlagSources(orgId, jobId, true);
  const flags = useMemo(
    () =>
      sources.findings.data || sources.injections.data
        ? flagContext(sources.findings.data?.items ?? [], sources.injections.data?.items ?? [])
        : EMPTY_FLAGS,
    [sources.findings.data, sources.injections.data],
  );
  const partial = (sources.findings.data?.total ?? 0) > 100 || (sources.injections.data?.total ?? 0) > 100;
  return { flags, partial };
}

/**
 * Processes: tree or list, with observation flags (not in the active list / exited / private
 * executable region / unusual parent), a search inside this job, and a side panel per process.
 * Above 5 000 processes the tree is not built and the list is shown.
 */
export function ProcessesTab({
  orgId,
  jobId,
  citedRef,
  onClearRef,
  onSelect,
}: {
  orgId: string;
  jobId: string;
  citedRef?: string | null;
  onClearRef?: () => void;
  /** Opens the side panel of a pid (owned by the results view, shared with the Network tab). */
  onSelect: (pid: number) => void;
}) {
  const [view, setView] = useState<"tree" | "list">("tree");
  const [search, setSearch] = useState("");
  const q = searchTerm(useDebounced(search));
  const forcedList = Boolean(citedRef);
  const all = useAllProcesses(orgId, jobId, view === "tree" && !forcedList);
  const capped = all.data?.capped ?? false;
  const shown = forcedList || capped ? "list" : view;
  const { flags, partial: flagsPartial } = useProcessFlags(orgId, jobId);

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1" role="group" aria-label="Process view">
          {(["tree", "list"] as const).map((value) => (
            <Button
              key={value}
              size="sm"
              variant={shown === value ? "secondary" : "ghost"}
              aria-pressed={shown === value}
              disabled={value === "tree" && (capped || forcedList)}
              onClick={() => setView(value)}
            >
              {value === "tree" ? "Tree" : "List"}
            </Button>
          ))}
        </div>
        {!forcedList ? (
          <Input
            className="w-72"
            type="search"
            placeholder="Search name, pid or command line"
            aria-label="Search processes in this job"
            maxLength={128}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        ) : null}
      </div>
      {capped ? (
        <p className="text-xs text-muted-foreground">
          This image has more than {formatCount(TREE_MAX_NODES)} processes, so the tree is not built; the list shows every
          one, page by page.
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        Observations describe what the image shows; they are leads to review, not verdicts.
        {flagsPartial ? " Flags reflect the first 100 findings and memory regions." : ""}
      </p>
      {shown === "tree" ? (
        all.isError ? (
          <QueryError error={all.error} onRetry={() => void all.refetch()} />
        ) : all.data ? (
          <ProcessTree processes={all.data.items} flags={flags} query={q ?? ""} onSelect={onSelect} />
        ) : (
          <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">Loading the process tree…</p>
        )
      ) : (
        <ProcessList
          orgId={orgId}
          jobId={jobId}
          q={q}
          flags={flags}
          citedRef={citedRef}
          onClearRef={onClearRef}
          onSelect={onSelect}
        />
      )}
    </div>
  );
}
