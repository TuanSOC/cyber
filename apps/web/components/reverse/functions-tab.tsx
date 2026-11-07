"use client";

import { useMemo, useState } from "react";

import { CitedRefBar } from "@/components/ai/cited-ref-bar";
import { ALL, FilterSelect } from "@/components/analysis/result-parts";
import { InertText } from "@/components/disk/inert-text";
import { WindowedRows } from "@/components/disk/windowed-rows";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { parseRowRef } from "@/lib/pcap-results";
import {
  DECOMPILE_LABELS,
  EMPTY_FILTERS,
  FUNCTION_SORT_LABELS,
  type FunctionFilters,
  type FunctionSort,
  type ReFunction,
  formatAddress,
  functionFlags,
  sortFunctions,
} from "@/lib/reverse";
import { useDebounced } from "@/lib/use-debounced";
import { RE_MAX_OFFSET, useReFunctions } from "@/lib/use-re-job";
import { cn } from "@/lib/utils";

const VIEWPORT = 520;
export const FUNCTION_ROW_HEIGHT = 36;
/** Columns of a function row and its header (fixed tracks; a 255-character name truncates). */
export const FUNCTION_GRID =
  "grid grid-cols-[9rem_minmax(8rem,1fr)_5.5rem_10rem_4.5rem_4.5rem_6.5rem] items-center gap-2 px-2";
const DECOMPILED_OPTIONS = [
  ["yes", "Decompiled"],
  ["no", "Not decompiled"],
] as const;
const SORT_OPTIONS = (Object.entries(FUNCTION_SORT_LABELS) as [FunctionSort, string][]).map(([v, l]) => [v, l] as const);

export function FunctionHeader() {
  return (
    <div role="row" className={cn(FUNCTION_GRID, "h-8 text-xs font-medium text-muted-foreground")}>
      <span role="columnheader">Address</span>
      <span role="columnheader">Name</span>
      <span role="columnheader" className="text-right">
        Size
      </span>
      <span role="columnheader">Decompiled</span>
      <span role="columnheader" className="text-right" title="Callers / callees">
        Calls
      </span>
      <span role="columnheader" className="text-right" title="Linked capa capabilities">
        Capa
      </span>
      <span role="columnheader" className="text-right" title="Decompile priority rank">
        Rank
      </span>
    </div>
  );
}

/** One function row: a button (keyboard: Tab to it, Enter / Space opens the function). */
export function FunctionRow({ fn, selected, cited, onOpen }: { fn: ReFunction; selected: boolean; cited: boolean; onOpen: (entry: string) => void }) {
  const flags = functionFlags(fn);
  return (
    <button
      type="button"
      role="row"
      aria-selected={selected}
      onClick={() => onOpen(fn.entry)}
      className={cn(
        FUNCTION_GRID,
        "h-9 w-full border-b text-left text-sm hover:bg-muted/40 focus-visible:bg-muted/60 focus-visible:outline-none",
        selected && "bg-primary/10",
        cited && "cited-row bg-primary/5 ring-1 ring-primary/40 ring-inset",
      )}
    >
      <span role="cell" className="font-mono text-xs">
        {formatAddress(fn.entry)}
      </span>
      <span role="cell" className="flex min-w-0 items-center gap-1">
        <InertText value={fn.name} mono className="min-w-0" max={255} />
        {flags.map((flag) => (
          <Badge key={flag} variant="outline" className="shrink-0 text-[10px] font-normal">
            {flag}
          </Badge>
        ))}
      </span>
      <span role="cell" className="text-right text-xs tabular-nums">
        {fn.size.toLocaleString("en-US")}
      </span>
      <span role="cell" className="truncate text-xs">
        {DECOMPILE_LABELS[fn.decompile_status] ?? fn.decompile_status}
      </span>
      <span role="cell" className="text-right text-xs text-muted-foreground tabular-nums">
        {fn.callers}/{fn.callees}
      </span>
      <span role="cell" className="text-right text-xs tabular-nums">
        {fn.capabilities || "—"}
      </span>
      <span role="cell" className="text-right text-xs text-muted-foreground tabular-nums">
        {fn.priority_rank ?? "—"}
      </span>
    </button>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="flex items-center gap-1.5 text-xs">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}

/**
 * Functions of an RE job: server-paginated (pages of 100 up to the API's offset cap) and
 * line-windowed, with the API's filters; the sort applies to the loaded rows (the API pages by
 * priority rank, then address). `?ref=<row id>` shows only the cited function.
 */
export function FunctionsTab({
  orgId,
  jobId,
  selected,
  citedRef,
  onClearRef,
  onOpen,
}: {
  orgId: string;
  jobId: string;
  selected: string | null;
  citedRef?: string | null;
  onClearRef?: () => void;
  onOpen: (entry: string) => void;
}) {
  const [filters, setFilters] = useState<FunctionFilters>(EMPTY_FILTERS);
  const [sort, setSort] = useState<FunctionSort>("rank");
  const debounced = useDebounced(filters);
  const cited = parseRowRef(citedRef);
  const pages = useReFunctions(orgId, jobId, debounced, cited.ref ?? null, !cited.invalid);
  const loaded = useMemo(() => (pages.data?.pages ?? []).flatMap((page) => page.items), [pages.data]);
  const rows = useMemo(() => sortFunctions(loaded, sort), [loaded, sort]);
  const total = pages.data?.pages[0]?.total ?? 0;
  const set = (patch: Partial<FunctionFilters>) => setFilters((current) => ({ ...current, ...patch }));

  return (
    <div className="flex flex-col gap-3">
      {citedRef ? <CitedRefBar invalid={cited.invalid} onClear={onClearRef} /> : null}
      {!citedRef ? (
        <div className="flex flex-wrap items-center gap-3">
          <Input
            value={filters.q}
            onChange={(event) => set({ q: event.target.value })}
            placeholder="Function name contains…"
            aria-label="Function name filter"
            maxLength={128}
            className="w-56"
          />
          <FilterSelect
            value={filters.decompiled === null ? ALL : filters.decompiled ? "yes" : "no"}
            onChange={(value) => set({ decompiled: value === ALL ? null : value === "yes" })}
            options={DECOMPILED_OPTIONS}
            allLabel="Decompiled or not"
            label="Decompiled filter"
            className="w-44"
          />
          <Toggle label="Has a capability" checked={filters.hasCapability} onChange={(v) => set({ hasCapability: v })} />
          <Toggle
            label="Calls a suspicious import"
            checked={filters.callsSuspiciousImport}
            onChange={(v) => set({ callsSuspiciousImport: v })}
          />
          <Toggle
            label="References an IOC string"
            checked={filters.referencesIocString}
            onChange={(v) => set({ referencesIocString: v })}
          />
          <Toggle label="Include library functions" checked={filters.includeLibrary} onChange={(v) => set({ includeLibrary: v })} />
          <FilterSelect
            value={sort}
            onChange={(value) => setSort(value === ALL ? "rank" : value)}
            options={SORT_OPTIONS}
            allLabel="Priority"
            label="Sort"
            className="w-36"
          />
        </div>
      ) : null}
      {pages.isError ? <QueryError error={pages.error} onRetry={() => void pages.refetch()} /> : null}
      <WindowedRows
        items={rows}
        rowHeight={FUNCTION_ROW_HEIGHT}
        height={Math.min(VIEWPORT, Math.max(rows.length, 3) * FUNCTION_ROW_HEIGHT)}
        label="Functions"
        header={<FunctionHeader />}
        renderRow={(fn) => (
          <FunctionRow fn={fn} selected={selected === fn.entry} cited={Boolean(cited.ref) && fn.id === cited.ref} onOpen={onOpen} />
        )}
        onNearEnd={pages.hasNextPage && !pages.isFetchingNextPage ? () => void pages.fetchNextPage() : undefined}
        footer={
          pages.isPending ? (
            "Loading functions…"
          ) : rows.length === 0 ? (
            "No function matches these filters."
          ) : (
            <>
              {rows.length.toLocaleString("en-US")} of {total.toLocaleString("en-US")} loaded
              {sort !== "rank" && rows.length < total ? " (sorted among the loaded rows)" : ""}
              {rows.length > RE_MAX_OFFSET ? " · narrow the filters to reach the rest" : ""}
            </>
          )
        }
      />
    </div>
  );
}
