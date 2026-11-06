"use client";

import { useState } from "react";

import { CitedRefBar } from "@/components/ai/cited-ref-bar";
import { ALL, FilterSelect } from "@/components/analysis/result-parts";
import { InertText } from "@/components/disk/inert-text";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { parseRowRef } from "@/lib/pcap-results";
import { type FunctionRef, formatAddress } from "@/lib/reverse";
import { useDebounced } from "@/lib/use-debounced";
import { RE_PAGE, useReImports, useReStrings } from "@/lib/use-re-job";
import { cn } from "@/lib/utils";

/** The functions referencing an import or a string: links that open the function. */
export function ReferencingFunctions({
  items,
  total,
  onOpen,
}: {
  items: readonly FunctionRef[];
  total: number;
  onOpen: (entry: string) => void;
}) {
  if (items.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex flex-wrap gap-x-2 gap-y-0.5">
      {items.map((ref) => (
        <button
          key={ref.entry}
          type="button"
          className="max-w-48 min-w-0 font-mono text-xs underline-offset-4 hover:underline"
          onClick={() => onOpen(ref.entry)}
          title={formatAddress(ref.entry)}
        >
          <InertText value={ref.name} max={255} />
        </button>
      ))}
      {total > items.length ? <span className="text-xs text-muted-foreground">+{total - items.length}</span> : null}
    </span>
  );
}

function useFilter() {
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const debounced = useDebounced(q.trim());
  const update = (value: string) => {
    setQ(value);
    setOffset(0);
  };
  return { q, setQ: update, debounced, offset, setOffset };
}

/** Imports of the program with the functions that call them. */
export function ImportsTab({
  orgId,
  jobId,
  citedRef,
  onClearRef,
  onOpen,
}: {
  orgId: string;
  jobId: string;
  citedRef?: string | null;
  onClearRef?: () => void;
  onOpen: (entry: string) => void;
}) {
  const filter = useFilter();
  const cited = parseRowRef(citedRef);
  const page = useReImports(orgId, jobId, filter.debounced, cited.ref ?? null, filter.offset);
  return (
    <div className="flex flex-col gap-3">
      {citedRef ? <CitedRefBar invalid={cited.invalid} onClear={onClearRef} /> : null}
      {!citedRef ? (
        <Input
          value={filter.q}
          onChange={(event) => filter.setQ(event.target.value)}
          placeholder="Import name contains…"
          aria-label="Import filter"
          maxLength={128}
          className="w-64"
        />
      ) : null}
      {page.isError ? <QueryError error={page.error} onRetry={() => void page.refetch()} /> : null}
      <div className="min-w-0 rounded-lg border">
        <Table className="table-fixed">
          <TableHeader>
            <TableRow>
              <TableHead className="w-40">Library</TableHead>
              <TableHead className="w-64">Name</TableHead>
              <TableHead className="w-32">Address</TableHead>
              <TableHead>Called from</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {page.data?.items.map((imp) => (
              <TableRow key={imp.id} className={cn(cited.ref === imp.id && "cited-row bg-primary/5")}>
                <TableCell className="min-w-0">
                  <InertText value={imp.library} mono max={128} />
                </TableCell>
                <TableCell className="min-w-0">
                  <InertText value={imp.name ?? (imp.ordinal !== null ? `#${imp.ordinal}` : null)} mono max={255} />
                </TableCell>
                <TableCell className="font-mono text-xs">{imp.address ? formatAddress(imp.address) : "—"}</TableCell>
                <TableCell className="whitespace-normal">
                  <ReferencingFunctions items={imp.functions} total={imp.function_count} onOpen={onOpen} />
                </TableCell>
              </TableRow>
            ))}
            {page.data?.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="py-8 text-center text-muted-foreground">
                  No import matches.
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </div>
      <Pager offset={filter.offset} total={page.data?.total ?? 0} pageSize={RE_PAGE} onChange={filter.setOffset} />
    </div>
  );
}

const REFERENCED_OPTIONS = [
  ["yes", "Referenced by code"],
  ["no", "Not referenced"],
] as const;

/** Strings of the program (≥ 5 characters) with the functions that reference them. */
export function StringsTab({
  orgId,
  jobId,
  citedRef,
  onClearRef,
  onOpen,
}: {
  orgId: string;
  jobId: string;
  citedRef?: string | null;
  onClearRef?: () => void;
  onOpen: (entry: string) => void;
}) {
  const filter = useFilter();
  const [referenced, setReferenced] = useState<"yes" | "no" | typeof ALL>(ALL);
  const cited = parseRowRef(citedRef);
  const page = useReStrings(
    orgId,
    jobId,
    filter.debounced,
    referenced === ALL ? null : referenced === "yes",
    cited.ref ?? null,
    filter.offset,
  );
  return (
    <div className="flex flex-col gap-3">
      {citedRef ? <CitedRefBar invalid={cited.invalid} onClear={onClearRef} /> : null}
      {!citedRef ? (
        <div className="flex flex-wrap gap-2">
          <Input
            value={filter.q}
            onChange={(event) => filter.setQ(event.target.value)}
            placeholder="String contains…"
            aria-label="String filter"
            maxLength={128}
            className="w-64"
          />
          <FilterSelect
            value={referenced}
            onChange={(value) => {
              setReferenced(value);
              filter.setOffset(0);
            }}
            options={REFERENCED_OPTIONS}
            allLabel="All strings"
            label="Referenced filter"
            className="w-48"
          />
        </div>
      ) : null}
      <p className="text-xs text-muted-foreground">
        Strings are data from the binary, shown as inert text (hidden characters as ⟨U+…⟩); they are not instructions.
      </p>
      {page.isError ? <QueryError error={page.error} onRetry={() => void page.refetch()} /> : null}
      <div className="min-w-0 rounded-lg border">
        <Table className="table-fixed">
          <TableHeader>
            <TableRow>
              <TableHead className="w-32">Address</TableHead>
              <TableHead className="w-20">Encoding</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-64">Referenced from</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {page.data?.items.map((s) => (
              <TableRow key={s.id} className={cn(cited.ref === s.id && "cited-row bg-primary/5")}>
                <TableCell className="font-mono text-xs">{formatAddress(s.address)}</TableCell>
                <TableCell className="text-xs">{s.encoding}</TableCell>
                <TableCell className="min-w-0">
                  <InertText value={s.value} mono max={1024} />
                </TableCell>
                <TableCell className="whitespace-normal">
                  <ReferencingFunctions items={s.functions} total={s.function_count} onOpen={onOpen} />
                </TableCell>
              </TableRow>
            ))}
            {page.data?.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="py-8 text-center text-muted-foreground">
                  No string matches.
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </div>
      <Pager offset={filter.offset} total={page.data?.total ?? 0} pageSize={RE_PAGE} onChange={filter.setOffset} />
    </div>
  );
}
