"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { CITED_ROW, CitedRefBar, useScrollToCited } from "@/components/ai/cited-ref-bar";
import { ExpandableRow, PAGE_SIZE, ResultTable, Trunc, usePageOffset } from "@/components/analysis/result-parts";
import { Badge } from "@/components/ui/badge";
import { TableCell, TableHead } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { type MemoryInjection, formatAddress, hexDumpLines } from "@/lib/memory";
import { citedQuery, formatCount, parseRowRef } from "@/lib/pcap-results";

const COLUMNS = 8;

/**
 * The first bytes and the disassembly of a region, as monospace text in `<pre>` (never HTML,
 * never executed or decoded further).
 */
export function RegionBytes({ region }: { region: Pick<MemoryInjection, "head_hex" | "disasm"> }) {
  const dump = hexDumpLines(region.head_hex);
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <div className="min-w-0">
        <p className="mb-1 text-xs text-muted-foreground">First bytes (hex)</p>
        {dump.length > 0 ? (
          <pre className="overflow-x-auto rounded-md border bg-muted/40 p-2 font-mono text-xs" data-testid="region-hex">
            {dump.join("\n")}
          </pre>
        ) : (
          <p className="text-xs text-muted-foreground">—</p>
        )}
      </div>
      <div className="min-w-0">
        <p className="mb-1 text-xs text-muted-foreground">Disassembly</p>
        {region.disasm ? (
          <pre className="max-h-72 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs" data-testid="region-disasm">
            {region.disasm}
          </pre>
        ) : (
          <p className="text-xs text-muted-foreground">—</p>
        )}
      </div>
    </div>
  );
}

export function RegionRow({ region, cited }: { region: MemoryInjection; cited?: boolean }) {
  return (
    <ExpandableRow
      columns={COLUMNS}
      className={cited ? CITED_ROW : undefined}
      cells={
        <>
          <TableCell className="tabular-nums">{region.pid}</TableCell>
          <TableCell>
            <Trunc value={region.process} className="max-w-40" />
          </TableCell>
          <TableCell className="font-mono text-xs">
            {formatAddress(region.start)}–{formatAddress(region.end)}
          </TableCell>
          <TableCell>
            <Trunc value={region.protection} mono className="max-w-48" />
          </TableCell>
          <TableCell>
            <Trunc value={region.tag} mono className="max-w-20" />
          </TableCell>
          <TableCell>
            <span className="inline-flex flex-wrap gap-1">
              {region.private ? <Badge variant="secondary">private</Badge> : null}
              {region.has_pe ? <Badge variant="secondary">PE header</Badge> : null}
            </span>
          </TableCell>
          <TableCell className="text-right tabular-nums">{formatCount(region.commit_charge)}</TableCell>
        </>
      }
      detail={<RegionBytes region={region} />}
    />
  );
}

/**
 * Private executable memory regions (malfind). Common in JIT hosts (browsers, .NET): an
 * observation to review, not a verdict.
 */
export function RegionsTab({
  orgId,
  jobId,
  pid,
  citedRef,
  onClearRef,
}: {
  orgId: string;
  jobId: string;
  pid?: number;
  citedRef?: string | null;
  onClearRef?: () => void;
}) {
  const cited = parseRowRef(citedRef);
  const [offset, setOffset] = usePageOffset(String(pid ?? ""));
  const query = citedQuery(cited.ref, { pid }, { limit: PAGE_SIZE, offset });
  const rows = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "memory", "injections", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/injections", {
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
      empty="No private executable memory regions were reported."
      note={
        <div className="flex flex-col gap-1">
          {(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
          <p className="text-xs text-muted-foreground">
            Private memory with execute permission. Just-in-time compilers (browsers, .NET, Java) create such regions
            too: each one is a lead to review, not a verdict. Bytes are shown as text only.
          </p>
        </div>
      }
      head={
        <>
          <TableHead className="w-8" />
          <TableHead className="w-20">PID</TableHead>
          <TableHead>Process</TableHead>
          <TableHead>Range</TableHead>
          <TableHead>Protection</TableHead>
          <TableHead className="w-20">Tag</TableHead>
          <TableHead className="w-40">Markers</TableHead>
          <TableHead className="w-24 text-right">Pages</TableHead>
        </>
      }
    >
      {(items) => items.map((region) => <RegionRow key={region.id} region={region} cited={region.id === cited.ref} />)}
    </ResultTable>
  );
}
