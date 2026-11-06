"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { CITED_ROW, CitedRefBar, useScrollToCited } from "@/components/ai/cited-ref-bar";
import { PAGE_SIZE, ResultTable, Trunc, When, usePageOffset } from "@/components/analysis/result-parts";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { TableCell, TableHead, TableRow } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { type MemoryConnection, formatAddress } from "@/lib/memory";
import { citedQuery, endpointText, parseRowRef, searchTerm } from "@/lib/pcap-results";
import { useDebounced } from "@/lib/use-debounced";
import { cn } from "@/lib/utils";

const COLUMNS = 7;

export function ConnectionRow({
  c,
  cited,
  onShowProcess,
}: {
  c: MemoryConnection;
  cited?: boolean;
  onShowProcess?: (pid: number) => void;
}) {
  return (
    <TableRow className={cn(cited && CITED_ROW)}>
      <TableCell>
        <Badge variant="outline" className="uppercase">
          {c.proto}
        </Badge>
      </TableCell>
      <TableCell>
        <Trunc value={endpointText(c.local_addr, c.local_port)} mono className="max-w-56" />
      </TableCell>
      <TableCell>
        <Trunc value={c.remote_addr ? endpointText(c.remote_addr, c.remote_port) : null} mono className="max-w-56" />
      </TableCell>
      <TableCell>
        <Trunc value={c.state} className="max-w-32" />
      </TableCell>
      <TableCell className="tabular-nums">
        {c.pid !== null && onShowProcess ? (
          <button type="button" className="underline underline-offset-4" onClick={() => onShowProcess(c.pid as number)}>
            {c.pid}
          </button>
        ) : (
          (c.pid ?? "—")
        )}
        {c.owner ? <Trunc value={c.owner} className="max-w-40 text-xs text-muted-foreground" /> : null}
      </TableCell>
      <TableCell>
        <When iso={c.created} />
      </TableCell>
      <TableCell className="font-mono text-xs text-muted-foreground">{formatAddress(c.offset)}</TableCell>
    </TableRow>
  );
}

export const CONNECTION_HEAD = (
  <>
    <TableHead className="w-20">Proto</TableHead>
    <TableHead>Local</TableHead>
    <TableHead>Remote</TableHead>
    <TableHead className="w-32">State</TableHead>
    <TableHead className="w-40">Process</TableHead>
    <TableHead className="w-44">Created</TableHead>
    <TableHead className="w-44">Offset</TableHead>
  </>
);

/** Sockets and connections recovered from the image (addresses are analyzer output, as text). */
export function NetworkTab({
  orgId,
  jobId,
  citedRef,
  onClearRef,
  onShowProcess,
}: {
  orgId: string;
  jobId: string;
  citedRef?: string | null;
  onClearRef?: () => void;
  onShowProcess?: (pid: number) => void;
}) {
  const cited = parseRowRef(citedRef);
  const [search, setSearch] = useState("");
  const q = searchTerm(useDebounced(search));
  const [offset, setOffset] = usePageOffset(q ?? "");
  const query = citedQuery(cited.ref, { q }, { limit: PAGE_SIZE, offset });
  const rows = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "memory", "connections", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/connections", {
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
      empty={q ? "No connections match this search." : "No sockets or connections were recovered from this image."}
      note={(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
      filters={
        cited.ref ? undefined : (
          <Input
            className="w-72"
            type="search"
            placeholder="Search addresses or process"
            aria-label="Search connections"
            maxLength={128}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        )
      }
      head={CONNECTION_HEAD}
    >
      {(items) =>
        items.map((c) => <ConnectionRow key={c.id} c={c} cited={c.id === cited.ref} onShowProcess={onShowProcess} />)
      }
    </ResultTable>
  );
}
