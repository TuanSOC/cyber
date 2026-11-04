"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import {
  ALL,
  CopyButton,
  FilterSelect,
  PAGE_SIZE,
  ResultTable,
  Trunc,
  When,
  usePageOffset,
} from "@/components/analysis/result-parts";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { TableCell, TableHead, TableRow } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { IOC_TYPE_LABELS, type IocType, formatCount, searchTerm } from "@/lib/pcap-results";
import { useDebounced } from "@/lib/use-debounced";

const COLUMNS = 6;
const TYPE_OPTIONS = Object.entries(IOC_TYPE_LABELS) as [IocType, string][];

/**
 * Observables seen in the capture or sample. Values are attacker-controlled (a "url" may be anything,
 * e.g. `javascript:`): shown as text with a copy button, never as a link.
 */
export function IocsTab({
  orgId,
  jobId,
  source = "capture",
}: {
  orgId: string;
  jobId: string;
  /** What the observables were extracted from ("capture", "file"). */
  source?: string;
}) {
  const [type, setType] = useState<IocType | typeof ALL>(ALL);
  const [search, setSearch] = useState("");
  const q = searchTerm(useDebounced(search));
  const filters = { type: type === ALL ? undefined : type, q };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = { ...filters, limit: PAGE_SIZE, offset };

  const iocs = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "iocs", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/iocs", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <ResultTable
      query={iocs}
      offset={offset}
      onOffset={setOffset}
      columns={COLUMNS}
      empty={type !== ALL || q ? "No IOCs match these filters." : "No observables recorded."}
      note={
        <p className="text-xs text-muted-foreground">
          Observables extracted from the {source}, without reputation or enrichment. Values are copied, never opened.
        </p>
      }
      filters={
        <>
          <FilterSelect
            value={type}
            onChange={setType}
            options={TYPE_OPTIONS}
            allLabel="All types"
            label="IOC type filter"
            className="w-44"
          />
          <Input
            className="w-72"
            type="search"
            placeholder="Search values"
            aria-label="Search IOC values"
            maxLength={200}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </>
      }
      head={
        <>
          <TableHead className="w-32">Type</TableHead>
          <TableHead>Value</TableHead>
          <TableHead className="w-20 text-right">Count</TableHead>
          <TableHead className="w-40">First seen</TableHead>
          <TableHead className="w-40">Last seen</TableHead>
          <TableHead className="w-24">Source</TableHead>
        </>
      }
    >
      {(items) =>
        items.map((ioc) => (
          <TableRow key={ioc.id}>
            <TableCell>
              <Badge variant="outline">{IOC_TYPE_LABELS[ioc.type] ?? ioc.type}</Badge>
            </TableCell>
            <TableCell>
              <div className="flex max-w-[32rem] items-center gap-1">
                <Trunc value={ioc.value} mono className="max-w-none min-w-0 select-all" />
                <CopyButton value={ioc.value} label="Copy IOC value" />
              </div>
            </TableCell>
            <TableCell className="text-right tabular-nums">{formatCount(ioc.count)}</TableCell>
            <TableCell>
              <When iso={ioc.first_seen} />
            </TableCell>
            <TableCell>
              <When iso={ioc.last_seen} />
            </TableCell>
            <TableCell>
              <Trunc value={ioc.source} className="max-w-24" />
            </TableCell>
          </TableRow>
        ))
      }
    </ResultTable>
  );
}
