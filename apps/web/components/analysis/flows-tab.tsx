"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { useState } from "react";

import {
  ALL,
  FilterSelect,
  PAGE_SIZE,
  ResultTable,
  Trunc,
  When,
  usePageOffset,
} from "@/components/analysis/result-parts";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TableCell, TableHead, TableRow } from "@/components/ui/table";
import { formatDuration } from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import {
  type FlowProto,
  type FlowSort,
  endpointText,
  formatCount,
  parseIpFilter,
  parsePortFilter,
} from "@/lib/pcap-results";
import { cn } from "@/lib/utils";
import { useDebounced } from "@/lib/use-debounced";

const COLUMNS = 9;
const PROTO_OPTIONS = [
  ["tcp", "TCP"],
  ["udp", "UDP"],
  ["icmp", "ICMP"],
  ["other", "Other"],
] as const;

/**
 * Flows with ip / port / proto filters. The ip and port filters mirror the URL (`ip`, `port`)
 * so a link from a finding or alert is shareable; `ref` (a Zeek uid) is only highlighted,
 * because the API cannot filter flows by uid.
 */
export function FlowsTab({
  orgId,
  jobId,
  initialIp,
  initialPort,
  highlightRef,
  onUrlChange,
}: {
  orgId: string;
  jobId: string;
  initialIp: string;
  initialPort: string;
  highlightRef: string | null;
  onUrlChange: (updates: Record<string, string | undefined>) => void;
}) {
  const [ipText, setIpText] = useState(initialIp);
  const [portText, setPortText] = useState(initialPort);
  const [proto, setProto] = useState<FlowProto | typeof ALL>(ALL);
  const [sort, setSort] = useState<FlowSort>("bytes");
  const ip = parseIpFilter(useDebounced(ipText));
  const port = parsePortFilter(useDebounced(portText));

  const filters = { ip: ip.ip, port: port.port, proto: proto === ALL ? undefined : proto, sort };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = { ...filters, limit: PAGE_SIZE, offset };

  const flows = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "flows", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/flows", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  const filtered = Boolean(filters.ip || filters.port !== undefined || filters.proto);
  const highlightedHere = Boolean(highlightRef && flows.data?.items.some((f) => f.flow_ref === highlightRef));

  return (
    <ResultTable
      query={flows}
      offset={offset}
      onOffset={setOffset}
      columns={COLUMNS}
      empty={filtered ? "No flows match these filters." : "No flows recorded."}
      note={
        highlightRef && (
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-primary/40 bg-primary/5 px-3 py-2 text-xs">
            <span>
              Showing flows of the selected connection; flow{" "}
              <code className="font-mono break-all">{highlightRef}</code> is highlighted
              {flows.data && !highlightedHere && " (not on this page: it may be on another page or was not kept)"}.
            </span>
            <Button variant="ghost" size="sm" className="ml-auto h-6 px-2 text-xs" onClick={() => onUrlChange({ ref: undefined })}>
              <X className="size-3.5" aria-hidden /> Clear highlight
            </Button>
          </div>
        )
      }
      filters={
        <>
          <div className="flex flex-col gap-1">
            <Input
              className="w-56"
              placeholder="IP address"
              aria-label="IP address filter"
              aria-invalid={ip.invalid || undefined}
              value={ipText}
              maxLength={45}
              onChange={(event) => {
                setIpText(event.target.value);
                onUrlChange({ ip: event.target.value.trim() || undefined });
              }}
            />
            {ip.invalid && <span className="text-xs text-destructive">Enter a full IPv4 or IPv6 address.</span>}
          </div>
          <div className="flex flex-col gap-1">
            <Input
              className="w-28"
              placeholder="Port"
              aria-label="Port filter"
              inputMode="numeric"
              aria-invalid={port.invalid || undefined}
              value={portText}
              maxLength={5}
              onChange={(event) => {
                setPortText(event.target.value);
                onUrlChange({ port: event.target.value.trim() || undefined });
              }}
            />
            {port.invalid && <span className="text-xs text-destructive">0–65535</span>}
          </div>
          <FilterSelect
            value={proto}
            onChange={setProto}
            options={PROTO_OPTIONS}
            allLabel="All protocols"
            label="Protocol filter"
            className="w-36"
          />
          <FilterSelect
            value={sort === "bytes" ? ALL : sort}
            onChange={(value) => setSort(value === ALL ? "bytes" : value)}
            options={[["ts", "Oldest first"]] as const}
            allLabel="Largest first"
            label="Sort order"
            className="w-36"
          />
        </>
      }
      head={
        <>
          <TableHead className="w-40">Start</TableHead>
          <TableHead>Source → destination</TableHead>
          <TableHead className="w-16">Proto</TableHead>
          <TableHead>Service</TableHead>
          <TableHead className="text-right">Bytes (orig / resp)</TableHead>
          <TableHead className="text-right">Packets</TableHead>
          <TableHead className="text-right">Duration</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Flow</TableHead>
        </>
      }
    >
      {(items) =>
        items.map((f) => {
          const src = endpointText(f.src_ip, f.src_port);
          const dst = endpointText(f.dst_ip, f.dst_port);
          const highlighted = Boolean(highlightRef) && f.flow_ref === highlightRef;
          return (
            <TableRow
              key={f.id}
              className={cn(highlighted && "bg-primary/10 hover:bg-primary/15")}
              aria-current={highlighted || undefined}
            >
              <TableCell>
                <When iso={f.ts} />
              </TableCell>
              <TableCell>
                <span className="block max-w-80 truncate font-mono text-xs" title={`${src} → ${dst}`}>
                  {src} <span className="text-muted-foreground">→</span> {dst}
                </span>
              </TableCell>
              <TableCell className="uppercase">{f.proto}</TableCell>
              <TableCell>
                <Trunc value={f.service} className="max-w-32" />
              </TableCell>
              <TableCell
                className="text-right tabular-nums"
                title={`${formatCount(f.orig_bytes)} B sent / ${formatCount(f.resp_bytes)} B received`}
              >
                {formatBytes(f.orig_bytes)} / {formatBytes(f.resp_bytes)}
              </TableCell>
              <TableCell className="text-right tabular-nums" title={`${f.orig_pkts} / ${f.resp_pkts}`}>
                {formatCount(f.orig_pkts + f.resp_pkts)}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {f.duration_s === null ? "—" : formatDuration(f.duration_s * 1000)}
              </TableCell>
              <TableCell>
                <Trunc value={f.conn_state} mono className="max-w-20" />
              </TableCell>
              <TableCell>
                <Trunc value={f.flow_ref} mono className={cn("max-w-40", highlighted && "font-semibold")} />
              </TableCell>
            </TableRow>
          );
        })
      }
    </ResultTable>
  );
}
