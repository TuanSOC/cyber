"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";

import {
  Endpoints,
  ExpandableRow,
  FieldList,
  FlowButton,
  PAGE_SIZE,
  ResultTable,
  Trunc,
  When,
  usePageOffset,
} from "@/components/analysis/result-parts";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { TableCell, TableHead } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import {
  type FlowLink,
  type NetRecord,
  type RecordKind,
  detailFlag,
  detailList,
  detailText,
  flowLinkFor,
  recordFields,
  searchTerm,
} from "@/lib/pcap-results";
import { useDebounced } from "@/lib/use-debounced";

type KindView = {
  noun: string;
  placeholder: string;
  head: ReactNode;
  cells: (details: unknown) => ReactNode;
};

const VIEWS: Record<RecordKind, KindView> = {
  dns: {
    noun: "DNS queries",
    placeholder: "Search query, type, rcode, answers",
    head: (
      <>
        <TableHead>Query</TableHead>
        <TableHead className="w-16">Type</TableHead>
        <TableHead className="w-28">Rcode</TableHead>
        <TableHead>Answers</TableHead>
      </>
    ),
    cells: (d) => (
      <>
        <TableCell>
          <Trunc value={detailText(d, "query")} mono className="max-w-72" />
        </TableCell>
        <TableCell>
          <Trunc value={detailText(d, "qtype")} className="max-w-16" />
        </TableCell>
        <TableCell>
          <Trunc value={detailText(d, "rcode")} className="max-w-28" />
        </TableCell>
        <TableCell>
          <Trunc value={detailList(d, "answers").join(", ")} mono className="max-w-72" />
        </TableCell>
      </>
    ),
  },
  http: {
    noun: "HTTP requests",
    placeholder: "Search method, host, URI, status, user agent",
    head: (
      <>
        <TableHead className="w-16">Method</TableHead>
        <TableHead>Host</TableHead>
        <TableHead>URI</TableHead>
        <TableHead className="w-16">Status</TableHead>
        <TableHead>User agent</TableHead>
        <TableHead>MIME</TableHead>
      </>
    ),
    cells: (d) => (
      <>
        <TableCell>
          <Trunc value={detailText(d, "method")} className="max-w-16" />
        </TableCell>
        <TableCell>
          <Trunc value={detailText(d, "host")} mono className="max-w-48" />
        </TableCell>
        <TableCell>
          <Trunc value={detailText(d, "uri")} mono className="max-w-64" />
        </TableCell>
        <TableCell className="tabular-nums">{detailText(d, "status_code") ?? "—"}</TableCell>
        <TableCell>
          <Trunc value={detailText(d, "user_agent")} className="max-w-56" />
        </TableCell>
        <TableCell>
          <Trunc value={detailList(d, "resp_mime_types").join(", ")} className="max-w-40" />
        </TableCell>
      </>
    ),
  },
  tls: {
    noun: "TLS handshakes",
    placeholder: "Search SNI, version, cipher, JA3, subject",
    head: (
      <>
        <TableHead className="w-20">Version</TableHead>
        <TableHead>Server name (SNI)</TableHead>
        <TableHead>Cipher</TableHead>
        <TableHead>JA3 / JA3S</TableHead>
        <TableHead>Certificate</TableHead>
        <TableHead className="w-40">Valid until</TableHead>
        <TableHead>Validation</TableHead>
      </>
    ),
    cells: (d) => {
      const selfSigned = detailFlag(d, "self_signed") === true;
      return (
        <>
          <TableCell>
            <Trunc value={detailText(d, "version")} className="max-w-20" />
          </TableCell>
          <TableCell>
            <Trunc value={detailText(d, "server_name")} mono className="max-w-56" />
          </TableCell>
          <TableCell>
            <Trunc value={detailText(d, "cipher")} mono className="max-w-48" />
          </TableCell>
          <TableCell>
            <Trunc value={detailText(d, "ja3")} mono className="max-w-32" />
            <Trunc value={detailText(d, "ja3s")} mono className="max-w-32 text-muted-foreground" />
          </TableCell>
          <TableCell>
            <Trunc value={detailText(d, "cert_subject")} className="max-w-56" />
            <Trunc value={detailText(d, "cert_issuer")} className="max-w-56 text-xs text-muted-foreground" />
          </TableCell>
          <TableCell>
            <When iso={detailText(d, "cert_not_after")} />
          </TableCell>
          <TableCell>
            <div className="flex items-center gap-1">
              <Trunc value={detailText(d, "validation_status")} className="max-w-40" />
              {selfSigned && (
                <Badge variant="outline" className="border-sev-medium/50 text-sev-medium">
                  Self-signed
                </Badge>
              )}
            </div>
          </TableCell>
        </>
      );
    },
  },
};

const BASE_COLUMNS = 4; // toggle, time, endpoints, flow

export function RecordsTab({
  orgId,
  jobId,
  kind,
  onShowFlow,
}: {
  orgId: string;
  jobId: string;
  kind: RecordKind;
  onShowFlow: (link: FlowLink) => void;
}) {
  const view = VIEWS[kind];
  const [search, setSearch] = useState("");
  const q = searchTerm(useDebounced(search));
  const [offset, setOffset] = usePageOffset(q ?? "");
  const query = { kind, q, limit: PAGE_SIZE, offset };
  const columns = BASE_COLUMNS + countColumns(kind);

  const records = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "records", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/records", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <ResultTable
      query={records}
      offset={offset}
      onOffset={setOffset}
      columns={columns}
      empty={q ? `No ${view.noun} match this search.` : `No ${view.noun} recorded.`}
      filters={
        <Input
          className="w-80"
          type="search"
          placeholder={view.placeholder}
          aria-label={`Search ${view.noun}`}
          maxLength={200}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      }
      head={
        <>
          <TableHead className="w-8" />
          <TableHead className="w-40">Time</TableHead>
          <TableHead>Client → server</TableHead>
          {view.head}
          <TableHead className="w-16" />
        </>
      }
    >
      {(items) => items.map((r) => <RecordRow key={r.id} record={r} view={view} columns={columns} onShowFlow={onShowFlow} />)}
    </ResultTable>
  );
}

function countColumns(kind: RecordKind): number {
  return { dns: 4, http: 6, tls: 7 }[kind];
}

function RecordRow({
  record: r,
  view,
  columns,
  onShowFlow,
}: {
  record: NetRecord;
  view: KindView;
  columns: number;
  onShowFlow: (link: FlowLink) => void;
}) {
  return (
    <ExpandableRow
      columns={columns}
      cells={
        <>
          <TableCell>
            <When iso={r.ts} />
          </TableCell>
          <TableCell>
            <Endpoints e={r} className="max-w-64" />
          </TableCell>
          {view.cells(r.details)}
          <TableCell>
            {r.flow_ref && <FlowButton link={flowLinkFor(r, r.flow_ref, true)} onShowFlow={onShowFlow} />}
          </TableCell>
        </>
      }
      detail={<FieldList fields={recordFields(r.kind, r.details)} />}
    />
  );
}
