"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import {
  ALL,
  Endpoints,
  FilterSelect,
  FlowButton,
  PAGE_SIZE,
  ResultTable,
  Trunc,
  When,
  usePageOffset,
} from "@/components/analysis/result-parts";
import { CITED_ROW, CitedRefBar, useScrollToCited } from "@/components/ai/cited-ref-bar";
import { ExplainButton } from "@/components/ai/explain-drawer";
import { SeverityBadge } from "@/components/severity-badge";
import { TableCell, TableHead, TableRow } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { type FlowLink, alertSeverity, citedQuery, flowLinkFor, parseRowRef } from "@/lib/pcap-results";

const COLUMNS = 8;
const SEVERITY_OPTIONS = [
  ["1", "1 (high)"],
  ["2", "2 (medium)"],
  ["3", "3 (low)"],
  ["4", "4 (info)"],
] as const;

type SeverityOption = (typeof SEVERITY_OPTIONS)[number][0];

/** Suricata alerts of one job; `citedRef` (an AI citation link) narrows the list to that alert. */
export function AlertsTab({
  orgId,
  jobId,
  suricataMissing,
  onShowFlow,
  citedRef,
  onClearRef,
}: {
  orgId: string;
  jobId: string;
  suricataMissing: boolean;
  onShowFlow: (link: FlowLink) => void;
  citedRef?: string | null;
  onClearRef?: () => void;
}) {
  const cited = parseRowRef(citedRef);
  const [severity, setSeverity] = useState<SeverityOption | typeof ALL>(ALL);
  const filters = { severity: severity === ALL ? undefined : Number(severity) };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = citedQuery(cited.ref, filters, { limit: PAGE_SIZE, offset });

  const alerts = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "alerts", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/alerts", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  useScrollToCited(Boolean(cited.ref), alerts.isSuccess);

  return (
    <ResultTable
      query={alerts}
      offset={cited.ref ? 0 : offset}
      onOffset={setOffset}
      columns={COLUMNS}
      empty={
        severity !== ALL
          ? "No alerts of this severity."
          : suricataMissing
            ? "No alerts: Suricata did not complete for this capture (see the Overview)."
            : "No Suricata signature alerts."
      }
      note={(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
      filters={
        cited.ref ? undefined : (
        <FilterSelect
          value={severity}
          onChange={setSeverity}
          options={SEVERITY_OPTIONS}
          allLabel="All severities"
          label="Alert severity filter"
          className="w-40"
        />
        )
      }
      head={
        <>
          <TableHead className="w-24">Severity</TableHead>
          <TableHead>Signature</TableHead>
          <TableHead className="w-32">SID:rev</TableHead>
          <TableHead>Category</TableHead>
          <TableHead className="w-16">Proto</TableHead>
          <TableHead>Endpoints</TableHead>
          <TableHead className="w-40">Time</TableHead>
          <TableHead className="w-36" />
        </>
      }
    >
      {(items) =>
        items.map((a) => (
          <TableRow key={a.id} className={a.id === cited.ref ? CITED_ROW : undefined}>
            <TableCell>
              <SeverityBadge severity={alertSeverity(a.severity)} />
              <span className="sr-only"> (Suricata severity {a.severity})</span>
            </TableCell>
            <TableCell>
              <Trunc value={a.signature} className="max-w-96" />
            </TableCell>
            <TableCell className="font-mono text-xs">
              {a.signature_id}:{a.rev}
            </TableCell>
            <TableCell>
              <Trunc value={a.category} className="max-w-56" />
            </TableCell>
            <TableCell>
              <Trunc value={a.proto} className="max-w-16" />
            </TableCell>
            <TableCell>
              <Endpoints e={a} />
            </TableCell>
            <TableCell>
              <When iso={a.ts} />
            </TableCell>
            <TableCell>
              <span className="flex items-center gap-1">
                {a.flow_ref && <FlowButton link={flowLinkFor(a, a.flow_ref, true)} onShowFlow={onShowFlow} />}
                <ExplainButton orgId={orgId} jobId={jobId} target="alert" targetId={a.id} title={a.signature} />
              </span>
            </TableCell>
          </TableRow>
        ))
      }
    </ResultTable>
  );
}
