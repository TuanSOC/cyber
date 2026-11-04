"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import {
  ALL,
  Endpoints,
  ExpandableRow,
  FilterSelect,
  FlowButton,
  PAGE_SIZE,
  ResultTable,
  Trunc,
  When,
  usePageOffset,
} from "@/components/analysis/result-parts";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { TableCell, TableHead } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import {
  FINDING_SEVERITIES,
  FINDING_TYPES,
  type Finding,
  type FindingSeverity,
  type FlowLink,
  attributeText,
  flowLinkFor,
  formatPercent,
} from "@/lib/pcap-results";

const COLUMNS = 9;
const SEVERITY_OPTIONS = FINDING_SEVERITIES.map((s) => [s, s[0].toUpperCase() + s.slice(1)] as const);

export function FindingsTab({
  orgId,
  jobId,
  onShowFlow,
}: {
  orgId: string;
  jobId: string;
  onShowFlow: (link: FlowLink) => void;
}) {
  const [severity, setSeverity] = useState<FindingSeverity | typeof ALL>(ALL);
  const [type, setType] = useState<string>(ALL);
  const filters = { severity: severity === ALL ? undefined : severity, type: type === ALL ? undefined : type };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = { ...filters, limit: PAGE_SIZE, offset };

  const findings = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "findings", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/findings", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  const filtered = severity !== ALL || type !== ALL;

  return (
    <ResultTable
      query={findings}
      offset={offset}
      onOffset={setOffset}
      columns={COLUMNS}
      empty={
        filtered
          ? "No findings match these filters."
          : "No findings. The heuristics found no behaviour worth a closer look in this capture."
      }
      note={
        <p className="text-xs text-muted-foreground">
          Findings are heuristics that describe observed behaviour; they are leads to review, not verdicts.
        </p>
      }
      filters={
        <>
          <FilterSelect
            value={severity}
            onChange={setSeverity}
            options={SEVERITY_OPTIONS}
            allLabel="All severities"
            label="Severity filter"
            className="w-40"
          />
          <FilterSelect
            value={type}
            onChange={setType}
            options={FINDING_TYPES}
            allLabel="All types"
            label="Finding type filter"
            className="w-60"
          />
        </>
      }
      head={
        <>
          <TableHead className="w-8" />
          <TableHead className="w-24">Severity</TableHead>
          <TableHead>Finding</TableHead>
          <TableHead>Endpoints</TableHead>
          <TableHead className="w-24 text-right">Confidence</TableHead>
          <TableHead>Method</TableHead>
          <TableHead className="w-40">First seen</TableHead>
          <TableHead className="w-40">Last seen</TableHead>
          <TableHead className="w-16" />
        </>
      }
    >
      {(items) => items.map((f) => <FindingRow key={f.id} finding={f} onShowFlow={onShowFlow} />)}
    </ResultTable>
  );
}

function FindingRow({ finding: f, onShowFlow }: { finding: Finding; onShowFlow: (link: FlowLink) => void }) {
  const attributes = Object.entries(f.attributes ?? {});
  return (
    <ExpandableRow
      columns={COLUMNS}
      cells={
        <>
          <TableCell>
            <SeverityBadge severity={f.severity} />
          </TableCell>
          <TableCell>
            <Trunc value={f.title} className="max-w-80 font-medium" />
            <Trunc value={f.type} mono className="text-muted-foreground" />
          </TableCell>
          <TableCell>
            <Endpoints e={f} />
          </TableCell>
          <TableCell className="text-right tabular-nums">{formatPercent(f.confidence)}</TableCell>
          <TableCell>
            <Trunc value={f.detection_method} mono className="max-w-56" />
          </TableCell>
          <TableCell>
            <When iso={f.ts} />
          </TableCell>
          <TableCell>
            <When iso={f.last_seen} />
          </TableCell>
          <TableCell>
            {f.flow_ref && <FlowButton link={flowLinkFor(f, f.flow_ref, false)} onShowFlow={onShowFlow} />}
          </TableCell>
        </>
      }
      detail={
        <div className="flex flex-col gap-3 text-sm">
          <p className="break-words whitespace-pre-wrap">{f.description}</p>
          {f.protocol && (
            <p>
              <span className="text-muted-foreground">Protocol: </span>
              {f.protocol}
            </p>
          )}
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">Measured values</p>
            {attributes.length === 0 ? (
              <p className="text-muted-foreground">None recorded.</p>
            ) : (
              <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1">
                {attributes.map(([key, value]) => (
                  <div key={key} className="contents">
                    <dt className="min-w-0 font-mono text-xs break-all text-muted-foreground">{key}</dt>
                    <dd className="min-w-0 break-all">{attributeText(value)}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              Evidence flows ({f.evidence_refs.length})
            </p>
            {f.evidence_refs.length === 0 ? (
              <p className="text-muted-foreground">None recorded.</p>
            ) : (
              <div className="flex flex-wrap gap-1">
                {f.evidence_refs.map((ref) => (
                  <Button
                    key={ref}
                    variant="outline"
                    size="sm"
                    className="h-6 max-w-56 px-2 font-mono text-xs"
                    title={`Show flow ${ref}`}
                    onClick={() => onShowFlow(flowLinkFor(f, ref, false))}
                  >
                    <span className="truncate">{ref}</span>
                  </Button>
                ))}
              </div>
            )}
          </div>
        </div>
      }
    />
  );
}
