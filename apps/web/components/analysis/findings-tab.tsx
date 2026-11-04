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
import { type AttackLookup, AttackChips, MitreNotice, useAttackLookup } from "@/components/ti/attack-chips";
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
import { STATIC_FINDING_TYPES } from "@/lib/static-results";
import { attackIdsFromAttributes } from "@/lib/ti";

const SEVERITY_OPTIONS = FINDING_SEVERITIES.map((s) => [s, s[0].toUpperCase() + s.slice(1)] as const);

/**
 * Findings of one job (the shared per-job route). `pcap` findings carry endpoints and evidence
 * flows (with links into the Flows tab); `static` findings describe the sample, their evidence
 * references (sections, rules, imports) are shown as text.
 */
export function FindingsTab({
  orgId,
  jobId,
  onShowFlow,
  variant = "pcap",
}: {
  orgId: string;
  jobId: string;
  onShowFlow?: (link: FlowLink) => void;
  variant?: "pcap" | "static";
}) {
  const isPcap = variant === "pcap";
  const columns = isPcap ? 9 : 6;
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
  // ATT&CK ids carried by findings (e.g. capa-derived static findings), labelled in one request.
  const attackIdsOnPage = findings.data?.items.flatMap((f) => attackIdsFromAttributes(f.attributes)) ?? [];
  const attackLookup = useAttackLookup(attackIdsOnPage);

  return (
    <ResultTable
      query={findings}
      offset={offset}
      onOffset={setOffset}
      columns={columns}
      empty={
        filtered
          ? "No findings match these filters."
          : isPcap
            ? "No findings. The heuristics found no behaviour worth a closer look in this capture."
            : "No findings. The heuristics and signature engines found nothing worth a closer look in this file."
      }
      note={
        <div className="flex flex-col gap-1">
          <p className="text-xs text-muted-foreground">
            {isPcap
              ? "Findings are heuristics that describe observed behaviour; they are leads to review, not verdicts."
              : "Findings are heuristics and signature hits over the file's static features; they are leads to review, not verdicts."}
          </p>
          {attackIdsOnPage.length > 0 && <MitreNotice meta={attackLookup.meta} />}
        </div>
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
            options={isPcap ? FINDING_TYPES : STATIC_FINDING_TYPES}
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
          {isPcap && <TableHead>Endpoints</TableHead>}
          <TableHead className="w-24 text-right">Confidence</TableHead>
          <TableHead>Method</TableHead>
          <TableHead className="w-40">{isPcap ? "First seen" : "Detected"}</TableHead>
          {isPcap && <TableHead className="w-40">Last seen</TableHead>}
          {isPcap && <TableHead className="w-16" />}
        </>
      }
    >
      {(items) =>
        items.map((f) => (
          <FindingRow
            key={f.id}
            finding={f}
            columns={columns}
            onShowFlow={isPcap ? onShowFlow : undefined}
            attackLookup={attackLookup}
          />
        ))
      }
    </ResultTable>
  );
}

function FindingRow({
  finding: f,
  columns,
  onShowFlow,
  attackLookup,
}: {
  finding: Finding;
  columns: number;
  onShowFlow?: (link: FlowLink) => void;
  attackLookup: AttackLookup;
}) {
  const attributes = Object.entries(f.attributes ?? {});
  const attack = attackIdsFromAttributes(f.attributes);
  return (
    <ExpandableRow
      columns={columns}
      cells={
        <>
          <TableCell>
            <SeverityBadge severity={f.severity} />
          </TableCell>
          <TableCell>
            <Trunc value={f.title} className="max-w-80 font-medium" />
            <Trunc value={f.type} mono className="text-muted-foreground" />
          </TableCell>
          {onShowFlow && (
            <TableCell>
              <Endpoints e={f} />
            </TableCell>
          )}
          <TableCell className="text-right tabular-nums">{formatPercent(f.confidence)}</TableCell>
          <TableCell>
            <Trunc value={f.detection_method} mono className="max-w-56" />
          </TableCell>
          <TableCell>
            <When iso={f.ts} />
          </TableCell>
          {onShowFlow && (
            <TableCell>
              <When iso={f.last_seen} />
            </TableCell>
          )}
          {onShowFlow && (
            <TableCell>
              {f.flow_ref && <FlowButton link={flowLinkFor(f, f.flow_ref, false)} onShowFlow={onShowFlow} />}
            </TableCell>
          )}
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
          {attack.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-medium text-muted-foreground">ATT&amp;CK techniques</p>
              <AttackChips ids={attack} lookup={attackLookup} max={20} />
            </div>
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
              {onShowFlow ? "Evidence flows" : "Evidence references"} ({f.evidence_refs.length})
            </p>
            {f.evidence_refs.length === 0 ? (
              <p className="text-muted-foreground">None recorded.</p>
            ) : !onShowFlow ? (
              <div className="flex flex-wrap gap-1">
                {f.evidence_refs.map((ref) => (
                  <span
                    key={ref}
                    className="max-w-72 truncate rounded-md border px-2 py-0.5 font-mono text-xs"
                    title={ref}
                  >
                    {ref}
                  </span>
                ))}
              </div>
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
