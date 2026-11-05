"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import {
  ALL,
  CopyButton,
  ExpandableRow,
  FilterSelect,
  PAGE_SIZE,
  ResultTable,
  Trunc,
  When,
  usePageOffset,
} from "@/components/analysis/result-parts";
import { CITED_ROW, CitedRefBar, useScrollToCited } from "@/components/ai/cited-ref-bar";
import { IocSeenIn } from "@/components/correlation/ioc-seen-in";
import { EnrichButton } from "@/components/ti/enrich-button";
import { ProviderChip } from "@/components/ti/provider-chip";
import { ResultById } from "@/components/ti/result-panel";
import { RunProgress } from "@/components/ti/run-progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { TableCell, TableHead } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { IOC_TYPE_LABELS, type IocType, citedQuery, formatCount, parseRowRef, searchTerm } from "@/lib/pcap-results";
import {
  type EnrichedIoc,
  PROVIDERS,
  historyHref,
  isActiveRun,
  lookupTypeForIoc,
  skipReasonText,
  urlQueryRemoved,
} from "@/lib/ti";
import { useDebounced } from "@/lib/use-debounced";
import { useLatestJobRun } from "@/lib/use-ti";

const COLUMNS = 8;
const TYPE_OPTIONS = Object.entries(IOC_TYPE_LABELS) as [IocType, string][];
// While an enrichment run is active the list is refreshed so chips appear as answers arrive.
const ENRICHING_REFRESH_MS = 10_000;

/**
 * Observables seen in the capture or sample. Values are attacker-controlled (a "url" may be anything,
 * e.g. `javascript:`): shown as text with a copy button, never as a link. With threat intel (M4)
 * each row carries the latest attributed answer per provider, or why the value is never sent.
 * `citedRef` (an AI citation link) narrows the list to that observable.
 */
export function IocsTab({
  orgId,
  jobId,
  source = "capture",
  citedRef,
  onClearRef,
}: {
  orgId: string;
  jobId: string;
  /** What the observables were extracted from ("capture", "file"). */
  source?: string;
  citedRef?: string | null;
  onClearRef?: () => void;
}) {
  const cited = parseRowRef(citedRef);
  const [type, setType] = useState<IocType | typeof ALL>(ALL);
  const [search, setSearch] = useState("");
  const q = searchTerm(useDebounced(search));
  const filters = { type: type === ALL ? undefined : type, q };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = {
    ...citedQuery(cited.ref, filters, { limit: PAGE_SIZE, offset }),
    include: "enrichment" as const,
  };
  const latestRun = useLatestJobRun(orgId, jobId);
  const run = latestRun.data?.items[0];
  const enriching = isActiveRun(run?.status);

  const iocs = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "iocs", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/iocs", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
    refetchInterval: enriching ? ENRICHING_REFRESH_MS : false,
  });
  useScrollToCited(Boolean(cited.ref), iocs.isSuccess);

  return (
    <ResultTable
      query={iocs}
      offset={cited.ref ? 0 : offset}
      onOffset={setOffset}
      columns={COLUMNS}
      empty={type !== ALL || q ? "No IOCs match these filters." : "No observables recorded."}
      note={
        <div className="flex flex-col gap-2">
          {(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
          {run && <RunProgress orgId={orgId} run={run} />}
          {/* M7 slot: "also seen in" (phase 8). */}
          <IocSeenIn orgId={orgId} jobId={jobId} />
          <p className="text-xs text-muted-foreground">
            Observables extracted from the {source}. Threat intel chips quote each provider&apos;s own answer with its
            date (hover a chip); they are attributed statements, not our assessment. Values are copied, never opened.
          </p>
        </div>
      }
      filters={
        cited.ref ? undefined : (
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
          <div className="ml-auto">
            <EnrichButton orgId={orgId} jobId={jobId} busy={enriching} />
          </div>
        </>
        )
      }
      head={
        <>
          <TableHead className="w-8" />
          <TableHead className="w-32">Type</TableHead>
          <TableHead>Value</TableHead>
          <TableHead className="w-20 text-right">Count</TableHead>
          <TableHead className="w-40">First seen</TableHead>
          <TableHead className="w-40">Last seen</TableHead>
          <TableHead className="w-24">Source</TableHead>
          <TableHead>Threat intel</TableHead>
        </>
      }
    >
      {(items) => items.map((ioc) => <IocRow key={ioc.id} orgId={orgId} ioc={ioc} cited={ioc.id === cited.ref} />)}
    </ResultTable>
  );
}

function sortedEnrichment(ioc: EnrichedIoc) {
  return [...(ioc.enrichment ?? [])].sort((a, b) => PROVIDERS.indexOf(a.provider) - PROVIDERS.indexOf(b.provider));
}

/** Per-provider chips, or why the value is never sent. */
function EnrichmentCell({ ioc }: { ioc: EnrichedIoc }) {
  const skip = skipReasonText(ioc.enrichment_skip);
  const answers = sortedEnrichment(ioc);
  const queryRemoved = !skip && urlQueryRemoved(ioc.type, ioc.value);
  return (
    <div className="flex max-w-96 flex-col gap-1">
      {skip ? (
        <span className="text-xs text-muted-foreground">{skip}</span>
      ) : answers.length === 0 ? (
        <span className="text-xs text-muted-foreground">—</span>
      ) : (
        <span className="flex flex-wrap gap-1">
          {answers.map((e) => (
            <ProviderChip key={e.provider} e={e} />
          ))}
        </span>
      )}
      {queryRemoved && <span className="text-[11px] text-muted-foreground">query removed before lookup</span>}
    </div>
  );
}

function IocRow({ orgId, ioc, cited }: { orgId: string; ioc: EnrichedIoc; cited: boolean }) {
  const answers = sortedEnrichment(ioc);
  const lookupType = lookupTypeForIoc(ioc.type);
  return (
    <ExpandableRow
      columns={COLUMNS}
      className={cited ? CITED_ROW : undefined}
      cells={
        <>
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
          <TableCell>
            <EnrichmentCell ioc={ioc} />
          </TableCell>
        </>
      }
      detail={
        <div className="flex flex-col gap-3 text-sm">
          <p className="font-mono text-xs break-all">{ioc.value}</p>
          {ioc.enrichment_skip ? (
            <p className="text-muted-foreground">Never sent to any provider: {skipReasonText(ioc.enrichment_skip)}.</p>
          ) : answers.length === 0 ? (
            <p className="text-muted-foreground">No provider answer recorded for this value yet.</p>
          ) : (
            <div className="grid gap-2 lg:grid-cols-2">
              {answers.map((e) => (
                <ResultById key={e.result_id} orgId={orgId} resultId={e.result_id} />
              ))}
            </div>
          )}
          {lookupType && (
            <Link
              href={historyHref(orgId, lookupType, ioc.value)}
              className="self-start text-xs text-primary underline-offset-4 hover:underline"
            >
              View history
            </Link>
          )}
        </div>
      }
    />
  );
}
