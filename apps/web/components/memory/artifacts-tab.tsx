"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { CITED_ROW, CitedRefBar, useScrollToCited } from "@/components/ai/cited-ref-bar";
import { ExpandableRow, PAGE_SIZE, ResultTable, Trunc, When, usePageOffset } from "@/components/analysis/result-parts";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TableCell, TableHead } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import {
  ARTIFACT_FIELDS,
  ARTIFACT_TYPE_LABELS,
  type ArtifactField,
  type ArtifactTab,
  FULL_PROFILE_ARTIFACTS,
  type MemoryArtifact,
  type MemoryArtifactType,
  TAB_ARTIFACT_TYPES,
  attributeValue,
  otherAttributes,
} from "@/lib/memory";
import { citedQuery, parseRowRef, searchTerm } from "@/lib/pcap-results";
import { useDebounced } from "@/lib/use-debounced";

const TAB_NOTES: Record<ArtifactTab, string> = {
  modules: "Modules loaded by each process. “Missing from a loader list” rows come from the full profile's loader-list check.",
  services: "Services found in memory, with the binary each one starts. Paths are shown as text, never opened.",
  registry: "Registry hives mapped in memory and UserAssist program-run counters.",
  linux: "Bash history, open files, syscall table entries without a kernel symbol, and kernel modules hidden from the module list.",
};

function FieldCell({ artifact, field }: { artifact: MemoryArtifact; field: ArtifactField }) {
  const value = attributeValue(artifact.attributes, field);
  if (field.format === "date") return <When iso={value} />;
  return <Trunc value={value} mono={field.format === "mono" || field.format === "address"} className="max-w-80" />;
}

/** One artifact row; the detail shows every other attribute as text. */
export function ArtifactRow({ artifact, cited }: { artifact: MemoryArtifact; cited?: boolean }) {
  const fields = ARTIFACT_FIELDS[artifact.type] ?? [];
  const extra = otherAttributes(artifact.type, artifact.attributes);
  return (
    <ExpandableRow
      columns={fields.length + 2}
      className={cited ? CITED_ROW : undefined}
      cells={
        <>
          <TableCell className="tabular-nums">{artifact.pid ?? "—"}</TableCell>
          {fields.map((field) => (
            <TableCell key={field.key}>
              <FieldCell artifact={artifact} field={field} />
            </TableCell>
          ))}
        </>
      }
      detail={
        <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-sm">
          {[...fields.map((field) => [field.label, attributeValue(artifact.attributes, field)] as const), ...extra].map(
            ([label, value]) => (
              <div key={label} className="contents">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="min-w-0 font-mono text-xs break-all whitespace-pre-wrap">{value ?? "—"}</dd>
              </div>
            ),
          )}
        </dl>
      }
    />
  );
}

function ArtifactTable({
  orgId,
  jobId,
  type,
  profile,
  citedRef,
  onClearRef,
}: {
  orgId: string;
  jobId: string;
  type: MemoryArtifactType;
  profile: string | null | undefined;
  citedRef?: string | null;
  onClearRef?: () => void;
}) {
  const cited = parseRowRef(citedRef);
  const [search, setSearch] = useState("");
  const q = searchTerm(useDebounced(search));
  const filters = { type, q };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));
  const query = citedQuery(cited.ref, filters, { limit: PAGE_SIZE, offset });
  const rows = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "memory", "artifacts", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/artifacts", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  useScrollToCited(Boolean(cited.ref), rows.isSuccess);
  const shownType = (cited.ref && rows.data?.items[0]?.type) || type;
  const fields = ARTIFACT_FIELDS[shownType] ?? [];
  const notRun = FULL_PROFILE_ARTIFACTS.has(type) && profile !== "full";

  return (
    <ResultTable
      query={rows}
      offset={cited.ref ? 0 : offset}
      onOffset={setOffset}
      columns={fields.length + 2}
      empty={
        q
          ? "No rows match this search."
          : notRun
            ? "Not collected: this check runs in the full profile only."
            : `No ${ARTIFACT_TYPE_LABELS[type].toLowerCase()} were recovered from this image.`
      }
      note={(cited.ref || cited.invalid) && <CitedRefBar invalid={cited.invalid} onClear={onClearRef} />}
      filters={
        cited.ref ? undefined : (
          <Input
            className="w-72"
            type="search"
            placeholder="Search"
            aria-label={`Search ${ARTIFACT_TYPE_LABELS[type]}`}
            maxLength={128}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        )
      }
      head={
        <>
          <TableHead className="w-8" />
          <TableHead className="w-20">PID</TableHead>
          {fields.map((field) => (
            <TableHead key={field.key}>{field.label}</TableHead>
          ))}
        </>
      }
    >
      {(items) => items.map((artifact) => <ArtifactRow key={artifact.id} artifact={artifact} cited={artifact.id === cited.ref} />)}
    </ResultTable>
  );
}

/** Modules / Services / Registry / Linux: one artifact type at a time (one request per page). */
export function ArtifactsTab({
  orgId,
  jobId,
  tab,
  profile,
  citedRef,
  onClearRef,
}: {
  orgId: string;
  jobId: string;
  tab: ArtifactTab;
  profile: string | null | undefined;
  citedRef?: string | null;
  onClearRef?: () => void;
}) {
  const types: readonly MemoryArtifactType[] = TAB_ARTIFACT_TYPES[tab];
  const [type, setType] = useState<MemoryArtifactType>(types[0]);
  const current = types.includes(type) ? type : types[0];
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">{TAB_NOTES[tab]}</p>
      {types.length > 1 && !citedRef ? (
        <div className="flex flex-wrap gap-1" role="group" aria-label="Artifact type">
          {types.map((value) => (
            <Button
              key={value}
              size="sm"
              variant={value === current ? "secondary" : "ghost"}
              aria-pressed={value === current}
              onClick={() => setType(value)}
            >
              {ARTIFACT_TYPE_LABELS[value]}
            </Button>
          ))}
        </div>
      ) : null}
      <ArtifactTable
        key={current}
        orgId={orgId}
        jobId={jobId}
        type={current}
        profile={profile}
        citedRef={citedRef}
        onClearRef={onClearRef}
      />
    </div>
  );
}
