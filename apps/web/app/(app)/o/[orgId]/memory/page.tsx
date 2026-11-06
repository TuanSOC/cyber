"use client";

import Link from "next/link";
import { useState } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { ALL, FilterSelect } from "@/components/analysis/result-parts";
import { PageHeader } from "@/components/page-header";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  ANALYSIS_STATUSES,
  ANALYSIS_STATUS_LABELS,
  type AnalysisJob,
  type AnalysisStatus,
  MEMORY_PROFILE_LABELS,
  type MemoryProfile,
  jobDurationText,
} from "@/lib/analysis";
import { formatDate } from "@/lib/format";
import { MEMORY_OS_LABELS, memoryJobFacts } from "@/lib/memory";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useMemoryJobs } from "@/lib/use-memory-job";
import { useNow } from "@/lib/use-now";

const COLUMNS = 9;
const STATUS_OPTIONS = ANALYSIS_STATUSES.map((s) => [s, ANALYSIS_STATUS_LABELS[s]] as const);
const PROFILE_OPTIONS = (Object.entries(MEMORY_PROFILE_LABELS) as [MemoryProfile, string][]).map(
  ([value, label]) => [value, label] as const,
);

/** "Symbols missing" is never shown as a clean run; unknown is a dash. */
function SymbolsCell({ job }: { job: Pick<AnalysisJob, "summary" | "error_code"> }) {
  const facts = memoryJobFacts(job);
  if (facts.symbols === "missing") return <Badge variant="destructive">Symbols missing</Badge>;
  if (facts.symbols === "resolved") return <span className="text-muted-foreground">Resolved</span>;
  return <span className="text-muted-foreground">—</span>;
}

export default function MemoryAnalysisPage() {
  const { orgId } = useOrg();
  const [status, setStatus] = useState<AnalysisStatus | typeof ALL>(ALL);
  const [profile, setProfile] = useState<MemoryProfile | typeof ALL>(ALL);
  const [offset, setOffset] = useState(0);

  const list = useMemoryJobs({
    orgId,
    status: status === ALL ? undefined : status,
    profile: profile === ALL ? undefined : profile,
    offset,
    pageSize: PAGE_SIZE,
  });
  const now = useNow(list.data?.items.some((job) => job.status === "running") ?? false);
  const filtered = status !== ALL || profile !== ALL;

  return (
    <>
      <PageHeader
        title="Memory Analysis"
        description="Offline triage of RAM images (Windows and Linux): processes, network, private executable regions, services, registry and shell history. Memory images are TLP:RED material by default."
      />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <FilterSelect
          value={status}
          onChange={(value) => {
            setStatus(value);
            setOffset(0);
          }}
          options={STATUS_OPTIONS}
          allLabel="All statuses"
          label="Status filter"
          className="w-40"
        />
        <FilterSelect
          value={profile}
          onChange={(value) => {
            setProfile(value);
            setOffset(0);
          }}
          options={PROFILE_OPTIONS}
          allLabel="All profiles"
          label="Profile filter"
          className="w-40"
        />
      </div>
      {list.isError && <QueryError error={list.error} onRetry={() => void list.refetch()} />}
      <div className="mt-3 min-w-0 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-32">Status</TableHead>
              <TableHead className="w-24">Profile</TableHead>
              <TableHead className="w-24">OS</TableHead>
              <TableHead>Evidence</TableHead>
              <TableHead className="w-36">Symbols</TableHead>
              <TableHead className="w-32">Findings</TableHead>
              <TableHead className="w-44">Created</TableHead>
              <TableHead className="w-24 text-right">Duration</TableHead>
              <TableHead className="w-20" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isPending && (
              <TableRow>
                <TableCell colSpan={COLUMNS} className="py-8 text-center text-muted-foreground">
                  Loading analyses…
                </TableCell>
              </TableRow>
            )}
            {list.data?.items.map((job) => {
              const created = formatDate(job.created_at);
              const facts = memoryJobFacts(job);
              const jobProfile = job.profile === "triage" || job.profile === "full" ? job.profile : null;
              return (
                <TableRow key={job.id}>
                  <TableCell>
                    <AnalysisStatusBadge status={job.status} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{jobProfile ? MEMORY_PROFILE_LABELS[jobProfile] : "—"}</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{facts.os ? MEMORY_OS_LABELS[facts.os] : "—"}</TableCell>
                  <TableCell className="max-w-72">
                    <Link
                      className="block truncate hover:underline"
                      title={job.evidence_filename}
                      href={orgPath(orgId, `evidence/${job.evidence_id}`)}
                    >
                      {job.evidence_filename}
                    </Link>
                    <Link
                      className="text-xs text-muted-foreground underline-offset-4 hover:underline"
                      href={orgPath(orgId, `investigations/${job.investigation_id}`)}
                    >
                      Open case
                    </Link>
                  </TableCell>
                  <TableCell>
                    <SymbolsCell job={job} />
                  </TableCell>
                  <TableCell>
                    <FindingCount job={job} />
                  </TableCell>
                  <TableCell title={created.utc} className="text-muted-foreground">
                    {created.local}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground tabular-nums">
                    {jobDurationText(job, now)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Link className="text-xs underline underline-offset-4" href={orgPath(orgId, `memory/${job.id}`)}>
                      Details
                    </Link>
                  </TableCell>
                </TableRow>
              );
            })}
            {list.data?.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={COLUMNS} className="py-10 text-center whitespace-normal text-muted-foreground">
                  {filtered
                    ? "No memory analyses match these filters."
                    : "No memory analyses yet. Upload a RAM image with “This is a memory image” ticked, then run the memory analysis from its evidence page. Memory images are never analyzed automatically."}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="mt-3 flex flex-col gap-2">
        <Pager offset={offset} total={list.data?.total ?? 0} onChange={setOffset} />
      </div>
    </>
  );
}
