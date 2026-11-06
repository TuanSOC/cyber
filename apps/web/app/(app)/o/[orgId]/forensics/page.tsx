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
  DISK_PROFILE_LABELS,
  type DiskProfile,
  analysisKindLabel,
  jobDurationText,
} from "@/lib/analysis";
import { FORMAT_LABELS, diskJobFacts, formatU64Bytes } from "@/lib/disk";
import { genericSensitivity } from "@/lib/evidence-sensitivity";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { formatCount } from "@/lib/pcap-results";
import { useCaseOptions, useDiskJobs, useEvidenceRecord } from "@/lib/use-disk-job";
import { useNow } from "@/lib/use-now";

const COLUMNS = 9;
const STATUS_OPTIONS = ANALYSIS_STATUSES.map((s) => [s, ANALYSIS_STATUS_LABELS[s]] as const);
const PROFILE_OPTIONS = (Object.entries(DISK_PROFILE_LABELS) as [DiskProfile, string][]).map(([v, l]) => [v, l] as const);

/** The restricted badge of a job's first segment (evidence record, shared cache with the evidence page). */
function RestrictedCell({ orgId, evidenceId }: { orgId: string; evidenceId: string }) {
  const evidence = useEvidenceRecord(orgId, evidenceId);
  const shown = genericSensitivity(evidence.data?.sensitivity);
  if (!evidence.data) return <span className="text-muted-foreground">…</span>;
  if (shown?.state === "restricted") return <Badge variant="destructive">TLP:RED</Badge>;
  if (shown?.state === "released") return <span className="text-xs text-muted-foreground">Released</span>;
  return <span className="text-muted-foreground">—</span>;
}

function ImageCell({ job }: { job: AnalysisJob }) {
  const facts = diskJobFacts(job);
  if (!facts.format && facts.segments === null) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex flex-col text-xs">
      <span>
        {facts.format ? FORMAT_LABELS[facts.format] : "—"}
        {facts.segments !== null ? ` · ${facts.segments} segment${facts.segments === 1 ? "" : "s"}` : ""}
      </span>
      <span className="text-muted-foreground">
        {facts.mediaSize ? formatU64Bytes(facts.mediaSize) : "—"}
        {facts.partitions !== null ? ` · ${formatCount(facts.partitions)} partition${facts.partitions === 1 ? "" : "s"}` : ""}
      </span>
    </span>
  );
}

export default function ForensicsPage() {
  const { orgId } = useOrg();
  const [status, setStatus] = useState<AnalysisStatus | typeof ALL>(ALL);
  const [profile, setProfile] = useState<DiskProfile | typeof ALL>(ALL);
  const [caseId, setCaseId] = useState<string>(ALL);
  const [offset, setOffset] = useState(0);
  const cases = useCaseOptions(orgId);

  const list = useDiskJobs({
    orgId,
    status: status === ALL ? undefined : status,
    profile: profile === ALL ? undefined : profile,
    investigationId: caseId === ALL ? undefined : caseId,
    offset,
    pageSize: PAGE_SIZE,
  });
  const now = useNow(list.data?.items.some((job) => job.status === "running") ?? false);
  const filtered = status !== ALL || profile !== ALL || caseId !== ALL;
  const reset = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setOffset(0);
  };

  return (
    <>
      <PageHeader
        title="Forensics"
        description="Offline disk image analysis with The Sleuth Kit and Plaso: partitions, file listings with hashes, artifact timelines and exports. Disk images are TLP:RED material by default."
      />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <FilterSelect
          value={caseId}
          onChange={reset(setCaseId)}
          options={(cases.data ?? []).map((c) => [c.id, `${c.case_ref} · ${c.title}`] as const)}
          allLabel="All cases"
          label="Case filter"
          className="w-56"
        />
        <FilterSelect value={status} onChange={reset(setStatus)} options={STATUS_OPTIONS} allLabel="All statuses" label="Status filter" className="w-40" />
        <FilterSelect value={profile} onChange={reset(setProfile)} options={PROFILE_OPTIONS} allLabel="All profiles" label="Profile filter" className="w-40" />
      </div>
      {list.isError && <QueryError error={list.error} onRetry={() => void list.refetch()} />}
      <div className="mt-3 min-w-0 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-32">Status</TableHead>
              <TableHead className="w-36">Kind</TableHead>
              <TableHead>Evidence</TableHead>
              <TableHead className="w-48">Image</TableHead>
              <TableHead className="w-24">Sensitivity</TableHead>
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
              return (
                <TableRow key={job.id}>
                  <TableCell>
                    <AnalysisStatusBadge status={job.status} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{analysisKindLabel(job)}</Badge>
                  </TableCell>
                  <TableCell className="max-w-72">
                    <Link className="block truncate hover:underline" title={job.evidence_filename} href={orgPath(orgId, `evidence/${job.evidence_id}`)}>
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
                    <ImageCell job={job} />
                  </TableCell>
                  <TableCell>
                    <RestrictedCell orgId={orgId} evidenceId={job.evidence_id} />
                  </TableCell>
                  <TableCell>
                    <FindingCount job={job} />
                  </TableCell>
                  <TableCell title={created.utc} className="text-muted-foreground">
                    {created.local}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground tabular-nums">{jobDurationText(job, now)}</TableCell>
                  <TableCell className="text-right">
                    <Link className="text-xs underline underline-offset-4" href={orgPath(orgId, `forensics/${job.id}`)}>
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
                    ? "No disk analyses match these filters."
                    : "No disk analyses yet. In a case, upload the image's segments with “Disk image (segment)” ticked (every .E01, .E02 … or .001, .002 … file), then open the first segment's evidence page and run the disk analysis. Disk images are never analyzed automatically."}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="mt-3 flex flex-col gap-2">
        <Pager offset={offset} total={list.data?.total ?? 0} onChange={setOffset} />
        <p className="text-xs text-muted-foreground">
          The findings count is a total: the job summary has no per-severity breakdown (open the job for its findings).
        </p>
      </div>
    </>
  );
}
