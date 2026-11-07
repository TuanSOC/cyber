"use client";

import Link from "next/link";
import { useState } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { ALL, FilterSelect } from "@/components/analysis/result-parts";
import { InertText } from "@/components/disk/inert-text";
import { PageHeader } from "@/components/page-header";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  ANALYSIS_STATUSES,
  ANALYSIS_STATUS_LABELS,
  type AnalysisStatus,
  RE_PROFILE_LABELS,
  type ReProfile,
  jobDurationText,
} from "@/lib/analysis";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { ENGINE_LABELS, reJobFacts } from "@/lib/reverse";
import { useNow } from "@/lib/use-now";
import { useReJobs } from "@/lib/use-re-job";

const COLUMNS = 9;
const STATUS_OPTIONS = ANALYSIS_STATUSES.map((s) => [s, ANALYSIS_STATUS_LABELS[s]] as const);
const PROFILE_OPTIONS = (Object.entries(RE_PROFILE_LABELS) as [ReProfile, string][]).map(([v, l]) => [v, l] as const);

/** Reverse Engineering: the org's RE jobs, newest first (M10 phase 10). */
export default function ReverseEngineeringPage() {
  const { orgId } = useOrg();
  const [status, setStatus] = useState<AnalysisStatus | typeof ALL>(ALL);
  const [profile, setProfile] = useState<ReProfile | typeof ALL>(ALL);
  const [offset, setOffset] = useState(0);
  const list = useReJobs({
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
        title="Reverse Engineering"
        description="Static reverse engineering of PE and ELF programs with Ghidra (radare2 for the quick profile): functions, calls, imports, strings and decompiled pseudo-C. Programs are never executed."
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
          className="w-44"
        />
      </div>
      {list.isError && <QueryError error={list.error} onRetry={() => void list.refetch()} />}
      <div className="mt-3 min-w-0 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-32">Status</TableHead>
              <TableHead className="w-32">Profile</TableHead>
              <TableHead>Sample</TableHead>
              <TableHead className="w-32">Engine</TableHead>
              <TableHead className="w-28 text-right">Functions</TableHead>
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
              const facts = reJobFacts(job);
              const jobProfile: ReProfile | null = job.profile === "quick" || job.profile === "full" ? job.profile : null;
              return (
                <TableRow key={job.id}>
                  <TableCell>
                    <AnalysisStatusBadge status={job.status} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{jobProfile ? RE_PROFILE_LABELS[jobProfile] : "—"}</Badge>
                  </TableCell>
                  <TableCell className="max-w-72">
                    <Link className="block min-w-0 hover:underline" href={orgPath(orgId, `evidence/${job.evidence_id}`)}>
                      <InertText value={job.evidence_filename} />
                    </Link>
                    <Link
                      className="text-xs text-muted-foreground underline-offset-4 hover:underline"
                      href={orgPath(orgId, `investigations/${job.investigation_id}`)}
                    >
                      Open case
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{facts.engine ? ENGINE_LABELS[facts.engine] : "—"}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {facts.functions !== null ? facts.functions.toLocaleString("en-US") : "—"}
                  </TableCell>
                  <TableCell>
                    <FindingCount job={job} />
                  </TableCell>
                  <TableCell title={created.utc} className="text-muted-foreground">
                    {created.local}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground tabular-nums">{jobDurationText(job, now)}</TableCell>
                  <TableCell className="text-right">
                    <Link className="text-xs underline underline-offset-4" href={orgPath(orgId, `reverse-engineering/${job.id}`)}>
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
                    ? "No reverse-engineering analyses match these filters."
                    : "No reverse-engineering analyses yet. Open a succeeded full static analysis of a PE or ELF file in the Malware Lab and choose “Reverse engineer”. Nothing is reverse engineered automatically."}
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
