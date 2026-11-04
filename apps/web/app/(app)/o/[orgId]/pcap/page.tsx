"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { AnalysisStatusBadge } from "@/components/analysis/analysis-status-badge";
import { FindingCount } from "@/components/analysis/finding-count";
import { PageHeader } from "@/components/page-header";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ANALYSIS_STATUSES,
  ANALYSIS_STATUS_LABELS,
  type AnalysisStatus,
  jobDurationText,
  pollWhileActive,
} from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useNow } from "@/lib/use-now";

const ALL = "all";
const COLUMNS = 9;

export default function PcapAnalysesPage() {
  const { orgId } = useOrg();
  const [status, setStatus] = useState<AnalysisStatus | typeof ALL>(ALL);
  const [offset, setOffset] = useState(0);

  const params = { status: status === ALL ? undefined : status, limit: PAGE_SIZE, offset };
  const list = useQuery({
    queryKey: ["org", orgId, "analyses", params],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses", {
          params: { path: { org_id: orgId }, query: params },
        }),
      ),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => pollWhileActive(query.state.data?.items),
  });
  const now = useNow(list.data?.items.some((job) => job.status === "running") ?? false);

  return (
    <>
      <PageHeader
        title="PCAP Analyzer"
        description="Analyses of packet captures (Zeek, Suricata, TShark) across this organization's investigations."
      />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Select
          value={status}
          onValueChange={(value) => {
            setStatus(value as AnalysisStatus | typeof ALL);
            setOffset(0);
          }}
        >
          <SelectTrigger className="w-40" aria-label="Status filter">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All statuses</SelectItem>
            {ANALYSIS_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {ANALYSIS_STATUS_LABELS[s]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {list.isError && <QueryError error={list.error} onRetry={() => void list.refetch()} />}
      <div className="mt-3 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-32">Status</TableHead>
              <TableHead>Evidence</TableHead>
              <TableHead className="w-32">Findings</TableHead>
              <TableHead className="w-24">Case</TableHead>
              <TableHead className="w-24">Trigger</TableHead>
              <TableHead className="w-40">Requested by</TableHead>
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
                  <TableCell className="max-w-80 truncate" title={job.evidence_filename}>
                    <Link className="hover:underline" href={orgPath(orgId, `evidence/${job.evidence_id}`)}>
                      {job.evidence_filename}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <FindingCount job={job} />
                  </TableCell>
                  <TableCell>
                    <Link
                      className="text-xs underline underline-offset-4"
                      href={orgPath(orgId, `investigations/${job.investigation_id}`)}
                    >
                      Open case
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant={job.auto ? "secondary" : "outline"}>{job.auto ? "Auto" : "Manual"}</Badge>
                  </TableCell>
                  <TableCell className="max-w-40 truncate text-muted-foreground" title={job.requested_by_name}>
                    {job.requested_by_name}
                  </TableCell>
                  <TableCell title={created.utc} className="text-muted-foreground">
                    {created.local}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground tabular-nums">
                    {jobDurationText(job, now)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Link className="text-xs underline underline-offset-4" href={orgPath(orgId, `pcap/${job.id}`)}>
                      Details
                    </Link>
                  </TableCell>
                </TableRow>
              );
            })}
            {list.data?.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={COLUMNS} className="py-10 text-center text-muted-foreground">
                  {status !== ALL ? (
                    `No ${ANALYSIS_STATUS_LABELS[status].toLowerCase()} analyses.`
                  ) : (
                    <>
                      No analyses yet. Packet captures (pcap / pcapng) uploaded as evidence are analyzed
                      automatically; analyses can also be started from an evidence page.
                    </>
                  )}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="mt-3">
        <Pager offset={offset} total={list.data?.total ?? 0} onChange={setOffset} />
      </div>
    </>
  );
}
