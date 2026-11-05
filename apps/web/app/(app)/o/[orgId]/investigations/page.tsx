"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import {
  ALL,
  type Filters,
  InvestigationFilters,
} from "@/components/investigations/investigation-filters";
import { LegalHoldBadge } from "@/components/investigations/legal-hold-badge";
import { NewInvestigationDialog } from "@/components/investigations/new-investigation-dialog";
import { PageHeader } from "@/components/page-header";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { STATUS_LABELS, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useDebounced } from "@/lib/use-debounced";

const INITIAL: Filters = { q: "", status: ALL, severity: ALL, sort: "-created_at" };

export default function InvestigationsPage() {
  const { orgId, can } = useOrg();
  const [filters, setFilters] = useState<Filters>(INITIAL);
  const [offset, setOffset] = useState(0);
  const q = useDebounced(filters.q.trim());

  const params = {
    q: q || undefined,
    status: filters.status === ALL ? undefined : filters.status,
    severity: filters.severity === ALL ? undefined : filters.severity,
    sort: filters.sort,
    limit: PAGE_SIZE,
    offset,
  };
  const list = useQuery({
    queryKey: ["org", orgId, "investigations", params],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations", {
          params: { path: { org_id: orgId }, query: params },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  const filtered = Boolean(q) || filters.status !== ALL || filters.severity !== ALL;

  return (
    <>
      <PageHeader
        title="Investigations"
        description="Cases and their evidence."
        actions={can("investigation.write") && <NewInvestigationDialog orgId={orgId} />}
      />
      <InvestigationFilters
        value={filters}
        onChange={(next) => {
          setFilters(next);
          setOffset(0);
        }}
      />
      {list.isError && <QueryError error={list.error} onRetry={() => void list.refetch()} />}
      <div className="mt-3 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-32">Case</TableHead>
              <TableHead>Title</TableHead>
              <TableHead className="w-28">Severity</TableHead>
              <TableHead className="w-32">Status</TableHead>
              <TableHead className="w-24 text-right">Evidence</TableHead>
              <TableHead className="w-44">Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isPending && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                  Loading investigations…
                </TableCell>
              </TableRow>
            )}
            {list.data?.items.map((inv) => {
              const created = formatDate(inv.created_at);
              return (
                <TableRow key={inv.id}>
                  <TableCell className="font-mono text-xs">{inv.case_ref}</TableCell>
                  <TableCell className="max-w-96 truncate" title={inv.title}>
                    <Link className="hover:underline" href={orgPath(orgId, `investigations/${inv.id}`)}>
                      {inv.title}
                    </Link>
                    {/* M7 slot: legal-hold badge (phase 9). */}
                    <LegalHoldBadge legalHold={inv.legal_hold} />
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={inv.severity} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">{STATUS_LABELS[inv.status]}</Badge>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{inv.evidence_count}</TableCell>
                  <TableCell title={created.utc} className="text-muted-foreground">
                    {created.local}
                  </TableCell>
                </TableRow>
              );
            })}
            {list.data?.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">
                  {filtered ? "No investigations match these filters." : "No investigations yet."}
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
