"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, unwrap } from "@/lib/api";
import { STATUS_LABELS, formatDate } from "@/lib/format";
import { NAV, orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";

function useInvestigationTotal(orgId: string, status: "open" | "in_progress") {
  return useQuery({
    queryKey: ["org", orgId, "investigations", { status, limit: 1 }],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations", {
          params: { path: { org_id: orgId }, query: { status, limit: 1 } },
        }),
      ).total,
  });
}

function RecentActivity({ orgId }: { orgId: string }) {
  const logs = useQuery({
    queryKey: ["org", orgId, "audit", { limit: 6 }],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/audit-logs", {
          params: { path: { org_id: orgId }, query: { limit: 6 } },
        }),
      ),
  });
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle className="text-base">Recent activity</CardTitle>
      </CardHeader>
      <CardContent>
        {logs.isError && <QueryError error={logs.error} onRetry={() => void logs.refetch()} />}
        <ul className="flex flex-col divide-y text-sm">
          {logs.data?.items.map((log) => (
            <li key={log.id} className="flex items-center gap-3 py-2">
              <span className="w-44 shrink-0 font-mono text-xs">{log.action}</span>
              <span className="min-w-0 flex-1 truncate text-muted-foreground">{log.actor_email ?? "system"}</span>
              <span className="text-xs text-muted-foreground" title={formatDate(log.occurred_at).utc}>
                {formatDate(log.occurred_at).local}
              </span>
            </li>
          ))}
        </ul>
        <Link className="mt-2 inline-block text-xs underline underline-offset-4" href={orgPath(orgId, "settings/audit")}>
          Full audit log
        </Link>
      </CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const { orgId, orgName, can } = useOrg();
  const open = useInvestigationTotal(orgId, "open");
  const inProgress = useInvestigationTotal(orgId, "in_progress");
  const recent = useQuery({
    queryKey: ["org", orgId, "investigations", { limit: 5 }],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations", {
          params: { path: { org_id: orgId }, query: { limit: 5 } },
        }),
      ),
  });
  const planned = NAV.filter((item) => item.plannedFor);

  return (
    <>
      <PageHeader title="Overview" description={`Workspace for ${orgName}.`} />
      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <Card>
          <CardHeader>
            <CardDescription>Open investigations</CardDescription>
            <CardTitle className="text-3xl tabular-nums">{open.data ?? "—"}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>In progress</CardDescription>
            <CardTitle className="text-3xl tabular-nums">{inProgress.data ?? "—"}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>All investigations</CardDescription>
            <CardTitle className="text-3xl tabular-nums">{recent.data?.total ?? "—"}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="text-base">Recent investigations</CardTitle>
        </CardHeader>
        <CardContent>
          {recent.isError && <QueryError error={recent.error} onRetry={() => void recent.refetch()} />}
          {recent.data?.items.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No investigations yet.{" "}
              <Link className="underline underline-offset-4" href={orgPath(orgId, "investigations")}>
                Open the investigations page
              </Link>{" "}
              to start one.
            </p>
          )}
          <ul className="flex flex-col divide-y">
            {recent.data?.items.map((inv) => (
              <li key={inv.id} className="flex items-center gap-3 py-2 text-sm">
                <span className="w-24 shrink-0 font-mono text-xs text-muted-foreground">{inv.case_ref}</span>
                <Link
                  className="min-w-0 flex-1 truncate hover:underline"
                  title={inv.title}
                  href={orgPath(orgId, `investigations/${inv.id}`)}
                >
                  {inv.title}
                </Link>
                <SeverityBadge severity={inv.severity} />
                <Badge variant="secondary">{STATUS_LABELS[inv.status]}</Badge>
                <span className="hidden w-40 text-right text-xs text-muted-foreground md:block" title={formatDate(inv.created_at).utc}>
                  {formatDate(inv.created_at).local}
                </span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      {can("audit.read") && <RecentActivity orgId={orgId} />}

      <h2 className="mb-3 text-sm font-medium text-muted-foreground">Coming in later milestones</h2>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {planned.map((item) => (
          <Link key={item.key} href={orgPath(orgId, item.segment)} className="group">
            <Card className="h-full transition-colors group-hover:border-primary/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <item.icon className="size-4" aria-hidden />
                  {item.label}
                </CardTitle>
                <CardDescription className="text-xs">Planned for {item.plannedFor}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </>
  );
}
