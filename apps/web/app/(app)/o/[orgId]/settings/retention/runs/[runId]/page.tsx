"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

import { NotFoundCard } from "@/components/not-found-card";
import { QueryError } from "@/components/query-error";
import { RetentionRunDetailView } from "@/components/retention/run-detail";
import { ApiError } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { FIRST_ITEMS_PAGE, type RunItemsQuery, fetchRun, isActiveRun, retentionKeys } from "@/lib/retention";

export default function RetentionRunPage() {
  const { runId } = useParams<{ runId: string }>();
  const { orgId, can } = useOrg();
  const [items, setItems] = useState<RunItemsQuery>(FIRST_ITEMS_PAGE);
  const run = useQuery({
    queryKey: retentionKeys.runPage(orgId, runId, items),
    queryFn: () => fetchRun(orgId, runId, items),
    enabled: can("audit.read"),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => (query.state.data && isActiveRun(query.state.data) ? 5_000 : false),
  });
  const back = orgPath(orgId, "settings/retention");

  if (!can("audit.read")) {
    return <p className="text-sm text-muted-foreground">Only owners and admins can view retention runs.</p>;
  }
  if (run.error instanceof ApiError && run.error.status === 404) {
    return <NotFoundCard title="Retention run not found" backHref={back} backLabel="Retention" />;
  }
  return (
    <div className="flex max-w-5xl flex-col gap-4">
      <Link href={back} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Retention
      </Link>
      {run.isError ? (
        <QueryError error={run.error} onRetry={() => void run.refetch()} />
      ) : run.data ? (
        <RetentionRunDetailView run={run.data} query={items} onQuery={setItems} loading={run.isPlaceholderData} />
      ) : (
        <p className="text-sm text-muted-foreground">Loading run…</p>
      )}
    </div>
  );
}
