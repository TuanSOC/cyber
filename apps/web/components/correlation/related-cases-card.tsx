"use client";

import { useQuery } from "@tanstack/react-query";

import { RelatedCasesList } from "@/components/correlation/correlation-parts";
import { QueryError } from "@/components/query-error";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import { correlationKeys, excludedText, fetchRelatedCases } from "@/lib/correlation";

/**
 * Cases sharing observables with this one, ranked by the number of shared observables (slot from
 * phase 1, RT16). Counts only, no score; common observables are left out of the ranking.
 */
export function RelatedCasesCard({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const query = useQuery({
    queryKey: correlationKeys.related(orgId, investigationId),
    queryFn: () => fetchRelatedCases(orgId, investigationId),
  });
  if (query.isError && query.error instanceof ApiError && query.error.code === "not_implemented") return null;
  const data = query.data;
  const excluded = data ? excludedText(data.common_keys_excluded) : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Related cases</CardTitle>
        <CardDescription>Other cases where the same observables were also observed.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : !data ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : data.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No shared observables.</p>
        ) : (
          <RelatedCasesList orgId={orgId} items={data.items} />
        )}
        {excluded && <p className="text-xs text-muted-foreground">{excluded}</p>}
      </CardContent>
    </Card>
  );
}
