"use client";

import { useQuery } from "@tanstack/react-query";

import { PlaceHoldButton } from "@/components/legal-holds/hold-actions";
import { HoldList } from "@/components/legal-holds/hold-list";
import { QueryError } from "@/components/query-error";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import { DEFAULT_DELAY_DAYS, type LegalHold, fetchHolds, holdKeys, holdState } from "@/lib/legal-holds";
import { fetchPolicy, retentionKeys } from "@/lib/retention";
import type { Permission } from "@/lib/roles";
import { useNow } from "@/lib/use-now";

/** The card's content (tests render it directly). */
export function CaseHoldCardView({
  orgId,
  investigationId,
  legalHold,
  holds,
  now,
  canManage,
  delayDays,
}: {
  orgId: string;
  investigationId: string;
  legalHold: boolean;
  holds: readonly LegalHold[];
  now: number;
  canManage: boolean;
  delayDays: number;
}) {
  const caseHolds = holds.filter((hold) => hold.scope === "investigation");
  const orgHolds = holds.filter((hold) => hold.scope === "org" && holdState(hold, now) !== "released");
  const activeCaseHold = caseHolds.some((hold) => !hold.released_at);
  return (
    <Card data-slot="case-hold-card">
      <CardHeader>
        <CardTitle>Legal hold</CardTitle>
        <CardDescription>
          {legalHold
            ? "This case is under legal hold: retention purges nothing from it."
            : "No legal hold covers this case."}
        </CardDescription>
        {canManage && !activeCaseHold && (
          <CardAction>
            <PlaceHoldButton orgId={orgId} investigationId={investigationId} />
          </CardAction>
        )}
      </CardHeader>
      {(caseHolds.length > 0 || orgHolds.length > 0) && (
        <CardContent className="flex flex-col gap-3">
          {orgHolds.length > 0 && (
            <p className="text-sm text-muted-foreground">An organization-wide hold also covers this case.</p>
          )}
          {caseHolds.length > 0 && (
            <HoldList
              orgId={orgId}
              holds={caseHolds}
              now={now}
              canManage={canManage}
              delayDays={delayDays}
              showScope={false}
            />
          )}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * M7 slot (RT16), mounted once in `components/investigations/overview-tab.tsx`: the case's
 * legal hold, with place / release for `org.update` only.
 */
export function CaseHoldCard({
  orgId,
  investigationId,
  legalHold,
  can,
}: {
  orgId: string;
  investigationId: string;
  legalHold: boolean;
  can: (permission: Permission) => boolean;
}) {
  const canManage = can("org.update");
  const now = useNow(true, 60_000);
  const holds = useQuery({
    queryKey: holdKeys.list(orgId, { investigationId }),
    queryFn: () => fetchHolds(orgId, { investigationId, limit: 50 }),
    enabled: can("investigation.read"),
  });
  // Only the release dialog needs the delay; members without org.update never see it.
  const policy = useQuery({
    queryKey: retentionKeys.policy(orgId),
    queryFn: () => fetchPolicy(orgId),
    enabled: canManage,
  });
  const delayDays = policy.data?.delay_days ?? DEFAULT_DELAY_DAYS;

  if (holds.isError) {
    // Until the holds API is deployed (501), keep the overview clean.
    if (holds.error instanceof ApiError && holds.error.status === 501) return null;
    return (
      <Card>
        <CardHeader>
          <CardTitle>Legal hold</CardTitle>
        </CardHeader>
        <CardContent>
          <QueryError error={holds.error} onRetry={() => void holds.refetch()} />
        </CardContent>
      </Card>
    );
  }
  return (
    <CaseHoldCardView
      orgId={orgId}
      investigationId={investigationId}
      legalHold={legalHold}
      holds={holds.data?.items ?? []}
      now={now}
      canManage={canManage && holds.isSuccess}
      delayDays={delayDays}
    />
  );
}
