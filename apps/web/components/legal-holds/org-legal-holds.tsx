"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { PlaceHoldButton } from "@/components/legal-holds/hold-actions";
import { HoldList } from "@/components/legal-holds/hold-list";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { HOLD_PAGE_SIZE, fetchHolds, holdKeys } from "@/lib/legal-holds";
import { useNow } from "@/lib/use-now";

/** The org's legal holds (active and released), with place / release for `org.update`. */
export function OrgLegalHolds({
  orgId,
  canManage,
  delayDays,
}: {
  orgId: string;
  canManage: boolean;
  delayDays: number;
}) {
  const [offset, setOffset] = useState(0);
  const [activeOnly, setActiveOnly] = useState(false);
  const now = useNow(true, 60_000);
  const holds = useQuery({
    queryKey: holdKeys.list(orgId, { activeOnly, offset }),
    queryFn: () => fetchHolds(orgId, { activeOnly, offset, limit: HOLD_PAGE_SIZE }),
    placeholderData: keepPreviousData,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Legal holds</CardTitle>
        <CardDescription>
          Data covered by an active hold, or by a hold released less than {delayDays} days ago, is never purged by
          retention. An organization hold covers every case.
        </CardDescription>
        {canManage && (
          <CardAction>
            <PlaceHoldButton orgId={orgId} />
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            className="size-4"
            checked={activeOnly}
            onChange={(event) => {
              setActiveOnly(event.target.checked);
              setOffset(0);
            }}
          />
          Still protecting only
        </label>
        {holds.isError ? (
          <QueryError error={holds.error} onRetry={() => void holds.refetch()} />
        ) : holds.data ? (
          <HoldList orgId={orgId} holds={holds.data.items} now={now} canManage={canManage} delayDays={delayDays} />
        ) : (
          <p className="text-sm text-muted-foreground">Loading legal holds…</p>
        )}
        <Pager offset={offset} total={holds.data?.total ?? 0} pageSize={HOLD_PAGE_SIZE} onChange={setOffset} />
      </CardContent>
    </Card>
  );
}
