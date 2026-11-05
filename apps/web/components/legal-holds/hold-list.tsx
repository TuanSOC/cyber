"use client";

import { ReleaseHoldButton } from "@/components/legal-holds/hold-actions";
import { Badge } from "@/components/ui/badge";
import { type LegalHold, HOLD_STATE_LABELS, holdScopeLabel, holdState, s3SyncLabel } from "@/lib/legal-holds";
import { formatDay, formatDayTime, labelText } from "@/lib/retention";

/**
 * Holds as a list. Reasons and names are user text, rendered as text. The release action shows
 * only with `canManage` (`org.update`) and only on holds not released yet.
 */
export function HoldList({
  orgId,
  holds,
  now,
  canManage,
  delayDays,
  showScope = true,
}: {
  orgId: string;
  holds: readonly LegalHold[];
  now: number;
  canManage: boolean;
  delayDays: number;
  showScope?: boolean;
}) {
  if (holds.length === 0) return <p className="text-sm text-muted-foreground">No legal holds.</p>;
  return (
    <ul className="flex flex-col divide-y">
      {holds.map((hold) => {
        const state = holdState(hold, now);
        const sync = s3SyncLabel(hold);
        return (
          <li key={hold.id} className="flex flex-col gap-1.5 py-3 first:pt-0 last:pb-0" data-hold-state={state}>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={state === "released" ? "outline" : "secondary"}>{HOLD_STATE_LABELS[state]}</Badge>
              {showScope && <span className="text-sm font-medium">{labelText(holdScopeLabel(hold), 40)}</span>}
              {sync && state !== "released" && (
                <span className="text-xs text-muted-foreground" title="Set by the retention worker shortly after the hold is placed.">
                  {sync}
                </span>
              )}
              {canManage && !hold.released_at && (
                <span className="ml-auto">
                  <ReleaseHoldButton orgId={orgId} hold={hold} delayDays={delayDays} />
                </span>
              )}
            </div>
            <p className="text-sm break-words whitespace-pre-wrap">{hold.reason}</p>
            <p className="text-xs text-muted-foreground">
              Placed by {labelText(hold.placed_by_name, 80)} on {formatDayTime(hold.placed_at)}
              {hold.released_at ? ` · released on ${formatDayTime(hold.released_at)}` : ""}
              {state === "protecting" && hold.protects_until ? ` · protects until ${formatDay(hold.protects_until)}` : ""}
            </p>
            {hold.release_reason && (
              <p className="text-xs break-words whitespace-pre-wrap text-muted-foreground">
                Release reason: {hold.release_reason}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}
