"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { CommonBadge, type KeyTarget, OccurrenceList, WhenText } from "@/components/correlation/correlation-parts";
import { IocValue } from "@/components/ioc-collections/ioc-parts";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { visText } from "@/lib/case";
import {
  type CorrelationLookup,
  collectionHref,
  collectionsText,
  correlationKeys,
  fetchKeyLookup,
  isUnnormalizableError,
  kindLabel,
  lookupSummary,
  tiHistoryText,
  tiLookupType,
} from "@/lib/correlation";
import { historyHref } from "@/lib/ti";

/**
 * Where one observable was also observed in the org (`POST /correlations/lookup`, the value in
 * the body, RT13; the server normalizes it): the jobs and cases with links, first and last seen,
 * the count of stored threat intel answers (with a link to the IOC history page) and the IOC
 * collections holding it, all from the one lookup answer.
 */
export function KeyDrawer({
  orgId,
  target,
  onClose,
}: {
  orgId: string;
  target: KeyTarget | null;
  onClose: () => void;
}) {
  return (
    <Sheet open={target !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        {target && <KeyDrawerBody orgId={orgId} target={target} />}
      </SheetContent>
    </Sheet>
  );
}

/** The collections holding the key (pure). */
export function CollectionMemberships({ orgId, data }: { orgId: string; data: Pick<CorrelationLookup, "collections" | "collections_total"> }) {
  const collections = data.collections ?? [];
  const total = data.collections_total ?? collections.length;
  return (
    <div className="flex flex-col gap-1">
      <p className="text-sm">{collectionsText(collections.length, total)}</p>
      {collections.length > 0 && (
        <ul className="flex flex-col gap-1">
          {collections.map((c) => {
            const href = collectionHref(orgId, c);
            const label = (
              <>
                <span className="font-mono text-xs">{visText(c.case_ref)}</span> {visText(c.name)}
              </>
            );
            return (
              <li key={c.collection_id} className="flex flex-wrap items-center gap-2 text-sm">
                {href ? (
                  <Link href={href} className="underline-offset-4 hover:underline">
                    {label}
                  </Link>
                ) : (
                  <span>{label}</span>
                )}
                {c.archived && <Badge variant="outline">Archived</Badge>}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function KeyDrawerBody({ orgId, target }: { orgId: string; target: KeyTarget }) {
  const lookup = useQuery({
    queryKey: correlationKeys.lookup(orgId, target.kind, target.value),
    queryFn: () => fetchKeyLookup(orgId, target.kind, target.value),
    // A value that does not normalize answers 422: retrying cannot help.
    retry: (count, error) => !isUnnormalizableError(error) && count < 2,
  });
  const tiType = tiLookupType(target.kind);
  const data = lookup.data;
  const tiValue = data?.value_norm ?? target.value;

  return (
    <>
      <SheetHeader>
        <SheetTitle>Also observed in</SheetTitle>
        <SheetDescription>
          Other jobs and cases of this organization where this {kindLabel(target.kind)} value was observed. A shared
          observable is a fact about the data only.
        </SheetDescription>
      </SheetHeader>
      <div className="flex flex-col gap-4 px-4 pb-6">
        <IocValue value={target.value} type={target.kind} reveal={false} />
        {lookup.isError && isUnnormalizableError(lookup.error) ? (
          <p className="text-sm text-muted-foreground">This value could not be normalized, so it is not indexed.</p>
        ) : lookup.isError ? (
          <QueryError error={lookup.error} onRetry={() => void lookup.refetch()} />
        ) : !data ? (
          <p className="text-sm text-muted-foreground" role="status">
            Loading…
          </p>
        ) : data.key === null ? (
          <p className="text-sm text-muted-foreground">This value could not be normalized, so it is not indexed.</p>
        ) : (
          <>
            <div className="flex flex-col gap-1">
              <p className="text-sm" role="status">
                {lookupSummary(data)}
              </p>
              <span className="flex flex-wrap gap-x-3">
                <WhenText iso={data.first_seen} prefix="first seen" />
                <WhenText iso={data.last_seen} prefix="last seen" />
              </span>
              {data.common && <CommonBadge jobs={data.jobs} />}
            </div>
            {tiType && (
              <p className="text-sm">
                <Link href={historyHref(orgId, tiType, tiValue)} className="underline-offset-4 hover:underline">
                  {typeof data.ti_results === "number" ? tiHistoryText(data.ti_results) : "Threat intel history"}
                </Link>
              </p>
            )}
            <CollectionMemberships orgId={orgId} data={data} />
            {data.items.length > 0 && <OccurrenceList orgId={orgId} items={data.items} />}
            {data.items.length < data.jobs && (
              <p className="text-xs text-muted-foreground">Showing the {data.items.length} most recent jobs.</p>
            )}
          </>
        )}
      </div>
    </>
  );
}
