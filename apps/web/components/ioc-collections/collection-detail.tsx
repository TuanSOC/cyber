"use client";

import { ArrowLeft, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { CollectionExportMenu } from "@/components/ioc-collections/export-menu";
import { AddResultList, CopyValue, IocValue } from "@/components/ioc-collections/ioc-parts";
import { ManualAddForm } from "@/components/ioc-collections/manual-add-form";
import { AddToReportButton } from "@/components/reports/add-to-report";
import { ProviderChip } from "@/components/ti/provider-chip";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { JobRoute } from "@/lib/ai";
import { type Investigation, caseErrorMessage, visText } from "@/lib/case";
import { formatDate } from "@/lib/format";
import type { IocItemManual, IocItemsAddResult } from "@/lib/ioc-collections";
import { tiChipSource } from "@/lib/ioc-collections";
import { orgPath } from "@/lib/nav";
import type { Permission } from "@/lib/roles";
import { historyHref, lookupTypeForIoc, tiIocTypeLabel } from "@/lib/ti";
import { useAddItems, useCollection, useCollectionItems, useRemoveItem, useUpdateCollection } from "@/lib/use-case";
import { useDebounced } from "@/lib/use-debounced";

/** One collection: items with attributed TI chips, remove, manual add, export and archive. */
export function CollectionDetail({
  orgId,
  inv,
  collectionId,
  can,
  reveal,
  routes,
  onBack,
}: {
  orgId: string;
  inv: Investigation;
  collectionId: string;
  can: (permission: Permission) => boolean;
  reveal: boolean;
  routes: ReadonlyMap<string, JobRoute>;
  onBack: () => void;
}) {
  const [search, setSearch] = useState("");
  const [showRemoved, setShowRemoved] = useState(false);
  const [lastAdd, setLastAdd] = useState<{ result: IocItemsAddResult; submitted: IocItemManual[] } | null>(null);
  const q = useDebounced(search.trim());
  const detail = useCollection(orgId, collectionId);
  const items = useCollectionItems(orgId, collectionId, { q: q || undefined, includeRemoved: showRemoved });
  const add = useAddItems(orgId, inv.id);
  const remove = useRemoveItem(orgId, inv.id, collectionId);
  const update = useUpdateCollection(orgId, inv.id, collectionId);
  const collection = detail.data?.collection;
  const writable = can("investigation.write") && inv.status !== "archived" && !collection?.archived;
  // Citing in a report draft needs the case to be writable (the collection may be archived).
  const citeIn = can("investigation.write") && inv.status !== "archived" ? inv.id : undefined;
  const rows = items.data?.pages.flatMap((page) => page.items) ?? [];
  const tiBlocked = inv.share_policy.ti_blocked;

  return (
    <div className="flex flex-col gap-3">
      <Button variant="ghost" size="sm" className="w-fit" onClick={onBack}>
        <ArrowLeft className="size-4" aria-hidden /> All collections
      </Button>
      {detail.isError ? (
        <p className="text-sm text-destructive" role="alert">
          {caseErrorMessage(detail.error)}
        </p>
      ) : !collection ? (
        <p className="text-sm text-muted-foreground">Loading the collection…</p>
      ) : (
        <>
          <div className="flex flex-wrap items-baseline gap-2">
            <h3 className="text-base font-semibold break-all">{visText(collection.name)}</h3>
            {collection.archived ? <Badge variant="outline">archived</Badge> : null}
            <span className="text-xs text-muted-foreground">
              {collection.item_count} items ·{" "}
              {Object.entries(detail.data?.counts_by_type ?? {})
                .map(([type, n]) => `${tiIocTypeLabel(type)} ${n}`)
                .join(", ") || "empty"}
            </span>
          </div>
          {collection.description ? (
            <p className="text-sm whitespace-pre-wrap text-muted-foreground">{visText(collection.description)}</p>
          ) : null}
          <CollectionExportMenu
            orgId={orgId}
            collectionId={collectionId}
            name={collection.name}
            tlp={inv.tlp}
            canWrite={can("evidence.write")}
          />
          {can("investigation.write") && inv.status !== "archived" ? (
            <Button
              variant="outline"
              size="sm"
              className="w-fit"
              disabled={update.isPending}
              onClick={() =>
                update.mutate(
                  { archived: !collection.archived },
                  { onError: (error) => toast.error(caseErrorMessage(error)) },
                )
              }
            >
              {collection.archived ? "Unarchive collection" : "Archive collection"}
            </Button>
          ) : null}
        </>
      )}
      {writable ? (
        <ManualAddForm
          pending={add.isPending}
          onAdd={(item) =>
            add.mutate(
              { collectionId, items: [item] },
              {
                onSuccess: (result) => setLastAdd({ result, submitted: [item] }),
                onError: (error) => toast.error(caseErrorMessage(error)),
              },
            )
          }
        />
      ) : null}
      {lastAdd ? <AddResultList result={lastAdd.result} submitted={lastAdd.submitted} /> : null}
      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="w-64"
          type="search"
          placeholder="Search values"
          aria-label="Search collection values"
          maxLength={200}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <label className="flex items-center gap-1.5 text-xs">
          <input type="checkbox" checked={showRemoved} onChange={(event) => setShowRemoved(event.target.checked)} />
          Show removed items
        </label>
      </div>
      {items.isError ? (
        <p className="text-sm text-destructive" role="alert">
          {caseErrorMessage(items.error)}
        </p>
      ) : null}
      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">Type</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-56">Threat intel (attributed)</TableHead>
              <TableHead className="w-40">Added</TableHead>
              <TableHead className="w-36" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.isPending ? (
              <TableRow>
                <TableCell colSpan={5} className="py-6 text-center text-muted-foreground">
                  Loading items…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="py-6 text-center text-muted-foreground">
                  No items.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((item) => {
                const added = formatDate(item.added_at);
                const lookup = lookupTypeForIoc(item.ioc_type);
                return (
                  <TableRow key={item.id} className={item.removed_at ? "opacity-60" : undefined}>
                    <TableCell className="text-xs">{tiIocTypeLabel(item.ioc_type)}</TableCell>
                    <TableCell>
                      <span className="flex items-start gap-1">
                        <IocValue value={item.value} type={item.ioc_type} reveal={reveal} />
                        <CopyValue value={item.value} />
                      </span>
                      {item.note ? <span className="block text-xs text-muted-foreground">{visText(item.note)}</span> : null}
                      {item.removed_at ? <span className="block text-xs text-muted-foreground">removed</span> : null}
                    </TableCell>
                    <TableCell>
                      <span className="flex flex-wrap gap-1">
                        {item.ti.length === 0 ? (
                          <span className="text-xs text-muted-foreground">
                            {item.ti_eligible ? "not looked up" : "never sent to providers"}
                          </span>
                        ) : (
                          item.ti.map((t) => <ProviderChip key={`${t.provider}-${t.fetched_at}`} e={tiChipSource(t)} />)
                        )}
                      </span>
                      {!tiBlocked && lookup && item.ti_eligible ? (
                        <Link href={historyHref(orgId, lookup, item.value)} className="text-[11px] underline-offset-4 hover:underline">
                          Look up / history
                        </Link>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground" title={added.utc}>
                      {added.local}
                      <span className="block">{item.added_by_name}</span>
                      {item.job_id && routes.get(item.job_id) ? (
                        <Link
                          href={orgPath(orgId, `${routes.get(item.job_id)}/${item.job_id}?tab=iocs`)}
                          className="block underline-offset-4 hover:underline"
                        >
                          source analysis
                        </Link>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      {citeIn && !item.removed_at && item.source === "job_ioc" && item.ioc_id ? (
                        // Only items taken from an analysis have an IOC row to cite; manual
                        // items are cited through the collection section of the report.
                        <AddToReportButton
                          orgId={orgId}
                          investigationId={citeIn}
                          row={{ kind: "ioc", ref_id: item.ioc_id, ...(item.job_id ? { job_id: item.job_id } : {}) }}
                        />
                      ) : null}
                      {writable && !item.removed_at ? (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          aria-label="Remove from the collection"
                          disabled={remove.isPending}
                          onClick={() => remove.mutate(item.id, { onError: (error) => toast.error(caseErrorMessage(error)) })}
                        >
                          <Trash2 className="size-4" aria-hidden />
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
      {items.hasNextPage && (
        <Button variant="outline" size="sm" className="w-fit" disabled={items.isFetchingNextPage} onClick={() => void items.fetchNextPage()}>
          Load more
        </Button>
      )}
      <p className="text-[11px] text-muted-foreground">
        Threat-intel chips quote each provider&apos;s own answer with its date; they are attributed statements, not our
        assessment.
      </p>
    </div>
  );
}
