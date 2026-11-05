"use client";

import { FolderPlus, Plus } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { CollectionDetail } from "@/components/ioc-collections/collection-detail";
import { AddResultList, CopyValue, IocValue } from "@/components/ioc-collections/ioc-parts";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import type { JobRoute } from "@/lib/ai";
import { type Investigation, caseErrorMessage, visText } from "@/lib/case";
import { formatDate } from "@/lib/format";
import {
  COLLECTION_DESCRIPTION_MAX,
  COLLECTION_NAME_MAX,
  type CaseIoc,
  type IocItemManual,
  type IocItemsAddResult,
  selectionToItems,
} from "@/lib/ioc-collections";
import { orgPath } from "@/lib/nav";
import { IOC_TYPE_LABELS, type IocType } from "@/lib/pcap-results";
import type { Permission } from "@/lib/roles";
import { historyHref, lookupTypeForIoc } from "@/lib/ti";
import { useAddItems, useCaseIocs, useCollections, useCreateCollection, useJobRoutes } from "@/lib/use-case";
import { useDebounced } from "@/lib/use-debounced";

const PAGE = 100;
const TYPES = Object.entries(IOC_TYPE_LABELS) as [IocType, string][];

/**
 * IOCs tab: the case-wide deduplicated IOC list (defanged by default, cursor paging) with
 * "Add to collection", and the case's collections with their items and exports.
 */
export function CaseIocsTab({
  orgId,
  inv,
  can,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
}) {
  const [reveal, setReveal] = useState(false);
  const [openCollection, setOpenCollection] = useState<string | null>(null);
  const routes = useJobRoutes(orgId, inv.id);
  return (
    <div className="flex flex-col gap-6">
      <label className="flex w-fit items-center gap-1.5 text-sm">
        <input type="checkbox" checked={reveal} onChange={(event) => setReveal(event.target.checked)} />
        Show values in clear (not defanged)
      </label>
      <Card>
        <CardHeader>
          <CardTitle>Collections</CardTitle>
        </CardHeader>
        <CardContent>
          {openCollection ? (
            <CollectionDetail
              orgId={orgId}
              inv={inv}
              collectionId={openCollection}
              can={can}
              reveal={reveal}
              routes={routes}
              onBack={() => setOpenCollection(null)}
            />
          ) : (
            <CollectionList orgId={orgId} inv={inv} can={can} onOpen={setOpenCollection} />
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Case IOCs</CardTitle>
        </CardHeader>
        <CardContent>
          <CaseIocTable orgId={orgId} inv={inv} can={can} reveal={reveal} routes={routes} />
        </CardContent>
      </Card>
    </div>
  );
}

function CollectionList({
  orgId,
  inv,
  can,
  onOpen,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
  onOpen: (id: string) => void;
}) {
  const collections = useCollections(orgId, inv.id);
  const items = collections.data?.items ?? [];
  const writable = can("investigation.write") && inv.status !== "archived";
  return (
    <div className="flex flex-col gap-3">
      {writable ? <NewCollectionDialog orgId={orgId} investigationId={inv.id} onCreated={onOpen} /> : null}
      {collections.isError ? (
        <p className="text-sm text-destructive" role="alert">
          {caseErrorMessage(collections.error)}
        </p>
      ) : collections.isPending ? (
        <p className="text-sm text-muted-foreground">Loading collections…</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No collections yet. Select IOCs below and add them to a new one.</p>
      ) : (
        <ul className="flex flex-col divide-y rounded-md border">
          {items.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
              <button type="button" className="min-w-0 truncate text-left font-medium hover:underline" onClick={() => onOpen(c.id)}>
                {visText(c.name)}
              </button>
              {c.archived ? <span className="text-xs text-muted-foreground">archived</span> : null}
              <span className="ml-auto text-xs text-muted-foreground tabular-nums">{c.item_count} items</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function NewCollectionDialog({
  orgId,
  investigationId,
  onCreated,
  trigger,
}: {
  orgId: string;
  investigationId: string;
  onCreated: (id: string) => void;
  trigger?: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const create = useCreateCollection(orgId, investigationId);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button variant="outline" size="sm" className="w-fit">
            <Plus className="size-4" aria-hidden /> New collection
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New IOC collection</DialogTitle>
          <DialogDescription>A named set of indicators of this case, exportable as CSV, JSON or STIX 2.1.</DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate(
              { name: name.trim(), description: description.trim() },
              {
                onSuccess: (created) => {
                  setOpen(false);
                  setName("");
                  setDescription("");
                  onCreated(created.id);
                },
                onError: (error) => toast.error(caseErrorMessage(error)),
              },
            );
          }}
        >
          <Input aria-label="Name" placeholder="Name" required maxLength={COLLECTION_NAME_MAX} value={name}
            onChange={(event) => setName(event.target.value)} />
          <Textarea aria-label="Description" placeholder="Description (optional)" rows={3}
            maxLength={COLLECTION_DESCRIPTION_MAX} value={description} onChange={(event) => setDescription(event.target.value)} />
          <DialogFooter>
            <Button type="submit" disabled={create.isPending || !name.trim()}>
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function CaseIocTable({
  orgId,
  inv,
  can,
  reveal,
  routes,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
  reveal: boolean;
  routes: ReadonlyMap<string, JobRoute>;
}) {
  const [type, setType] = useState<string>("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Map<string, CaseIoc>>(new Map());
  const q = useDebounced(search.trim());
  const iocs = useCaseIocs(orgId, inv.id, { type: type || undefined, q: q || undefined, limit: PAGE });
  const rows = iocs.data?.pages.flatMap((page) => page.items) ?? [];
  const total = iocs.data?.pages[0]?.total;
  const writable = can("investigation.write") && inv.status !== "archived";
  const tiBlocked = inv.share_policy.ti_blocked;
  const toggle = (ioc: CaseIoc) =>
    setSelected((prev) => {
      const next = new Map(prev);
      if (next.has(ioc.ioc_key)) next.delete(ioc.ioc_key);
      else next.set(ioc.ioc_key, ioc);
      return next;
    });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <select
          aria-label="IOC type filter"
          className="h-9 rounded-md border border-input bg-background px-2 text-sm"
          value={type}
          onChange={(event) => setType(event.target.value)}
        >
          <option value="">All types</option>
          {TYPES.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <Input className="w-64" type="search" placeholder="Search values" aria-label="Search case IOC values"
          maxLength={200} value={search} onChange={(event) => setSearch(event.target.value)} />
        {writable ? (
          <AddToCollectionDialog
            orgId={orgId}
            investigationId={inv.id}
            selection={[...selected.values()]}
            onDone={() => setSelected(new Map())}
          />
        ) : null}
        <span className="ml-auto text-xs text-muted-foreground tabular-nums">
          {total != null ? `${total} IOCs` : `${rows.length}${iocs.hasNextPage ? "+" : ""} IOCs`}
        </span>
      </div>
      {iocs.isError ? (
        <p className="text-sm text-destructive" role="alert">
          {caseErrorMessage(iocs.error)}
        </p>
      ) : null}
      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              {writable ? <TableHead className="w-8"><span className="sr-only">Select</span></TableHead> : null}
              <TableHead className="w-28">Type</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-24 text-right">Analyses</TableHead>
              <TableHead className="w-40">First / last seen</TableHead>
              <TableHead className="w-28">Collections</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {iocs.isPending ? (
              <TableRow>
                <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                  Loading IOCs…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                  {type || q ? "No IOCs match these filters." : "No IOCs in the latest analyses of this case."}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((ioc) => {
                const lookup = lookupTypeForIoc(ioc.ioc_type);
                return (
                  <TableRow key={ioc.ioc_key}>
                    {writable ? (
                      <TableCell>
                        <input
                          type="checkbox"
                          aria-label="Select IOC"
                          checked={selected.has(ioc.ioc_key)}
                          onChange={() => toggle(ioc)}
                        />
                      </TableCell>
                    ) : null}
                    <TableCell className="text-xs">{IOC_TYPE_LABELS[ioc.ioc_type as IocType] ?? ioc.ioc_type}</TableCell>
                    <TableCell>
                      <span className="flex items-start gap-1">
                        <IocValue value={ioc.value} type={ioc.ioc_type} reveal={reveal} />
                        <CopyValue value={ioc.value} />
                      </span>
                      {!tiBlocked && lookup ? (
                        <Link href={historyHref(orgId, lookup, ioc.value)} className="text-[11px] underline-offset-4 hover:underline">
                          Look up / history
                        </Link>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      <JobLinks orgId={orgId} jobIds={ioc.job_ids} count={ioc.count_jobs} routes={routes} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {ioc.first_seen ? formatDate(ioc.first_seen).local : "—"}
                      <span className="block">{ioc.last_seen ? formatDate(ioc.last_seen).local : ""}</span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground tabular-nums">
                      {ioc.in_collections.length > 0 ? `in ${ioc.in_collections.length}` : "—"}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
      {iocs.hasNextPage && (
        <Button variant="outline" size="sm" className="w-fit" disabled={iocs.isFetchingNextPage} onClick={() => void iocs.fetchNextPage()}>
          Load more
        </Button>
      )}
      {tiBlocked ? (
        <p className="text-[11px] text-muted-foreground">
          Threat-intel lookups are hidden: the share policy of this case blocks threat-intel providers.
        </p>
      ) : null}
    </div>
  );
}

function JobLinks({
  orgId,
  jobIds,
  count,
  routes,
}: {
  orgId: string;
  jobIds: readonly string[];
  count: number;
  routes: ReadonlyMap<string, JobRoute>;
}) {
  return (
    <span className="inline-flex flex-wrap justify-end gap-1">
      {jobIds.slice(0, 5).map((id, index) => {
        const route = routes.get(id);
        return route ? (
          <Link key={id} href={orgPath(orgId, `${route}/${id}?tab=iocs`)} className="underline-offset-4 hover:underline">
            #{index + 1}
          </Link>
        ) : null;
      })}
      <span className="text-muted-foreground">({count})</span>
    </span>
  );
}

function AddToCollectionDialog({
  orgId,
  investigationId,
  selection,
  onDone,
}: {
  orgId: string;
  investigationId: string;
  selection: CaseIoc[];
  onDone: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const [last, setLast] = useState<{ result: IocItemsAddResult; submitted: IocItemManual[] } | null>(null);
  const collections = useCollections(orgId, investigationId);
  const add = useAddItems(orgId, investigationId);
  const choices = (collections.data?.items ?? []).filter((c) => !c.archived);
  const chosen = target || choices[0]?.id || "";
  const { items, skipped } = selectionToItems(selection);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setLast(null);
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={selection.length === 0}>
          <FolderPlus className="size-4" aria-hidden /> Add to collection ({selection.length})
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add {selection.length} IOCs to a collection</DialogTitle>
          <DialogDescription>
            Values are normalized by the server; duplicates are reported, not added twice.
            {skipped > 0 ? ` ${skipped} selected values of types without threat-intel support are skipped.` : ""}
          </DialogDescription>
        </DialogHeader>
        {choices.length === 0 ? (
          <div className="flex flex-col gap-2 text-sm text-muted-foreground">
            <p>No open collection in this case yet.</p>
            <NewCollectionDialog orgId={orgId} investigationId={investigationId} onCreated={setTarget} />
          </div>
        ) : (
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Collection</span>
            <select
              className="h-9 rounded-md border border-input bg-background px-2 text-sm"
              value={chosen}
              onChange={(event) => setTarget(event.target.value)}
            >
              {choices.map((c) => (
                <option key={c.id} value={c.id}>
                  {visText(c.name)}
                </option>
              ))}
            </select>
          </label>
        )}
        {last ? <AddResultList result={last.result} submitted={last.submitted} /> : null}
        <DialogFooter>
          <Button
            disabled={!chosen || items.length === 0 || add.isPending}
            onClick={() =>
              add.mutate(
                { collectionId: chosen, items },
                {
                  onSuccess: (result) => {
                    setLast({ result, submitted: items });
                    onDone();
                  },
                  onError: (error) => toast.error(caseErrorMessage(error)),
                },
              )
            }
          >
            Add
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
