"use client";

import { Download } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { TlpBadge } from "@/components/tlp/tlp-badge";
import { TimelineRow } from "@/components/timeline/timeline-parts";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  type Investigation,
  type RefKindName,
  TIMELINE_EXPORT_MAX_ROWS,
  TIMELINE_KINDS,
  TIMELINE_KIND_LABELS,
  caseErrorMessage,
} from "@/lib/case";
import type { Permission } from "@/lib/roles";
import { useCaseTimeline, useExportTimeline, useJobRoutes } from "@/lib/use-case";

/** Timeline tab: the merged case timeline with a kinds filter and the CSV / JSON export. */
export function CaseTimeline({
  orgId,
  inv,
  can,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
}) {
  const [kinds, setKinds] = useState<RefKindName[]>([]);
  const timeline = useCaseTimeline(orgId, inv.id, kinds);
  const routes = useJobRoutes(orgId, inv.id);
  const exporter = useExportTimeline(orgId, inv.id);
  const rows = timeline.data?.pages.flatMap((page) => page.items) ?? [];
  // Report drafts change only with investigation.write on a case that is not archived.
  const citeIn = can("investigation.write") && inv.status !== "archived" ? inv.id : undefined;
  const toggle = (kind: RefKindName) =>
    setKinds((prev) => (prev.includes(kind) ? prev.filter((k) => k !== kind) : [...prev, kind]));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Timeline</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <fieldset className="flex flex-wrap items-center gap-2">
          <legend className="sr-only">Kinds</legend>
          <span className="text-xs text-muted-foreground">Show:</span>
          {TIMELINE_KINDS.map((kind) => (
            <label key={kind} className="flex items-center gap-1 rounded border px-2 py-0.5 text-xs">
              <input type="checkbox" checked={kinds.includes(kind)} onChange={() => toggle(kind)} />
              {TIMELINE_KIND_LABELS[kind]}
            </label>
          ))}
          {kinds.length > 0 ? (
            <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => setKinds([])}>
              All kinds
            </Button>
          ) : null}
        </fieldset>
        {can("evidence.read") ? (
          <div className="flex flex-wrap items-center gap-3">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" disabled={exporter.isPending}>
                  <Download className="size-4" aria-hidden /> Export
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                {(["csv", "json"] as const).map((format) => (
                  <DropdownMenuItem
                    key={format}
                    onSelect={() =>
                      exporter.mutate(
                        { format, kinds, caseRef: inv.case_ref },
                        {
                          onSuccess: (filename) => toast.success(`Downloaded ${filename}`),
                          onError: (error) => toast.error(caseErrorMessage(error)),
                        },
                      )
                    }
                  >
                    {format.toUpperCase()}
                    {kinds.length > 0 ? " (current filter)" : ""}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <TlpBadge tlp={inv.tlp} />
              At most {TIMELINE_EXPORT_MAX_ROWS.toLocaleString("en-US")} rows; marked with the case TLP; not redacted.
            </span>
          </div>
        ) : null}
        {timeline.isError ? (
          <p className="text-sm text-destructive" role="alert">
            {caseErrorMessage(timeline.error)}
          </p>
        ) : timeline.isPending ? (
          <p className="text-sm text-muted-foreground">Loading the timeline…</p>
        ) : rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">No events{kinds.length > 0 ? " of these kinds" : ""}.</p>
        ) : (
          <ol className="flex flex-col divide-y rounded-md border">
            {rows.map((entry) => (
              <TimelineRow
                key={`${entry.ref_kind}:${entry.ref_id}:${entry.ts}`}
                orgId={orgId}
                entry={entry}
                routes={routes}
                citeIn={citeIn}
              />
            ))}
          </ol>
        )}
        {timeline.hasNextPage && (
          <Button variant="outline" size="sm" className="w-fit" disabled={timeline.isFetchingNextPage} onClick={() => void timeline.fetchNextPage()}>
            Load more
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
