"use client";

import type { ReactNode } from "react";

import { When } from "@/components/analysis/result-parts";
import { ArtifactRow } from "@/components/memory/artifacts-tab";
import { CONNECTION_HEAD, ConnectionRow } from "@/components/memory/network-tab";
import { ProcessFlags } from "@/components/memory/process-flags";
import { RegionBytes } from "@/components/memory/regions-tab";
import { QueryError } from "@/components/query-error";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  ARTIFACT_TYPE_LABELS,
  type FlagContext,
  type MemoryProcess,
  type ProcessDetail,
  formatAddress,
  processFlags,
} from "@/lib/memory";
import { useProcessDetail } from "@/lib/use-memory-job";

function ProcLink({ p, onSelect }: { p: MemoryProcess; onSelect: (pid: number) => void }) {
  return (
    <button type="button" className="text-left underline-offset-4 hover:underline" onClick={() => onSelect(p.pid)}>
      <span className="tabular-nums">{p.pid}</span> <span className="break-all">{p.name}</span>
    </button>
  );
}

/** The body of the side panel (rendered alone in tests): every value is text. */
export function ProcessDetailView({
  detail,
  flags,
  onSelect,
}: {
  detail: ProcessDetail;
  flags: FlagContext;
  onSelect: (pid: number) => void;
}) {
  const p = detail.process;
  const facts: [string, ReactNode][] = [
    ["PID / PPID", `${p.pid} / ${p.ppid ?? "—"}`],
    ["Started", <When key="s" iso={p.create_time} />],
    ["Exited", <When key="e" iso={p.exit_time} />],
    ["Threads / handles", `${p.threads ?? "—"} / ${p.handles ?? "—"}`],
    ["Session", p.session_id ?? "—"],
    ["WoW64", p.wow64 === null ? "—" : p.wow64 ? "yes" : "no"],
    ["Seen by", p.sources.join(", ") || "—"],
    ["Offset", <span key="o" className="font-mono text-xs">{formatAddress(p.offset)}</span>],
    ["Image path", <span key="i" className="font-mono text-xs break-all">{p.image_path ?? "—"}</span>],
  ];
  return (
    <div className="flex flex-col gap-5 text-sm">
      <ProcessFlags flags={processFlags(p, flags)} />
      {detail.instances > 1 ? (
        <p className="text-xs text-muted-foreground">
          {detail.instances} process records share pid {p.pid} (pids are reused during a capture); this panel shows one.
        </p>
      ) : null}
      <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1">
        {facts.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="min-w-0">{value}</dd>
          </div>
        ))}
      </dl>
      <section>
        <h3 className="mb-1 text-xs font-medium text-muted-foreground">Command line</h3>
        {p.cmdline ? (
          <pre className="max-h-48 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-all" data-testid="process-cmdline">
            {p.cmdline}
          </pre>
        ) : (
          <p className="text-muted-foreground">—</p>
        )}
      </section>
      <section className="flex flex-col gap-1">
        <h3 className="text-xs font-medium text-muted-foreground">Parent</h3>
        {detail.parent ? <ProcLink p={detail.parent} onSelect={onSelect} /> : <p className="text-muted-foreground">Not in the image</p>}
        <h3 className="mt-2 text-xs font-medium text-muted-foreground">Children ({detail.children.length})</h3>
        {detail.children.length === 0 ? (
          <p className="text-muted-foreground">—</p>
        ) : (
          <ul className="flex flex-col gap-0.5">
            {detail.children.map((child) => (
              <li key={child.id}>
                <ProcLink p={child} onSelect={onSelect} />
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="flex flex-col gap-1">
        <h3 className="text-xs font-medium text-muted-foreground">Connections ({detail.connections.length})</h3>
        {detail.connections.length === 0 ? (
          <p className="text-muted-foreground">—</p>
        ) : (
          <div className="min-w-0 rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>{CONNECTION_HEAD}</TableRow>
              </TableHeader>
              <TableBody>
                {detail.connections.map((c) => (
                  <ConnectionRow key={c.id} c={c} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>
      <section className="flex flex-col gap-2">
        <h3 className="text-xs font-medium text-muted-foreground">Private executable regions ({detail.injections.length})</h3>
        {detail.injections.length === 0 ? (
          <p className="text-muted-foreground">—</p>
        ) : (
          detail.injections.map((region) => (
            <div key={region.id} className="flex flex-col gap-1 rounded-md border p-2">
              <p className="font-mono text-xs">
                {formatAddress(region.start)}–{formatAddress(region.end)} · {region.protection ?? "—"}
              </p>
              <RegionBytes region={region} />
            </div>
          ))
        )}
      </section>
      <section className="flex flex-col gap-1">
        <h3 className="text-xs font-medium text-muted-foreground">Artifacts ({detail.artifacts.length})</h3>
        {detail.artifacts.length === 0 ? (
          <p className="text-muted-foreground">—</p>
        ) : (
          <div className="min-w-0 rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>PID</TableHead>
                  <TableHead colSpan={4}>Attributes (expand a row for every value)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.artifacts.map((artifact) => (
                  <ArtifactRow key={artifact.id} artifact={artifact} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {detail.artifacts.length > 0 ? (
          <p className="text-xs text-muted-foreground">
            Types: {[...new Set(detail.artifacts.map((a) => ARTIFACT_TYPE_LABELS[a.type] ?? a.type))].join(", ")}
          </p>
        ) : null}
      </section>
    </div>
  );
}

/** Side panel of one process (its connections, memory regions and artifacts). */
export function ProcessPanel({
  orgId,
  jobId,
  pid,
  flags,
  onSelect,
  onClose,
}: {
  orgId: string;
  jobId: string;
  pid: number | null;
  flags: FlagContext;
  onSelect: (pid: number) => void;
  onClose: () => void;
}) {
  const detail = useProcessDetail(orgId, jobId, pid);
  return (
    <Sheet open={pid !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto data-[side=right]:sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="break-all">{detail.data ? detail.data.process.name : `Process ${pid ?? ""}`}</SheetTitle>
          <SheetDescription>pid {pid}</SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">
          {detail.isError ? (
            <QueryError error={detail.error} onRetry={() => void detail.refetch()} />
          ) : detail.data ? (
            <ProcessDetailView detail={detail.data} flags={flags} onSelect={onSelect} />
          ) : (
            <p className="text-sm text-muted-foreground">Loading…</p>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
