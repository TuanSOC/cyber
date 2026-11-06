"use client";

import { type ReactNode, useState } from "react";

import { FileFlags, FileTime } from "@/components/disk/file-row";
import { InertText } from "@/components/disk/inert-text";
import { KeyDrawer } from "@/components/correlation/key-drawer";
import type { KeyTarget } from "@/components/correlation/correlation-parts";
import { HashValue } from "@/components/hash-value";
import { QueryError } from "@/components/query-error";
import { type Severity, SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
  type DiskEvent,
  type DiskFileDetail,
  FILE_TYPE_LABELS,
  KNOWN_LABELS,
  TIME_BASIS_LOCAL,
  exportRefusalText,
  formatU64,
  pathMarkers,
} from "@/lib/disk";
import { EXPORT_REQUEST_NOTICE } from "@/lib/disk-exports";
import { artifactLabel } from "@/lib/disk-timeline";
import { formatBytes } from "@/lib/format";
import { useDiskFile, useDiskFileEvents, useDiskFileFindings } from "@/lib/use-disk-job";

type FindingLike = { id: string; title: string; severity: Severity };

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="contents">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all">{children}</dd>
    </div>
  );
}

/**
 * Everything about one file (pure; tested with a fixture): metadata, the inode's other names
 * (hard links), streams, hashes, the reference-set match, YARA rules, findings and events that
 * cite it, and Export (enabled from the API's `exportable` flag; otherwise the reason).
 */
export function FileDetailView({
  file,
  events,
  findings,
  canExport,
  inBatch,
  exportPending,
  onExport,
  onToggleBatch,
  onSeenIn,
}: {
  file: DiskFileDetail;
  events: readonly DiskEvent[] | null;
  findings: readonly FindingLike[] | null;
  canExport: boolean;
  inBatch: boolean;
  exportPending: boolean;
  onExport: () => void;
  onToggleBatch: () => void;
  onSeenIn: (target: KeyTarget) => void;
}) {
  const markers = pathMarkers(file);
  const local = file.time_basis === "local_unknown";
  return (
    <div className="flex flex-col gap-5 text-sm" data-testid="file-detail">
      <section className="flex flex-col gap-2">
        <FileFlags file={file} />
        {markers.length > 0 ? <p className="text-xs text-amber-700 dark:text-amber-400">{markers.join(". ")}.</p> : null}
        <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1">
          <Row label="Path">
            <InertText value={file.path} mono wrap />
          </Row>
          {file.stream ? (
            <Row label="Stream">
              <InertText value={file.stream} mono wrap />
            </Row>
          ) : null}
          <Row label="Partition">{file.partition_index}</Row>
          <Row label="Inode">
            <span className="font-mono text-xs">
              {formatU64(file.meta_addr)}
              {file.meta_seq !== null && file.meta_seq !== undefined ? `-${file.meta_seq}` : ""}
            </span>
          </Row>
          <Row label="Type">{FILE_TYPE_LABELS[file.type]}</Row>
          <Row label="Content type">{file.magic ? <InertText value={file.magic} wrap /> : "—"}</Row>
          <Row label="Size">{file.size === null || file.size === undefined ? "—" : `${formatBytes(file.size)} (${file.size} bytes)`}</Row>
          {file.mode !== null && file.mode !== undefined ? (
            <Row label="Mode">
              <span className="font-mono text-xs">{file.mode.toString(8).padStart(4, "0")}</span>
            </Row>
          ) : null}
          {file.uid !== null && file.uid !== undefined ? <Row label="Owner (uid / gid)">{`${file.uid} / ${file.gid ?? "—"}`}</Row> : null}
          <Row label="Modified">
            <FileTime iso={file.mtime} basis={file.time_basis} />
          </Row>
          <Row label="Accessed">
            <FileTime iso={file.atime} basis={file.time_basis} />
          </Row>
          <Row label="Changed">
            <FileTime iso={file.ctime} basis={file.time_basis} />
          </Row>
          <Row label="Created">
            <FileTime iso={file.crtime} basis={file.time_basis} />
          </Row>
        </dl>
        {local ? <p className="text-xs text-muted-foreground">FAT stores {TIME_BASIS_LOCAL}: the times are shown as written.</p> : null}
      </section>

      <section className="flex flex-col gap-1">
        <h3 className="font-semibold">Hashes</h3>
        {file.sha256 || file.md5 || file.sha1 ? (
          <dl className="grid grid-cols-[4rem_1fr] gap-x-3 gap-y-1">
            {file.md5 ? (
              <Row label="md5">
                <HashValue value={file.md5} />
              </Row>
            ) : null}
            {file.sha1 ? (
              <Row label="sha1">
                <HashValue value={file.sha1} />
              </Row>
            ) : null}
            {file.sha256 ? (
              <Row label="sha256">
                <HashValue value={file.sha256} />
              </Row>
            ) : null}
          </dl>
        ) : (
          <p className="text-muted-foreground">Not hashed{file.hash_status ? ` (${file.hash_status.replaceAll("_", " ")})` : ""}.</p>
        )}
        {file.known ? (
          <p>
            {KNOWN_LABELS[file.known].label}
            {file.known_set ? (
              <>
                {" "}
                in <span className="font-mono text-xs">{file.known_set}</span>
              </>
            ) : null}
            <span className="block text-xs text-muted-foreground">{KNOWN_LABELS[file.known].hint}</span>
          </p>
        ) : null}
        {file.sha256 ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="self-start"
            onClick={() => onSeenIn({ kind: "sha256", value: file.sha256 ?? "" })}
          >
            Also seen in…
          </Button>
        ) : null}
      </section>

      {file.other_names.length > 0 ? (
        <section className="flex flex-col gap-1">
          <h3 className="font-semibold">Other names (hard links)</h3>
          <ul className="flex flex-col gap-0.5">
            {file.other_names.map((name) => (
              <li key={name}>
                <InertText value={name} mono wrap />
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {file.streams.length > 0 ? (
        <section className="flex flex-col gap-1">
          <h3 className="font-semibold">Named streams</h3>
          <ul className="flex flex-col gap-0.5">
            {file.streams.map((stream) => (
              <li key={stream}>
                <InertText value={stream} mono wrap />
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {file.yara_rules.length > 0 ? (
        <section className="flex flex-col gap-1">
          <h3 className="font-semibold">YARA rules that matched</h3>
          <p className="font-mono text-xs break-all">{file.yara_rules.join(", ")}</p>
          <p className="text-xs text-muted-foreground">A rule match is a lead to review, not a conclusion.</p>
        </section>
      ) : null}

      <section className="flex flex-col gap-1">
        <h3 className="font-semibold">Findings citing this file</h3>
        {findings === null ? (
          <p className="text-muted-foreground">Loading…</p>
        ) : findings.length === 0 ? (
          <p className="text-muted-foreground">None among the job&apos;s first 100 findings.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {findings.map((f) => (
              <li key={f.id} className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <InertText value={f.title} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-1">
        <h3 className="font-semibold">Events of this file</h3>
        {events === null ? (
          <p className="text-muted-foreground">Loading…</p>
        ) : events.length === 0 ? (
          <p className="text-muted-foreground">No parsed artifact event names this file (first 100 matches checked).</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {events.map((e) => (
              <li key={e.id} className="flex flex-col">
                <span className="text-xs text-muted-foreground">
                  <FileTime iso={e.ts} basis="utc" /> · {artifactLabel(e.artifact)} · <InertText value={e.ts_desc} className="inline" />
                </span>
                <InertText value={e.message} wrap max={512} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-2 rounded-md border p-3">
        <h3 className="font-semibold">Export</h3>
        {file.exportable ? (
          <>
            <p className="text-xs text-muted-foreground">{EXPORT_REQUEST_NOTICE}</p>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" disabled={!canExport || exportPending} onClick={onExport}>
                {exportPending ? "Requesting…" : "Export this file"}
              </Button>
              <Button type="button" size="sm" variant="outline" disabled={!canExport} onClick={onToggleBatch}>
                {inBatch ? "Remove from export batch" : "Add to export batch"}
              </Button>
            </div>
            {!canExport ? <p className="text-xs text-muted-foreground">Exporting needs the evidence write permission.</p> : null}
          </>
        ) : (
          <>
            <Button type="button" size="sm" disabled className="self-start">
              Export this file
            </Button>
            <p className="text-xs text-muted-foreground" data-testid="not-exportable">
              {exportRefusalText(file.not_exportable_reason)}
            </p>
          </>
        )}
      </section>
    </div>
  );
}

/** The file detail drawer (one request for the detail, one each for events and findings). */
export function FileDrawer({
  orgId,
  jobId,
  fileId,
  canExport,
  inBatch,
  exportPending,
  onExport,
  onToggleBatch,
  onClose,
}: {
  orgId: string;
  jobId: string;
  fileId: string | null;
  canExport: boolean;
  inBatch: (id: string) => boolean;
  exportPending: boolean;
  onExport: (id: string) => void;
  onToggleBatch: (id: string) => void;
  onClose: () => void;
}) {
  const detail = useDiskFile(orgId, jobId, fileId);
  const file = detail.data ?? null;
  const events = useDiskFileEvents(orgId, jobId, file ? { id: file.id, name: file.name } : null);
  const findings = useDiskFileFindings(orgId, jobId, fileId);
  const [seenIn, setSeenIn] = useState<KeyTarget | null>(null);
  return (
    <>
      <Sheet open={fileId !== null} onOpenChange={(open) => !open && onClose()}>
        <SheetContent className="w-full overflow-y-auto data-[side=right]:sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="break-all">{file ? <InertText value={file.name} wrap /> : "File"}</SheetTitle>
            <SheetDescription>From the disk image: names and paths are shown as text.</SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-6">
            {detail.isError ? (
              <QueryError error={detail.error} onRetry={() => void detail.refetch()} />
            ) : !file ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : (
              <FileDetailView
                file={file}
                events={events.isPending && events.fetchStatus !== "idle" ? null : (events.data?.items ?? [])}
                findings={findings.isPending ? null : findings.matches}
                canExport={canExport}
                inBatch={inBatch(file.id)}
                exportPending={exportPending}
                onExport={() => onExport(file.id)}
                onToggleBatch={() => onToggleBatch(file.id)}
                onSeenIn={setSeenIn}
              />
            )}
          </div>
        </SheetContent>
      </Sheet>
      <KeyDrawer orgId={orgId} target={seenIn} onClose={() => setSeenIn(null)} />
    </>
  );
}
