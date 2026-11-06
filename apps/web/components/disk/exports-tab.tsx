"use client";

import { Download } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

import { InertText } from "@/components/disk/inert-text";
import { HashValue } from "@/components/hash-value";
import { QueryError } from "@/components/query-error";
import { TlpBadge } from "@/components/tlp/tlp-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import {
  type DiskExport,
  EXPORT_STATE_HINTS,
  EXPORT_STATE_LABELS,
  INTEROP_EXPORTS,
  INTEROP_TLP_NOTICE,
  PROMOTE_NOTICE,
  fileExportErrorText,
} from "@/lib/disk-exports";
import { formatBytes, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useDiskExport, useInteropDownload, usePromoteExport, useRememberedExports } from "@/lib/use-disk-job";

/** The interop downloads (fixed catalog; requests built from the job id only). */
export function InteropDownloads({
  restricted,
  pending,
  onDownload,
}: {
  restricted: boolean;
  pending: string | null;
  onDownload: (name: (typeof INTEROP_EXPORTS)[number]["name"], excel?: boolean) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Interop downloads {restricted ? <TlpBadge tlp="red" /> : null}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {restricted ? (
          <p className="rounded-md border border-destructive/50 p-2 text-xs" data-testid="interop-tlp">
            {INTEROP_TLP_NOTICE}
          </p>
        ) : null}
        <ul className="flex flex-col gap-2">
          {INTEROP_EXPORTS.map((e) => (
            <li key={e.name} className="flex flex-wrap items-center gap-3">
              <Button type="button" size="sm" variant="outline" disabled={pending !== null} onClick={() => onDownload(e.name)}>
                <Download className="size-4" aria-hidden />
                {pending === e.name ? "Preparing…" : e.label}
              </Button>
              {e.name === "timeline.csv" ? (
                <Button type="button" size="sm" variant="ghost" disabled={pending !== null} onClick={() => onDownload(e.name, true)}>
                  CSV for Excel
                </Button>
              ) : null}
              <span className="text-xs text-muted-foreground">{e.purpose}</span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">Each download is recorded in the audit log.</p>
      </CardContent>
    </Card>
  );
}

/** One file export row (pure): state, size and the worker's sha256 (unverified), the evidence link. */
export function ExportRowView({
  orgId,
  item,
  canPromote,
  promotePending,
  promoteError,
  onPromote,
}: {
  orgId: string;
  item: DiskExport;
  canPromote: boolean;
  promotePending: boolean;
  promoteError: unknown;
  onPromote: () => void;
}) {
  const created = formatDate(item.created_at);
  return (
    <li className="flex flex-col gap-1 rounded-md border p-3 text-sm" data-testid="file-export">
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant={item.state === "failed" ? "destructive" : item.state === "promoted" ? "secondary" : "outline"}
          title={EXPORT_STATE_HINTS[item.state]}
        >
          {EXPORT_STATE_LABELS[item.state]}
        </Badge>
        <InertText value={item.path} mono className="min-w-0 flex-1" />
        <span className="text-xs text-muted-foreground" title={created.utc}>
          {created.local}
        </span>
      </div>
      {item.state === "expired" ? <p className="text-xs text-muted-foreground">{EXPORT_STATE_HINTS.expired}</p> : null}
      {item.state === "pending" ? <p className="text-xs text-muted-foreground">{EXPORT_STATE_HINTS.pending}</p> : null}
      {item.state === "failed" ? (
        <p className="text-xs text-destructive">{item.error_code ? fileExportErrorText(item.error_code) : EXPORT_STATE_HINTS.failed}</p>
      ) : null}
      {item.state === "ready" ? (
        <div className="flex flex-col gap-1 text-xs">
          <span>Size: {item.size === null || item.size === undefined ? "—" : formatBytes(item.size)}</span>
          {item.worker_sha256 ? (
            <span className="flex flex-wrap items-center gap-1">
              sha256 reported by the worker (unverified): <HashValue value={item.worker_sha256} short />
            </span>
          ) : null}
          <p className="text-muted-foreground">{PROMOTE_NOTICE}</p>
          <Button type="button" size="sm" className="self-start" disabled={!canPromote || promotePending} onClick={onPromote}>
            {promotePending ? "Adding…" : "Add to case as evidence"}
          </Button>
          {promoteError ? (
            <p role="alert" className="text-destructive">
              {fileExportErrorText(promoteError)}
            </p>
          ) : null}
        </div>
      ) : null}
      {item.state === "promoted" && item.evidence_id ? (
        <p className="text-xs">
          Added as new evidence with the platform&apos;s own hashes:{" "}
          <Link className="underline underline-offset-4" href={orgPath(orgId, `evidence/${item.evidence_id}`)}>
            open the evidence
          </Link>
          .
        </p>
      ) : null}
    </li>
  );
}

function ExportRow({ orgId, exportId, investigationId, canPromote }: { orgId: string; exportId: string; investigationId: string; canPromote: boolean }) {
  const item = useDiskExport(orgId, exportId);
  const promote = usePromoteExport(orgId, investigationId);
  if (item.isError) {
    if (item.error instanceof ApiError && item.error.status === 404) return null; // forgotten or another org's id
    return (
      <li>
        <QueryError error={item.error} onRetry={() => void item.refetch()} />
      </li>
    );
  }
  if (!item.data) return <li className="text-xs text-muted-foreground">Loading…</li>;
  return (
    <ExportRowView
      orgId={orgId}
      item={item.data}
      canPromote={canPromote}
      promotePending={promote.isPending}
      promoteError={promote.error}
      onPromote={() =>
        promote.mutate(exportId, {
          onSuccess: () => toast.success("Added to the case as evidence"),
        })
      }
    />
  );
}

/**
 * The Exports tab: the interop downloads (TLP:RED reminder while restricted) and the file
 * exports requested from this browser (the API has no per-job list yet) with their state;
 * a ready export can be added to the case as derived evidence.
 */
export function ExportsTab({
  orgId,
  jobId,
  investigationId,
  restricted,
  canWrite,
}: {
  orgId: string;
  jobId: string;
  investigationId: string;
  restricted: boolean;
  canWrite: boolean;
}) {
  const download = useInteropDownload(orgId, jobId);
  const remembered = useRememberedExports(orgId, jobId);
  const ids = remembered.data ?? [];
  return (
    <div className="flex flex-col gap-6">
      <InteropDownloads
        restricted={restricted}
        pending={download.isPending ? (download.variables?.name ?? null) : null}
        onDownload={(name, excel) =>
          download.mutate(
            { name, excel },
            {
              onSuccess: (filename) => toast.success(`Downloaded ${filename}`),
              onError: (error) => toast.error(fileExportErrorText(error)),
            },
          )
        }
      />
      <Card>
        <CardHeader>
          <CardTitle>File exports</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground">
            Export files from the Files tab (open a file, then “Export this file” or add it to a batch of up to 20). The
            exports requested from this browser are listed here.
          </p>
          {ids.length === 0 ? (
            <p className="text-sm text-muted-foreground">No file export requested from this browser yet.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {ids.map((exportId) => (
                <ExportRow key={exportId} orgId={orgId} exportId={exportId} investigationId={investigationId} canPromote={canWrite} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
