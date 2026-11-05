"use client";

import { useMutation } from "@tanstack/react-query";
import { Download, FileJson, Printer, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { errorMessage } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { downloadFilename, formatUtc } from "@/lib/report-format";
import {
  FORMAT_LABELS,
  RENDER_FORMATS,
  RENDER_STATUS_LABELS,
  type RenderFormat,
  type RenderOut,
  downloadRender,
  downloadSnapshot,
  isFinalRender,
  latestRenders,
  renderErrorText,
  reportErrorText,
  saveBlob,
} from "@/lib/reports";
import { useRenders, useRequestRender } from "@/lib/use-reports";
import { cn } from "@/lib/utils";

/** One format's latest render: status (typed failure reason and hint), Render and Download. */
export function RenderRow({
  format,
  render,
  canRender,
  canDownload,
  onRender,
  onDownload,
  pending,
}: {
  format: RenderFormat;
  render: RenderOut | undefined;
  canRender: boolean;
  canDownload: boolean;
  onRender: () => void;
  onDownload: (render: RenderOut) => void;
  pending: boolean;
}) {
  const failure = render?.status === "failed" ? renderErrorText(render.error_code) : null;
  const active = render && !isFinalRender(render.status);
  return (
    <li className="flex flex-wrap items-start justify-between gap-3 border-b py-2 last:border-b-0" data-format={format}>
      <div className="min-w-0 text-sm">
        <p className="font-medium">{FORMAT_LABELS[format]}</p>
        <p className={cn("text-xs", failure ? "text-destructive" : "text-muted-foreground")} aria-live="polite">
          {!render ? "Not rendered yet." : `${RENDER_STATUS_LABELS[render.status]}`}
          {render?.status === "succeeded"
            ? ` · ${render.bytes !== null ? formatBytes(render.bytes) : "size unknown"}${render.pages ? ` · ${render.pages} pages` : ""} · ${formatUtc(render.finished_at)}`
            : null}
          {failure ? `: ${failure.text}` : null}
        </p>
        {failure ? <p className="text-xs text-muted-foreground">{failure.hint}</p> : null}
        {render?.status === "succeeded" && render.sha256 ? (
          <p className="font-mono text-[11px] break-all text-muted-foreground">SHA-256 {render.sha256}</p>
        ) : null}
      </div>
      <div className="flex gap-2">
        {render?.status === "succeeded" ? (
          <Button size="sm" variant="outline" disabled={!canDownload} onClick={() => onDownload(render)}>
            <Download className="size-4" aria-hidden />
            Download
          </Button>
        ) : null}
        {canRender && (!render || render.status === "failed") ? (
          <Button size="sm" variant="outline" disabled={pending || Boolean(active)} onClick={onRender}>
            <RefreshCw className="size-4" aria-hidden />
            {render?.status === "failed" ? "Render again" : "Render"}
          </Button>
        ) : null}
      </div>
    </li>
  );
}

/**
 * Renditions of a signed version (views of the snapshot; the snapshot is the record). Finalize
 * queues the PDF; HTML and Markdown are rendered on demand. Polled while a render is active.
 */
export function ReportRenders({
  orgId,
  reportId,
  version,
  canRender,
  canDownload,
}: {
  orgId: string;
  reportId: string;
  version: number;
  canRender: boolean;
  canDownload: boolean;
}) {
  const renders = useRenders(orgId, reportId, version);
  const request = useRequestRender(orgId, reportId, version);
  const latest = latestRenders(renders.data ?? []);
  const download = useMutation({
    mutationFn: async (render: RenderOut) => {
      const file = await downloadRender(orgId, render.id);
      saveBlob(file.blob, downloadFilename(file.disposition, `report-v${version}.${render.format}`));
    },
    onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)),
  });
  const snapshot = useMutation({
    mutationFn: async () => {
      const file = await downloadSnapshot(orgId, reportId, version);
      saveBlob(file.blob, downloadFilename(file.disposition, `report-v${version}.snapshot.json`));
    },
    onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)),
  });

  return (
    <section aria-labelledby="report-renders-h" className="rounded-md border p-4 print:hidden">
      <h2 id="report-renders-h" className="text-base font-semibold">
        Downloads
      </h2>
      <p className="mt-1 text-xs text-muted-foreground">
        Downloads are recorded in the audit log. The PDF embeds the signed snapshot, its manifest and signature.
      </p>
      {renders.isError ? (
        <div className="mt-3">
          <QueryError error={renders.error} onRetry={() => void renders.refetch()} />
        </div>
      ) : (
        <ul className="mt-2">
          {RENDER_FORMATS.map((format) => (
            <RenderRow
              key={format}
              format={format}
              render={latest[format]}
              canRender={canRender}
              canDownload={canDownload && !download.isPending}
              pending={request.isPending}
              onRender={() =>
                request.mutate(format, {
                  onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)),
                })
              }
              onDownload={(render) => download.mutate(render)}
            />
          ))}
        </ul>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={!canDownload || snapshot.isPending} onClick={() => snapshot.mutate()}>
          <FileJson className="size-4" aria-hidden />
          Signed snapshot (JSON)
        </Button>
        <Button size="sm" variant="ghost" onClick={() => window.print()} title="Prints this page; it is not the signed PDF">
          <Printer className="size-4" aria-hidden />
          Quick print (not the signed PDF)
        </Button>
      </div>
    </section>
  );
}
