import { AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";

import { InertText } from "@/components/disk/inert-text";
import { HashValue } from "@/components/hash-value";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDuration } from "@/lib/analysis";
import {
  type DiskSummary,
  FORMAT_LABELS,
  MEDIA_HASH_TEXT,
  type MediaHashStatus,
  TIMELINE_ENGINE_LABELS,
  formatU64,
  formatU64Bytes,
  stageCompleteness,
  stageLabel,
  stageReasonText,
  stageStatusLabel,
} from "@/lib/disk";
import { artifactLabel } from "@/lib/disk-timeline";
import { formatBytes } from "@/lib/format";
import { formatCount } from "@/lib/pcap-results";
import { cn } from "@/lib/utils";

const STAGE_STYLE: Record<string, string> = {
  ok: "border-border",
  failed: "border-destructive/50 text-destructive",
  timeout: "border-destructive/50 text-destructive",
  skipped: "border-amber-500/60",
  truncated: "border-amber-500/60",
  unsupported: "border-amber-500/60",
};

/**
 * Every stage of the run (per partition where it applies) with its outcome, its reason when
 * skipped (e.g. "deadline": not enough job time left) and its `truncated` marker: a partial run
 * is never shown as complete. Stage names and reasons are allow-listed identifiers, shown as text.
 */
export function StageStrip({ summary }: { summary: Pick<DiskSummary, "stages" | "truncated"> }) {
  const state = stageCompleteness(summary);
  return (
    <div className="flex flex-col gap-2" data-testid="stage-strip">
      <p className={cn("text-sm", state.complete ? "text-muted-foreground" : "font-medium text-amber-700 dark:text-amber-400")}>
        {state.complete
          ? "Every analysis stage finished; no result was cut at a limit."
          : summary.stages.length === 0
            ? "No analysis stage ran."
            : `Partial result: ${[
                state.incomplete.length > 0 ? `${state.incomplete.length} stage(s) did not finish` : null,
                state.truncated.length > 0 ? `${state.truncated.length} stage(s) were cut at a limit` : null,
                summary.truncated && state.truncated.length === 0 ? "stored rows were cut at a limit" : null,
              ]
                .filter(Boolean)
                .join("; ")}. Missing rows are not evidence of absence.`}
      </p>
      <ul className="flex flex-wrap gap-1.5" aria-label="Analysis stages">
        {summary.stages.map((s, index) => {
          const reason = stageReasonText(s.reason);
          const status = stageStatusLabel(s.status);
          return (
            <li key={`${s.stage}-${s.partition_index ?? "image"}-${index}`}>
              <Badge
                variant="outline"
                className={cn("gap-1 text-[11px] font-normal", STAGE_STYLE[s.status] ?? "border-amber-500/60")}
                title={[
                  `${stageLabel(s.stage)}${s.partition_index !== null && s.partition_index !== undefined ? ` · partition ${s.partition_index}` : ""}`,
                  `${status}${reason ? ` (${reason})` : ""}`,
                  `${formatCount(s.rows)} rows`,
                  formatDuration(s.duration_ms),
                  s.error_code ? `error ${s.error_code}` : null,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              >
                <span className="font-medium">{stageLabel(s.stage)}</span>
                {s.partition_index !== null && s.partition_index !== undefined ? <span>p{s.partition_index}</span> : null}
                <span>{status}</span>
                {reason && s.status !== "ok" ? <span className="text-muted-foreground">({reason})</span> : null}
                {s.truncated && s.status !== "truncated" ? <span className="font-medium">· truncated</span> : null}
              </Badge>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** The worker-reported media hash status, worded "consistent with…", never "verified" (RT17). */
export function MediaHashStatusView({ status }: { status: MediaHashStatus | null | undefined }) {
  if (!status) return <span className="text-muted-foreground">Not reported</span>;
  const text = MEDIA_HASH_TEXT[status];
  if (status === "mismatch") {
    return (
      <Alert variant="destructive" data-testid="media-hash-mismatch">
        <AlertTriangle className="size-4" aria-hidden />
        <AlertTitle>{text.label}</AlertTitle>
        <AlertDescription>{text.detail}</AlertDescription>
      </Alert>
    );
  }
  return (
    <span className="flex flex-col gap-0.5" data-testid="media-hash-status">
      <span className={cn("font-medium", text.tone === "muted" && "text-muted-foreground")}>{text.label}</span>
      <span className="text-xs text-muted-foreground">{text.detail}</span>
    </span>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="text-sm">{children}</div>
    </div>
  );
}

/**
 * The image facts of a disk job. Only the per-segment sha256s are computed by the platform
 * (at upload); format, media size and media hashes are reported by the worker and labelled so.
 * EWF acquisition values come from the image: quoted, inert text.
 */
export function DiskOverview({ summary }: { summary: DiskSummary }) {
  const ewf = Object.entries(summary.ewf_meta ?? {});
  const tools = Object.entries(summary.tool_versions ?? {});
  return (
    <div className="flex flex-col gap-6" data-testid="disk-overview">
      <Card>
        <CardHeader>
          <CardTitle>Image</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Fact label="Format (reported by the worker)">{FORMAT_LABELS[summary.format] ?? summary.format}</Fact>
            <Fact label="Media size (reported by the worker)">
              <span title={`${formatU64(summary.media_size)} bytes`}>{formatU64Bytes(summary.media_size)}</span>
              <span className="block text-xs text-muted-foreground tabular-nums">
                {formatU64(summary.media_size)} bytes · {formatCount(summary.sector_size)}-byte sectors
              </span>
            </Fact>
            <Fact label="Volume system">{summary.volume_system ? <InertText value={summary.volume_system} /> : "None"}</Fact>
            <Fact label="Timeline engine">
              {TIMELINE_ENGINE_LABELS[summary.timeline_engine] ?? summary.timeline_engine}
              {summary.timeline_engine === "replay" ? (
                <Badge variant="outline" className="ml-2" data-testid="replay-label">
                  timeline_engine: replay
                </Badge>
              ) : null}
            </Fact>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Fact label="Media hash status (reported by the worker)">
              <MediaHashStatusView status={summary.media_hash_status} />
            </Fact>
            <Fact label="Media sha256 (reported by the worker, not platform-computed)">
              {summary.media_sha256 ? <HashValue value={summary.media_sha256} short /> : <span className="text-muted-foreground">—</span>}
              {summary.ewf_md5 ? (
                <span className="mt-1 block text-xs text-muted-foreground">
                  Acquisition md5 stored in the image: <code className="font-mono break-all">{summary.ewf_md5}</code>
                </span>
              ) : null}
              {summary.ewf_sha1 ? (
                <span className="block text-xs text-muted-foreground">
                  Acquisition sha1 stored in the image: <code className="font-mono break-all">{summary.ewf_sha1}</code>
                </span>
              ) : null}
            </Fact>
          </div>
          {summary.media_hash_status === "absent" ? (
            <p className="text-xs text-muted-foreground">
              Without a stored acquisition hash, corrupted chunks of the image cannot be detected.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Segments</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-2 text-xs text-muted-foreground">
            The sha256 of each segment was computed by the platform at upload (the only platform-computed image hash).
          </p>
          <div className="min-w-0 rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">#</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead className="w-28 text-right">Size</TableHead>
                  <TableHead>sha256</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {summary.segments.map((s) => (
                  <TableRow key={s.evidence_id}>
                    <TableCell className="tabular-nums">{s.ordinal + 1}</TableCell>
                    <TableCell className="max-w-72">
                      <InertText value={s.original_filename} mono />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{formatBytes(s.size_bytes)}</TableCell>
                    <TableCell>
                      <HashValue value={s.sha256} short />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {ewf.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>EWF acquisition details</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="mb-2 text-xs text-muted-foreground">As written in the image by the acquisition tool (quoted, not checked).</p>
            <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-sm" data-testid="ewf-meta">
              {ewf.map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-muted-foreground">
                    <InertText value={key} max={64} />
                  </dt>
                  <dd className="min-w-0">
                    “<InertText value={value} wrap max={1024} />”
                  </dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Stages</CardTitle>
        </CardHeader>
        <CardContent>
          <StageStrip summary={summary} />
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Artifacts</CardTitle>
          </CardHeader>
          <CardContent>
            {summary.artifacts.length === 0 ? (
              <p className="text-sm text-muted-foreground">No artifact files were collected.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Artifact</TableHead>
                    <TableHead className="text-right">Files</TableHead>
                    <TableHead className="text-right">Events read</TableHead>
                    <TableHead className="text-right">Events stored</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.artifacts.map((a) => (
                    <TableRow key={a.artifact}>
                      <TableCell>{artifactLabel(a.artifact)}</TableCell>
                      <TableCell className="text-right tabular-nums">{formatCount(a.files)}</TableCell>
                      <TableCell className="text-right tabular-nums">{formatCount(a.events_read)}</TableCell>
                      <TableCell
                        className={cn("text-right tabular-nums", a.events_stored < a.events_read && "text-amber-700 dark:text-amber-400")}
                        title={a.events_stored < a.events_read ? "Fewer events stored than read: cut at the per-artifact limit" : undefined}
                      >
                        {formatCount(a.events_stored)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Reference hash sets and tools</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4 text-sm">
            {summary.hashsets.length === 0 ? (
              <p className="text-muted-foreground">No reference hash set was used.</p>
            ) : (
              <ul className="flex flex-col gap-1" aria-label="Hash sets used">
                {summary.hashsets.map((h) => (
                  <li key={h.name} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{h.name}</span>
                    <Badge variant="outline">
                      {h.kind === "known_good" ? "known software" : h.kind === "known_bad" ? "files to look at" : "notable"}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{formatCount(h.count)} hashes</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs text-muted-foreground">
              Known software is not necessarily benign; a reference-set match is a lead, not a conclusion.
            </p>
            {tools.length > 0 ? (
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-xs" aria-label="Tool versions">
                {tools.map(([tool, version]) => (
                  <div key={tool} className="contents">
                    <dt className="text-muted-foreground">{tool}</dt>
                    <dd className="font-mono">{version}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
            <p className="text-xs text-muted-foreground">Analyzer engine: {summary.engine}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
