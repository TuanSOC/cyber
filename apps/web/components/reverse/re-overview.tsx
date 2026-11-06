import { Info } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { InertText } from "@/components/disk/inert-text";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { formatDuration } from "@/lib/analysis";
import { formatBytes } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import {
  ENGINE_LABELS,
  type ReStageOut,
  type ReSummary,
  STAGE_LABELS,
  STAGE_STATE_LABELS,
  SYNTHETIC_METRICS_NOTE,
  formatAddress,
} from "@/lib/reverse";
import { cn } from "@/lib/utils";

const STATE_CLASS: Record<ReStageOut["status"], string> = {
  ok: "border-emerald-500/50",
  timeout: "border-amber-500/60 bg-amber-500/10",
  failed: "border-destructive/60 bg-destructive/10",
  skipped: "border-muted-foreground/30 text-muted-foreground",
};

/** Engine name; the replay engine (test data) is labelled so it is never taken for analysis. */
export function ReEngineLabel({ engine, version }: { engine: ReSummary["engine"] | undefined; version?: string | null }) {
  if (!engine) return null;
  return (
    <Badge variant={engine === "replay" ? "destructive" : "outline"}>
      {ENGINE_LABELS[engine]}
      {version ? ` ${version}` : ""}
    </Badge>
  );
}

/** One chip per stage (ok / timeout / failed / skipped, with `truncated`): never "complete" when partial. */
export function StageStrip({ stages }: { stages: readonly ReStageOut[] }) {
  if (stages.length === 0) return <p className="text-xs text-muted-foreground">No stage ran.</p>;
  return (
    <ol className="flex flex-wrap gap-2" aria-label="Analysis stages">
      {stages.map((s) => (
        <li key={s.stage} className={cn("rounded-md border px-2 py-1 text-xs", STATE_CLASS[s.status])} data-stage={s.stage}>
          <span className="font-medium">{STAGE_LABELS[s.stage] ?? s.stage}</span>: {STAGE_STATE_LABELS[s.status] ?? s.status}
          {s.truncated ? <span className="ml-1 font-medium">(truncated)</span> : null}
          <span className="ml-1 text-muted-foreground tabular-nums">{formatDuration(s.duration_ms)}</span>
          {s.peak_memory_bytes ? (
            <span className="ml-1 text-muted-foreground" title="Peak memory of the stage (container cgroup)">
              · {formatBytes(s.peak_memory_bytes)}
            </span>
          ) : null}
          {s.error_code ? <span className="ml-1 font-mono text-[10px]">({s.error_code})</span> : null}
        </li>
      ))}
    </ol>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="min-w-0 text-sm">{children}</div>
    </div>
  );
}

const count = (counts: Record<string, number>, key: string) =>
  typeof counts[key] === "number" ? counts[key].toLocaleString("en-US") : "—";

/** Program facts, source static job, stage strip, decompile budget and capa linking. */
export function ReOverview({ orgId, summary }: { orgId: string; summary: ReSummary }) {
  const truncated = Object.entries(summary.truncated).filter(([, on]) => on).map(([key]) => key);
  return (
    <div className="flex flex-col gap-4">
      {summary.newer_job_id ? (
        <p className="rounded-md border border-primary/40 bg-primary/5 p-3 text-sm" data-testid="newer-job">
          A newer reverse-engineering job of this sample exists.{" "}
          <Link className="underline underline-offset-4" href={orgPath(orgId, `reverse-engineering/${summary.newer_job_id}`)}>
            Open the newer job
          </Link>
        </p>
      ) : null}
      <Card>
        <CardContent className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Fact label="Format">
            {summary.format.toUpperCase()} · {summary.arch} · {summary.bits}-bit · {summary.endianness}
          </Fact>
          <Fact label="Machine / language">
            <InertText value={[summary.machine, summary.language_id, summary.compiler_spec].filter(Boolean).join(" · ") || null} mono />
          </Fact>
          <Fact label="Image base (preferred)">
            <span className="font-mono">
              {formatAddress(summary.image_base)} ({formatAddress(summary.preferred_base)})
            </span>
          </Fact>
          <Fact label="Entry point">
            <span className="font-mono">{summary.entry ? formatAddress(summary.entry) : "—"}</span>
          </Fact>
          <Fact label="Engine">
            <ReEngineLabel engine={summary.engine} version={summary.engine_version} />
          </Fact>
          <Fact label="Analysis">
            {summary.analysis_status === "complete" ? "Complete" : summary.analysis_status === "timeout" ? "Stopped at the time limit (partial)" : summary.analysis_status === "failed" ? "Failed (partial)" : "Not run"}
          </Fact>
          <Fact label="Source static analysis">
            <Link className="underline underline-offset-4" href={orgPath(orgId, `malware/${summary.source_job_id}`)}>
              Open in the Malware Lab
            </Link>
          </Fact>
          <Fact label="Code">{summary.code_kind === "pseudo_c" ? "Pseudo-C (decompiled)" : "Disassembly only"}</Fact>
        </CardContent>
      </Card>
      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-medium">Stages</h3>
        <StageStrip stages={summary.stages} />
        {truncated.length ? (
          <p className="text-xs text-muted-foreground">Cut at a platform limit: {truncated.join(", ")}.</p>
        ) : null}
      </div>
      <Card>
        <CardContent className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Fact label="Functions">{count(summary.counts, "functions")}</Fact>
          <Fact label="Decompiled (budget)">
            {count(summary.counts, "decompiled")}
            {typeof summary.counts.decompile_budget === "number" ? ` of ${count(summary.counts, "decompile_budget")}` : ""}
          </Fact>
          <Fact label="Capabilities linked to functions">
            {count(summary.counts, "capa_linked")}
            {summary.counts.capa_unlocated ? (
              <span className="text-xs text-muted-foreground"> ({count(summary.counts, "capa_unlocated")} not inside a function)</span>
            ) : null}
          </Fact>
          <Fact label="Imports / strings">
            {count(summary.counts, "imports")} / {count(summary.counts, "strings")}
          </Fact>
        </CardContent>
      </Card>
      {summary.decompile_addresses.length ? (
        <p className="text-xs text-muted-foreground">
          Decompiled first on request: <span className="font-mono">{summary.decompile_addresses.map(formatAddress).join(", ")}</span>
        </p>
      ) : null}
      <p className="flex items-start gap-2 text-xs text-muted-foreground">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        {SYNTHETIC_METRICS_NOTE}
      </p>
    </div>
  );
}
