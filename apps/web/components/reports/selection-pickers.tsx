"use client";

import { X } from "lucide-react";
import { useId, useState } from "react";

import { AddToReportButton } from "@/components/reports/add-to-report";
import { Group } from "@/components/reports/builder-fields";
import { RText } from "@/components/reports/report-text";
import { Toggle } from "@/components/reports/selection-groups";
import { Button } from "@/components/ui/button";
import { type AiRun, formatAccuracy, taskLabel } from "@/lib/ai";
import { errorMessage } from "@/lib/api";
import { formatUtc } from "@/lib/report-format";
import {
  type CitedRowRef,
  type DraftInclude,
  MAX_AI_RUNS,
  MAX_CITED_ROWS,
  reportErrorText,
  toggleId,
} from "@/lib/reports";
import { useJobRows } from "@/lib/use-reports";

/*
 * Selection groups fed by the case's data (analyses, notes, AI runs, cited rows). The lists are
 * fetched by the builder and passed in, so each group stays a plain component.
 */

type GroupProps = { include: DraftInclude; onChange: (include: DraftInclude) => void; disabled: boolean };

export type CaseJob = { id: string; analyzer: string; evidence_filename: string; status: string; created_at: string };
export type CaseNote = { id: string; body: string | null; author_name: string; updated_at: string };

function LoadState({ loading, error, empty, count }: { loading: boolean; error: unknown; empty: string; count: number }) {
  if (loading) return <p className="text-xs text-muted-foreground">Loading…</p>;
  if (error) return <p className="text-xs text-destructive">{reportErrorText(error) ?? errorMessage(error)}</p>;
  if (count === 0) return <p className="text-xs text-muted-foreground">{empty}</p>;
  return null;
}

const analyzerText = (analyzer: string) =>
  analyzer === "pcap" ? "PCAP" : analyzer === "static" ? "Static" : analyzer === "memory" ? "Memory" : analyzer === "disk" ? "Disk" : analyzer === "reverse" ? "RE" : analyzer;

export function JobsPicker({
  include,
  onChange,
  disabled,
  jobs,
  loading,
  error,
}: GroupProps & { jobs: readonly CaseJob[]; loading: boolean; error: unknown }) {
  const name = useId();
  const picked = include.jobs === "latest" ? null : include.jobs;
  return (
    <Group title="Analyses" description="Findings, alerts, IOCs and tool versions come from these analyses.">
      <label className="flex items-start gap-2 text-sm">
        <input
          type="radio"
          name={name}
          className="mt-1"
          checked={picked === null}
          disabled={disabled}
          onChange={() => onChange({ ...include, jobs: "latest" })}
        />
        <span>The latest analysis of each evidence item and kind</span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="radio"
          name={name}
          className="mt-1"
          checked={picked !== null}
          disabled={disabled}
          onChange={() => onChange({ ...include, jobs: [] })}
        />
        <span>Pick analyses</span>
      </label>
      {picked !== null ? (
        <div className="flex flex-col gap-1 pl-5">
          <LoadState loading={loading} error={error} empty="This case has no analyses." count={jobs.length} />
          {jobs.map((job) => (
            <Toggle
              key={job.id}
              label={`${analyzerText(job.analyzer)} · ${job.evidence_filename} · ${job.status} · ${formatUtc(job.created_at)}`}
              checked={picked.includes(job.id)}
              disabled={disabled}
              onChange={(on) => onChange({ ...include, jobs: toggleId(picked, job.id, on) })}
            />
          ))}
        </div>
      ) : null}
    </Group>
  );
}

export function NotesPicker({
  include,
  onChange,
  disabled,
  notes,
  loading,
  error,
}: GroupProps & { notes: readonly CaseNote[]; loading: boolean; error: unknown }) {
  return (
    <Group
      title="Analyst notes"
      description="Notes marked “include in reports”, at their current version. External reports leave notes out."
    >
      <LoadState loading={loading} error={error} empty="No notes of this case are marked for reports." count={notes.length} />
      {notes.map((note) => (
        <label key={note.id} className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={include.notes.includes(note.id)}
            disabled={disabled}
            onChange={(event) => onChange({ ...include, notes: toggleId(include.notes, note.id, event.target.checked) })}
          />
          <span className="min-w-0">
            <RText value={(note.body ?? "").slice(0, 160) || "(empty note)"} className="line-clamp-2" />
            <span className="block text-xs text-muted-foreground">
              {note.author_name} · {formatUtc(note.updated_at)}
            </span>
          </span>
        </label>
      ))}
    </Group>
  );
}

export function AiRunsPicker({
  include,
  onChange,
  disabled,
  runs,
  loading,
  error,
}: GroupProps & { runs: readonly AiRun[]; loading: boolean; error: unknown }) {
  const full = include.ai_runs.length >= MAX_AI_RUNS;
  return (
    <Group
      title="AI runs"
      description={`Completed runs of this case and its analyses (refused or withheld runs are not offered). Only verified statements and labelled hypotheses go in. At most ${MAX_AI_RUNS}.`}
    >
      <LoadState loading={loading} error={error} empty="No completed AI runs for this case." count={runs.length} />
      {runs.map((run) => {
        const checked = include.ai_runs.includes(run.id);
        return (
          <label key={run.id} className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={checked}
              disabled={disabled || (!checked && full)}
              onChange={(event) =>
                onChange({ ...include, ai_runs: toggleId(include.ai_runs, run.id, event.target.checked, MAX_AI_RUNS) })
              }
            />
            <span>
              {taskLabel(run.task)} · {run.scope === "investigation" ? "case" : "analysis"}
              <span className="block text-xs text-muted-foreground">
                {run.provider} / {run.served_model ?? run.model} · {formatUtc(run.finished_at ?? run.created_at)}
                {run.citation_accuracy !== null ? ` · citations verified ${formatAccuracy(run.citation_accuracy)}` : ""}
                {run.claims_unsupported ? ` · ${run.claims_unsupported} unsupported statement(s) left out` : ""}
              </span>
            </span>
          </label>
        );
      })}
    </Group>
  );
}

const ROW_KINDS: readonly ["finding" | "alert", string][] = [
  ["finding", "Findings"],
  ["alert", "Alerts"],
];

/** Pick rows of one analysis to cite (each becomes a [Cn] entry of the appendix). */
function RowPicker({
  orgId,
  investigationId,
  jobs,
  onAdd,
  disabled,
}: {
  orgId: string;
  investigationId: string;
  jobs: readonly CaseJob[];
  onAdd: (row: CitedRowRef) => void;
  disabled: boolean;
}) {
  const jobSelect = useId();
  const kindSelect = useId();
  const [jobId, setJobId] = useState<string | null>(null);
  const [kind, setKind] = useState<"finding" | "alert">("finding");
  const job = jobs.find((j) => j.id === jobId) ?? null;
  const effectiveKind = job?.analyzer === "static" ? "finding" : kind;
  const rows = useJobRows(orgId, jobId, effectiveKind);
  return (
    <div className="flex flex-col gap-2 rounded-md border border-dashed p-3">
      <div className="flex flex-wrap gap-3">
        <span className="flex flex-col gap-1">
          <label htmlFor={jobSelect} className="text-xs font-medium">
            Analysis
          </label>
          <select
            id={jobSelect}
            className="h-8 max-w-72 rounded-md border border-input bg-background px-2 text-sm"
            value={jobId ?? ""}
            disabled={disabled}
            onChange={(event) => setJobId(event.target.value || null)}
          >
            <option value="">Choose an analysis…</option>
            {jobs.map((j) => (
              <option key={j.id} value={j.id}>
                {analyzerText(j.analyzer)} · {j.evidence_filename}
              </option>
            ))}
          </select>
        </span>
        {job?.analyzer === "pcap" ? (
          <span className="flex flex-col gap-1">
            <label htmlFor={kindSelect} className="text-xs font-medium">
              Rows
            </label>
            <select
              id={kindSelect}
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
              value={kind}
              disabled={disabled}
              onChange={(event) => setKind(event.target.value === "alert" ? "alert" : "finding")}
            >
              {ROW_KINDS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </span>
        ) : null}
      </div>
      {jobId ? (
        <>
          <LoadState loading={rows.isLoading} error={rows.error} empty="No rows." count={rows.data?.length ?? 0} />
          <ul className="flex max-h-64 flex-col gap-1 overflow-y-auto">
            {(rows.data ?? []).map((row) => (
              <li key={row.id} className="flex items-center justify-between gap-2 text-sm">
                <span className="min-w-0">
                  <RText value={row.label} className="line-clamp-1" />
                  <span className="block text-xs text-muted-foreground">{row.severity}</span>
                </span>
                <AddToReportButton
                  orgId={orgId}
                  investigationId={investigationId}
                  row={{ kind: effectiveKind, ref_id: row.id, job_id: jobId }}
                  onAdd={onAdd}
                  disabled={disabled}
                  label="Cite"
                />
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

export function CitedRowsPicker({
  orgId,
  investigationId,
  include,
  jobs,
  onAdd,
  onRemove,
  disabled,
}: {
  orgId: string;
  investigationId: string;
  include: DraftInclude;
  jobs: readonly CaseJob[];
  onAdd: (row: CitedRowRef) => void;
  onRemove: (row: CitedRowRef) => void;
  disabled: boolean;
}) {
  const rows = include.cited_rows;
  return (
    <Group
      title="Cited rows"
      description={`Rows the report cites explicitly: each one is copied into the appendix with its hash. ${rows.length} of ${MAX_CITED_ROWS}.`}
    >
      {rows.length === 0 ? <p className="text-xs text-muted-foreground">No rows cited yet.</p> : null}
      <ul className="flex flex-col gap-1">
        {rows.map((row) => (
          <li key={`${row.kind}:${row.job_id ?? ""}:${row.ref_id}`} className="flex items-center justify-between gap-2 text-xs">
            <span className="min-w-0 font-mono break-all">
              {row.kind} · <RText value={row.ref_id} mono />
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="size-6"
              disabled={disabled}
              aria-label={`Remove cited ${row.kind} ${row.ref_id}`}
              onClick={() => onRemove(row)}
            >
              <X className="size-3.5" aria-hidden />
            </Button>
          </li>
        ))}
      </ul>
      {!disabled ? <RowPicker orgId={orgId} investigationId={investigationId} jobs={jobs} onAdd={onAdd} disabled={disabled} /> : null}
    </Group>
  );
}
