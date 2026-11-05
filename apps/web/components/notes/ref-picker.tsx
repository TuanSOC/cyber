"use client";

import { useQuery } from "@tanstack/react-query";
import { Link2 } from "lucide-react";
import { useState } from "react";

import { useInvestigationAnalyses } from "@/components/analysis/investigation-analyses";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { analysisKindLabel } from "@/lib/analysis";
import { api } from "@/lib/api";
import { caseErrorMessage, unwrapCase, visText } from "@/lib/case";
import { defang } from "@/lib/ioc-collections";
import { NOTE_MAX_REFS, type NoteRef } from "@/lib/notes";
import { useCaseEvidence } from "@/lib/use-case";
import { useDebounced } from "@/lib/use-debounced";

type Source = "evidence" | "finding" | "alert" | "ioc";

const SOURCES: [Source, string][] = [
  ["evidence", "Evidence"],
  ["finding", "Findings"],
  ["alert", "Alerts"],
  ["ioc", "IOCs"],
];

type Candidate = { ref: NoteRef; text: string; detail?: string };

const LIMIT = 25;

/**
 * Picks records of this case to link from a note: evidence items, or findings, alerts and IOCs
 * of one of the case's analyses. Candidate text is rendered as text; the API re-checks every
 * ref in the case scope (`422 ref_out_of_scope`).
 */
export function RefPicker({
  orgId,
  investigationId,
  count,
  onAdd,
}: {
  orgId: string;
  investigationId: string;
  count: number;
  onAdd: (ref: NoteRef) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="sm" disabled={count >= NOTE_MAX_REFS}>
          <Link2 className="size-4" aria-hidden /> Link a record ({count}/{NOTE_MAX_REFS})
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Link a record</DialogTitle>
          <DialogDescription>Evidence, findings, alerts and IOCs of this case.</DialogDescription>
        </DialogHeader>
        {open ? <PickerBody orgId={orgId} investigationId={investigationId} onAdd={onAdd} /> : null}
      </DialogContent>
    </Dialog>
  );
}

function PickerBody({
  orgId,
  investigationId,
  onAdd,
}: {
  orgId: string;
  investigationId: string;
  onAdd: (ref: NoteRef) => void;
}) {
  const [source, setSource] = useState<Source>("evidence");
  const [jobId, setJobId] = useState<string>("");
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim()).toLowerCase();
  const analyses = useInvestigationAnalyses(orgId, investigationId);
  const jobs = (analyses.data?.items ?? []).filter(
    (job) => job.status === "succeeded" && (source !== "alert" || job.analyzer === "pcap"),
  );
  const job = jobs.find((j) => j.id === jobId) ?? jobs[0];
  const evidence = useCaseEvidence(orgId, investigationId, 0, 50);

  const rows = useQuery({
    queryKey: ["org", orgId, "note-ref-picker", source, job?.id ?? "", q],
    enabled: source !== "evidence" && Boolean(job),
    queryFn: async (): Promise<Candidate[]> => {
      const jobPath = { org_id: orgId, job_id: job?.id ?? "" };
      if (source === "finding") {
        const page = unwrapCase(
          await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/findings", {
            params: { path: jobPath, query: { limit: 100 } },
          }),
        );
        return page.items.map((f) => ({
          ref: { kind: "finding", ref_id: f.id, job_id: job?.id ?? null },
          text: f.title,
          detail: f.severity,
        }));
      }
      if (source === "alert") {
        const page = unwrapCase(
          await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/alerts", {
            params: { path: jobPath, query: { limit: 100 } },
          }),
        );
        return page.items.map((a) => ({
          ref: { kind: "alert", ref_id: a.id, job_id: job?.id ?? null },
          text: a.signature,
          detail: `severity ${a.severity}`,
        }));
      }
      const page = unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/iocs", {
          params: { path: jobPath, query: { limit: LIMIT, ...(q ? { q } : {}) } },
        }),
      );
      return page.items.map((i) => ({
        ref: { kind: "ioc", ref_id: i.id, job_id: job?.id ?? null },
        text: defang(i.value, i.type),
        detail: i.type,
      }));
    },
  });

  const candidates: Candidate[] =
    source === "evidence"
      ? (evidence.data?.items ?? []).map((e) => ({
          ref: { kind: "evidence", ref_id: e.id, job_id: null },
          text: e.original_filename,
          detail: e.detected_mime,
        }))
      : (rows.data ?? []);
  const shown = candidates.filter((c) => !q || source === "ioc" || c.text.toLowerCase().includes(q)).slice(0, LIMIT);
  const error = source === "evidence" ? evidence.error : rows.error;
  const loading = source === "evidence" ? evidence.isPending : rows.isFetching && !rows.data;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Record type">
        {SOURCES.map(([value, label]) => (
          <Button
            key={value}
            type="button"
            size="sm"
            variant={source === value ? "default" : "outline"}
            role="radio"
            aria-checked={source === value}
            onClick={() => setSource(value)}
          >
            {label}
          </Button>
        ))}
      </div>
      {source !== "evidence" ? (
        jobs.length === 0 ? (
          <p className="text-sm text-muted-foreground">No succeeded analysis{source === "alert" ? " of a capture" : ""} in this case.</p>
        ) : (
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Analysis</span>
            <select
              className="h-9 rounded-md border border-input bg-background px-2 text-sm"
              value={job?.id ?? ""}
              onChange={(event) => setJobId(event.target.value)}
            >
              {jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {j.evidence_filename} ({analysisKindLabel(j)})
                </option>
              ))}
            </select>
          </label>
        )
      ) : null}
      <Input
        type="search"
        placeholder="Filter"
        aria-label="Filter records"
        maxLength={200}
        value={search}
        onChange={(event) => setSearch(event.target.value)}
      />
      {error ? (
        <p className="text-sm text-destructive" role="alert">
          {caseErrorMessage(error)}
        </p>
      ) : loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : shown.length === 0 ? (
        <p className="text-sm text-muted-foreground">Nothing to link.</p>
      ) : (
        <ul className="flex max-h-80 flex-col divide-y overflow-y-auto rounded-md border">
          {shown.map((c) => (
            <li key={`${c.ref.kind}:${c.ref.ref_id}`} className="flex items-center gap-2 px-3 py-1.5 text-sm">
              <span className="min-w-0 flex-1 truncate font-mono text-xs" title={visText(c.text)}>
                {visText(c.text)}
              </span>
              {c.detail ? <span className="text-xs text-muted-foreground">{c.detail}</span> : null}
              <Button type="button" size="xs" variant="outline" onClick={() => onAdd(c.ref)}>
                Link
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
