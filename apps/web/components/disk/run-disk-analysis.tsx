"use client";

import type { Schemas } from "@cyberlab/contracts";
import { ArrowDown, ArrowUp, HardDrive, Plus, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { InertText } from "@/components/disk/inert-text";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { OS_HINT_LABELS, type OsHint, analysisErrorText } from "@/lib/analysis";
import {
  DISK_MAX_IMAGE_BYTES_DEFAULT,
  DISK_MAX_SEGMENTS,
  DISK_OS_HINTS,
  DISK_PROFILE_HINTS,
  DISK_PROFILE_RUN_LABELS,
  DISK_RUN_NOTICES,
  DISK_RUN_PROFILES,
  type DiskRunProfile,
  checkSegments,
  diskRunErrorText,
  moveSegment,
  siblingSegments,
  sortByName,
} from "@/lib/disk";
import { formatBytes } from "@/lib/format";
import { useRunDisk, useSegmentCandidates } from "@/lib/use-disk-job";

type Evidence = Schemas["EvidenceOut"];

/** Why an evidence item cannot be a segment, or null. */
export function segmentUnavailable(e: Pick<Evidence, "purged_at" | "status" | "size_bytes">): string | null {
  if (e.purged_at) return "purged by retention";
  if (e.status === "archived") return "archived";
  if (e.size_bytes <= 0) return "empty";
  return null;
}

/** The initial ordered selection: this evidence first, then its likely sibling segments. */
export function initialSegments(current: Evidence, candidates: readonly Evidence[]): Evidence[] {
  const usable = candidates.filter((c) => c.id === current.id || segmentUnavailable(c) === null);
  const siblings = siblingSegments(current, usable);
  return [current, ...siblings.filter((s) => s.id !== current.id)];
}

/**
 * The ordered segment picker (keyboard-accessible: up / down / remove buttons, no drag). The
 * current evidence is pinned first (the API requires it); the others are added from the
 * case's evidence in natural name order.
 */
export function SegmentPicker({
  currentId,
  candidates,
  selected,
  onChange,
  maxImageBytes = DISK_MAX_IMAGE_BYTES_DEFAULT,
}: {
  currentId: string;
  candidates: readonly Evidence[];
  selected: readonly Evidence[];
  onChange: (next: Evidence[]) => void;
  maxImageBytes?: number;
}) {
  const check = checkSegments(selected, currentId, { maxImage: maxImageBytes, maxSegment: Number.POSITIVE_INFINITY });
  const chosen = new Set(selected.map((s) => s.id));
  const others = sortByName(candidates.filter((c) => !chosen.has(c.id)));
  return (
    <div className="flex flex-col gap-3">
      <fieldset className="flex flex-col gap-1">
        <legend className="mb-1 text-sm font-medium">
          Segments, in order ({selected.length} of at most {DISK_MAX_SEGMENTS})
        </legend>
        <ol className="flex max-h-56 flex-col gap-1 overflow-y-auto rounded-md border p-1" aria-label="Selected segments">
          {selected.map((segment, index) => {
            const pinned = segment.id === currentId;
            return (
              <li key={segment.id} className="flex items-center gap-2 rounded px-1 py-0.5 text-sm hover:bg-muted/50">
                <span className="w-6 shrink-0 text-right text-xs text-muted-foreground tabular-nums">{index + 1}.</span>
                <span className="min-w-0 flex-1">
                  <InertText value={segment.original_filename} mono />
                </span>
                <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{formatBytes(segment.size_bytes)}</span>
                {pinned ? (
                  <span className="w-[4.5rem] shrink-0 text-right text-xs text-muted-foreground">this evidence</span>
                ) : (
                  <span className="flex shrink-0 gap-0.5">
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      className="size-6"
                      aria-label={`Move segment ${index + 1} up`}
                      disabled={index <= 1}
                      onClick={() => onChange(moveSegment(selected, index, -1))}
                    >
                      <ArrowUp className="size-3.5" aria-hidden />
                    </Button>
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      className="size-6"
                      aria-label={`Move segment ${index + 1} down`}
                      disabled={index >= selected.length - 1}
                      onClick={() => onChange(moveSegment(selected, index, 1))}
                    >
                      <ArrowDown className="size-3.5" aria-hidden />
                    </Button>
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      className="size-6"
                      aria-label={`Remove segment ${index + 1}`}
                      onClick={() => onChange(selected.filter((s) => s.id !== segment.id))}
                    >
                      <X className="size-3.5" aria-hidden />
                    </Button>
                  </span>
                )}
              </li>
            );
          })}
        </ol>
        <p
          className={check.overSet ? "text-xs font-medium text-destructive" : "text-xs text-muted-foreground"}
          data-testid="segment-total"
        >
          Total {formatBytes(check.total)} of at most {formatBytes(maxImageBytes)} (DISK_MAX_IMAGE_BYTES, default)
          {check.overSet ? ": too large, remove segments or ask an operator to raise the limit." : "."}
        </p>
        {check.notFirstByName ? (
          <p className="text-xs text-amber-700 dark:text-amber-400" data-testid="not-first">
            By name, another selected segment comes before this evidence. A disk analysis starts from the first segment:
            open the evidence page of the first segment (.E01, .001 or aa) and run it from there.
          </p>
        ) : null}
      </fieldset>
      {others.length > 0 ? (
        <details className="rounded-md border p-2 text-sm">
          <summary className="cursor-pointer text-sm">Add other evidence of this case ({others.length})</summary>
          <ul className="mt-2 flex max-h-48 flex-col gap-1 overflow-y-auto" aria-label="Other evidence of this case">
            {others.map((c) => {
              const why = segmentUnavailable(c);
              return (
                <li key={c.id} className="flex items-center gap-2">
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="size-6 shrink-0"
                    aria-label={`Add ${c.original_filename} as segment ${selected.length + 1}`}
                    disabled={why !== null || selected.length >= DISK_MAX_SEGMENTS}
                    onClick={() => onChange([...selected, c])}
                  >
                    <Plus className="size-3.5" aria-hidden />
                  </Button>
                  <span className="min-w-0 flex-1">
                    <InertText value={c.original_filename} mono />
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground">{why ?? formatBytes(c.size_bytes)}</span>
                </li>
              );
            })}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

/** The body of the run dialog (also rendered alone in tests). */
export function RunDiskForm({
  evidence,
  candidates,
  candidatesNote,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  evidence: Evidence;
  candidates: readonly Evidence[];
  candidatesNote?: string | null;
  pending: boolean;
  error: unknown;
  onSubmit: (choice: { profile: DiskRunProfile; osHint: OsHint; segments: string[] }) => void;
  onCancel: () => void;
}) {
  const [profile, setProfile] = useState<DiskRunProfile>("triage");
  const [osHint, setOsHint] = useState<OsHint>("auto");
  const [selected, setSelected] = useState<Evidence[]>(() => initialSegments(evidence, candidates));
  const check = checkSegments(selected, evidence.id);
  const names = selected.map((s) => s.original_filename);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (!pending && check.ok) onSubmit({ profile, osHint, segments: selected.map((s) => s.id) });
      }}
    >
      <SegmentPicker currentId={evidence.id} candidates={candidates} selected={selected} onChange={setSelected} />
      {candidatesNote ? <p className="text-xs text-muted-foreground">{candidatesNote}</p> : null}
      <p className="text-xs text-muted-foreground">{DISK_RUN_NOTICES.order}</p>
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium">Profile</legend>
        {DISK_RUN_PROFILES.map((value) => (
          <label key={value} className="flex items-start gap-2 text-sm">
            <input
              type="radio"
              name="disk-profile"
              className="mt-1"
              value={value}
              checked={profile === value}
              onChange={() => setProfile(value)}
            />
            <span>
              <span className="font-medium">{DISK_PROFILE_RUN_LABELS[value]}</span>
              <span className="block text-xs text-muted-foreground">{DISK_PROFILE_HINTS[value]}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium">Operating system</legend>
        <div className="flex flex-wrap gap-4">
          {DISK_OS_HINTS.map((value) => (
            <label key={value} className="flex items-center gap-2 text-sm">
              <input type="radio" name="disk-os" value={value} checked={osHint === value} onChange={() => setOsHint(value)} />
              {OS_HINT_LABELS[value]}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="flex flex-col gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-xs" data-testid="disk-run-notices">
        <p>{DISK_RUN_NOTICES.restricted}</p>
        <p>{DISK_RUN_NOTICES.download}</p>
        <p>{DISK_RUN_NOTICES.never_auto}</p>
      </div>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {diskRunErrorText(error, names)}
        </p>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending || !check.ok}>
          {pending ? "Requesting…" : "Run disk analysis"}
        </Button>
      </DialogFooter>
    </form>
  );
}

/**
 * "Run disk analysis" on an evidence item (M9 phase 11, mounted once in the evidence analyses
 * card): the ordered segment picker (evidence of this case), profile `triage` / `full` and the
 * OS hint, with the TLP:RED and re-download notices. Never automatic.
 */
export function RunDiskAnalysis({
  orgId,
  evidence,
  canRun,
  active,
  onRequested,
}: {
  orgId: string;
  evidence: Evidence;
  /** The analyses card's own rule (write permission, case and evidence not archived or purged). */
  canRun: boolean;
  /** A disk job of this evidence is already queued or running (the API answers 409). */
  active: boolean;
  onRequested: () => void;
}) {
  const [open, setOpen] = useState(false);
  const run = useRunDisk(orgId, evidence.id);
  const candidates = useSegmentCandidates(orgId, evidence.investigation_id, open);
  const list = candidates.data?.items;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) run.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button
          size="sm"
          variant="outline"
          disabled={!canRun || active}
          title={active ? "A disk analysis of this evidence is already queued or running" : "The Sleuth Kit and Plaso over a disk image, offline"}
        >
          <HardDrive className="size-4" aria-hidden />
          Run disk analysis
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Run disk analysis</DialogTitle>
          <DialogDescription className="break-all">{evidence.original_filename}</DialogDescription>
        </DialogHeader>
        {!open ? null : candidates.isError ? (
          <p role="alert" className="text-sm text-destructive">
            The evidence of this case could not be listed. Close and try again.
          </p>
        ) : !list ? (
          <p className="text-sm text-muted-foreground">Loading the evidence of this case…</p>
        ) : (
          <RunDiskForm
            evidence={evidence}
            candidates={list}
            candidatesNote={candidates.data?.capped ? "Only the first 300 evidence items of this case are offered." : null}
            pending={run.isPending}
            error={run.error}
            onCancel={() => setOpen(false)}
            onSubmit={(choice) =>
              run.mutate(choice, {
                onSuccess: (job) => {
                  if (job.status === "failed") toast.error(analysisErrorText(job.error_code) ?? "Disk analysis failed");
                  else toast.success("Disk analysis queued");
                  setOpen(false);
                  onRequested();
                },
              })
            }
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
