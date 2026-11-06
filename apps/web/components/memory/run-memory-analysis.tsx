"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useQuery } from "@tanstack/react-query";
import { Cpu } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

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
import { MEMORY_PROFILE_LABELS, type MemoryProfile, OS_HINT_LABELS, type OsHint, analysisErrorText } from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";
import {
  EARLIER_JOBS_NOTICE,
  MEMORY_PROFILES,
  MEMORY_PROFILE_HINTS,
  OS_HINTS,
  RUN_NOTICE,
  memoryRunErrorText,
} from "@/lib/memory";
import { useRunMemory } from "@/lib/use-memory-job";

/** The body of the run dialog (also rendered alone in tests). */
export function RunMemoryForm({
  earlierJobs,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  /** Other analyses already ran on this not-yet-restricted evidence (RT3 notice). */
  earlierJobs: boolean;
  pending: boolean;
  error: unknown;
  onSubmit: (choice: { profile: MemoryProfile; osHint: OsHint }) => void;
  onCancel: () => void;
}) {
  const [profile, setProfile] = useState<MemoryProfile>("triage");
  const [osHint, setOsHint] = useState<OsHint>("auto");
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (!pending) onSubmit({ profile, osHint });
      }}
    >
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium">Profile</legend>
        {MEMORY_PROFILES.map((value) => (
          <label key={value} className="flex items-start gap-2 text-sm">
            <input
              type="radio"
              name="memory-profile"
              className="mt-1"
              value={value}
              checked={profile === value}
              onChange={() => setProfile(value)}
            />
            <span>
              <span className="font-medium">{MEMORY_PROFILE_LABELS[value]}</span>
              <span className="block text-xs text-muted-foreground">{MEMORY_PROFILE_HINTS[value]}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium">Operating system</legend>
        <div className="flex flex-wrap gap-4">
          {OS_HINTS.map((value) => (
            <label key={value} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="memory-os"
                value={value}
                checked={osHint === value}
                onChange={() => setOsHint(value)}
              />
              {OS_HINT_LABELS[value]}
            </label>
          ))}
        </div>
      </fieldset>
      <p className="rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-xs">{RUN_NOTICE}</p>
      {earlierJobs ? (
        <p className="rounded-md border p-3 text-xs" data-testid="earlier-jobs">
          {EARLIER_JOBS_NOTICE}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {memoryRunErrorText(error)}
        </p>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Requesting…" : "Run memory analysis"}
        </Button>
      </DialogFooter>
    </form>
  );
}

/**
 * "Run memory analysis" on an evidence item (M8 phase 9, mounted once in the evidence analyses
 * card): a dialog with the profile (triage / full), the OS hint and the TLP:RED notice. Memory
 * runs are never automatic.
 */
export function RunMemoryAnalysis({
  orgId,
  evidence,
  canRun,
  active,
  onRequested,
}: {
  orgId: string;
  evidence: Schemas["EvidenceOut"];
  /** The analyses card's own rule (write permission, case and evidence not archived or purged). */
  canRun: boolean;
  /** A memory job of this evidence is already queued or running (the API answers 409). */
  active: boolean;
  /** Called after a run was requested (the card refreshes its list and the custody). */
  onRequested: () => void;
}) {
  const [open, setOpen] = useState(false);
  const run = useRunMemory(orgId, evidence.id);
  const marked = evidence.memory_sensitivity === "restricted" || evidence.memory_sensitivity === "released";
  // RT3: only an evidence item that is not marked yet can have unrestricted earlier results.
  const earlier = useQuery({
    queryKey: ["org", orgId, "evidence", evidence.id, "analyses", "memory-run-check"],
    enabled: open && !marked,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path: { org_id: orgId, evidence_id: evidence.id }, query: { limit: 1, offset: 0 } },
        }),
      ),
  });

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
          title={active ? "A memory analysis of this evidence is already queued or running" : "Volatility 3 triage of a RAM image, offline"}
        >
          <Cpu className="size-4" aria-hidden />
          Run memory analysis
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Run memory analysis</DialogTitle>
          <DialogDescription className="break-all">{evidence.original_filename}</DialogDescription>
        </DialogHeader>
        {open ? (
          <RunMemoryForm
            earlierJobs={!marked && (earlier.data?.total ?? 0) > 0}
            pending={run.isPending}
            error={run.error}
            onCancel={() => setOpen(false)}
            onSubmit={(choice) =>
              run.mutate(choice, {
                onSuccess: (job) => {
                  if (job.status === "failed") toast.error(analysisErrorText(job.error_code) ?? "Memory analysis failed");
                  else toast.success("Memory analysis queued");
                  setOpen(false);
                  onRequested();
                },
              })
            }
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
