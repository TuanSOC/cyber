"use client";

import type { Schemas } from "@cyberlab/contracts";
import { Binary } from "lucide-react";
import { useRouter } from "next/navigation";
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
import { RE_PROFILE_LABELS, type ReProfile } from "@/lib/analysis";
import { ApiError } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { NEVER_EXECUTED, RUN_COST, reOffered, reRunErrorText } from "@/lib/reverse";
import { useRunRe } from "@/lib/use-re-job";

type AnalysisJob = Schemas["AnalysisJobOut"];

export const RE_PROFILE_HINTS: Record<ReProfile, string> = {
  full: "Ghidra: functions, call graph, imports and strings per function, and pseudo-C for the most relevant functions. Minutes per sample.",
  quick: "radare2: functions, imports, strings and calls in seconds, without decompilation. Only when this platform enables it.",
};

/** The body of the run dialog (also rendered alone in tests). */
export function RunReForm({
  pending,
  error,
  quickUnavailable,
  onSubmit,
  onCancel,
}: {
  pending: boolean;
  error: unknown;
  /** The API refused `quick` (`422 profile_unavailable`): the option is no longer offered. */
  quickUnavailable: boolean;
  onSubmit: (profile: ReProfile) => void;
  onCancel: () => void;
}) {
  const [profile, setProfile] = useState<ReProfile>("full");
  const profiles: ReProfile[] = quickUnavailable ? ["full"] : ["full", "quick"];
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (!pending) onSubmit(quickUnavailable ? "full" : profile);
      }}
    >
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium">Profile</legend>
        {profiles.map((value) => (
          <label key={value} className="flex items-start gap-2 text-sm">
            <input
              type="radio"
              name="re-profile"
              className="mt-1"
              value={value}
              checked={(quickUnavailable ? "full" : profile) === value}
              onChange={() => setProfile(value)}
            />
            <span>
              <span className="font-medium">{RE_PROFILE_LABELS[value]}</span>
              <span className="block text-xs text-muted-foreground">{RE_PROFILE_HINTS[value]}</span>
            </span>
          </label>
        ))}
        {quickUnavailable ? (
          <p className="text-xs text-muted-foreground">The quick profile is not enabled on this platform.</p>
        ) : null}
      </fieldset>
      <p className="rounded-md border p-3 text-xs">{RUN_COST}</p>
      <p className="rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs" data-testid="never-executed">
        {NEVER_EXECUTED}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {reRunErrorText(error)}
        </p>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Requesting…" : "Reverse engineer"}
        </Button>
      </DialogFooter>
    </form>
  );
}

/**
 * "Reverse engineer" on a static job (M10 phase 10 fills the phase-1 slot in the Malware Lab
 * job header): offered for a succeeded static `full` job that identified a PE / ELF file and
 * a member with `evidence.write`; never automatic. A `429 too_many_active_jobs` with reason
 * `heavy_analysis_busy` says another heavy analysis is running (no queue position, RT2).
 */
export function RunReAnalysis({ orgId, job }: { orgId: string; job: AnalysisJob }) {
  const { can } = useOrg();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [quickUnavailable, setQuickUnavailable] = useState(false);
  const run = useRunRe(orgId);
  if (!reOffered(job) || !can("evidence.write")) return null;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) run.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" title="Static reverse engineering with Ghidra (the program is never run)">
          <Binary className="size-4" aria-hidden />
          Reverse engineer
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reverse engineer</DialogTitle>
          <DialogDescription className="break-all">{job.evidence_filename}</DialogDescription>
        </DialogHeader>
        {open ? (
          <RunReForm
            pending={run.isPending}
            error={run.error}
            quickUnavailable={quickUnavailable}
            onCancel={() => setOpen(false)}
            onSubmit={(profile) =>
              run.mutate(
                { evidenceId: job.evidence_id, sourceJobId: job.id, profile },
                {
                  onSuccess: (created) => {
                    toast.success("Reverse engineering queued");
                    setOpen(false);
                    router.push(orgPath(orgId, `reverse-engineering/${created.id}`));
                  },
                  onError: (error) => {
                    if (error instanceof ApiError && error.code === "profile_unavailable") setQuickUnavailable(true);
                  },
                },
              )
            }
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
