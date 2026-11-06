"use client";

import { useId, useState } from "react";

import { InertText } from "@/components/disk/inert-text";
import { TlpBadge } from "@/components/tlp/tlp-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { Textarea } from "@/components/ui/textarea";
import { errorMessage } from "@/lib/api";
import type { DiskRestriction } from "@/lib/disk";
import { DISK_RELEASE_ACK, DISK_RESTRICTED_BANNER } from "@/lib/evidence-sensitivity";
import { apiErrorText } from "@/lib/http-errors";
import { RELEASE_REASON_MAX, RELEASE_REASON_MIN, releaseReady } from "@/lib/memory-sensitivity";
import { usePutEvidenceSharePolicy } from "@/lib/use-case";
import { useReleaseDiskJob } from "@/lib/use-disk-job";

export type SegmentRef = { evidenceId: string; filename: string };

/** The acknowledgement and reason of a batch release (also rendered alone in tests). */
export function DiskReleaseForm({
  segments,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  segments: readonly SegmentRef[];
  pending: boolean;
  error: unknown;
  onSubmit: (body: { acknowledge: true; reason: string }) => void;
  onCancel: () => void;
}) {
  const id = useId();
  const [ack, setAck] = useState(false);
  const [reason, setReason] = useState("");
  const ready = releaseReady(ack, reason);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (ready && !pending) onSubmit({ acknowledge: true, reason: reason.trim() });
      }}
    >
      <p className="text-sm">
        This releases every still-restricted segment of this disk image ({segments.length}) in one request, recorded in
        the audit log once per segment. Files already exported from the image stay restricted (each is released on its
        own). Releasing does not change the share policy by itself: the AI and threat-intel exclusions are cleared per
        segment afterwards.
      </p>
      <label className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-sm font-medium">
        <input type="checkbox" className="mt-1" checked={ack} required name="acknowledge" onChange={(e) => setAck(e.target.checked)} />
        <span>{DISK_RELEASE_ACK}</span>
      </label>
      <div className="flex flex-col gap-1">
        <label htmlFor={`${id}-reason`} className="text-sm font-medium">
          Reason <span className="text-muted-foreground">({RELEASE_REASON_MIN}–{RELEASE_REASON_MAX} characters, audited)</span>
        </label>
        <Textarea
          id={`${id}-reason`}
          name="reason"
          rows={3}
          value={reason}
          maxLength={RELEASE_REASON_MAX}
          onChange={(e) => setReason(e.target.value)}
        />
      </div>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {apiErrorText(error) ?? errorMessage(error)}
        </p>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={!ready || pending}>
          {pending ? "Releasing…" : `Release ${segments.length === 1 ? "the segment" : `all ${segments.length} segments`}`}
        </Button>
      </DialogFooter>
    </form>
  );
}

/** One segment's "Clear AI and threat-intel exclusions" step (share-policy PUT). */
function ClearFlagsRow({ orgId, segment, investigationId }: { orgId: string; segment: SegmentRef; investigationId?: string }) {
  const put = usePutEvidenceSharePolicy(orgId, segment.evidenceId, investigationId);
  return (
    <li className="flex items-center gap-2 text-sm">
      <span className="min-w-0 flex-1">
        <InertText value={segment.filename} mono />
      </span>
      {put.isSuccess ? (
        <span className="text-xs text-muted-foreground">Exclusions cleared</span>
      ) : (
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={put.isPending}
          onClick={() => put.mutate({ ai_excluded: false, ti_excluded: false })}
        >
          {put.isPending ? "Clearing…" : "Clear AI / TI exclusions"}
        </Button>
      )}
      {put.isError ? (
        <span role="alert" className="text-xs text-destructive">
          {apiErrorText(put.error) ?? errorMessage(put.error)}
        </span>
      ) : null}
    </li>
  );
}

/** After the batch release: clear the share-policy flags segment by segment (each a choice). */
export function ClearFlagsStep({ orgId, segments, investigationId }: { orgId: string; segments: readonly SegmentRef[]; investigationId?: string }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm">
        Released. AI and threat-intel stay excluded until the flags are cleared. Clear them only for the segments whose
        content may be shared with those providers:
      </p>
      <ul className="flex max-h-64 flex-col gap-1 overflow-y-auto" aria-label="Segments">
        {segments.map((segment) => (
          <ClearFlagsRow key={segment.evidenceId} orgId={orgId} segment={segment} investigationId={investigationId} />
        ))}
      </ul>
    </div>
  );
}

function ReleaseDiskButton({
  orgId,
  jobId,
  evidenceId,
  investigationId,
  segments,
}: {
  orgId: string;
  jobId: string;
  evidenceId: string;
  investigationId?: string;
  segments: readonly SegmentRef[];
}) {
  const [open, setOpen] = useState(false);
  const release = useReleaseDiskJob(
    orgId,
    evidenceId,
    jobId,
    segments.map((s) => s.evidenceId),
  );
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next && !release.isSuccess) release.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          Release…
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Release this disk image</DialogTitle>
          <DialogDescription>Every restricted segment of this analysis.</DialogDescription>
        </DialogHeader>
        {release.isSuccess ? (
          <>
            <ClearFlagsStep orgId={orgId} segments={segments} investigationId={investigationId} />
            <DialogFooter>
              <Button type="button" onClick={() => setOpen(false)}>
                Close
              </Button>
            </DialogFooter>
          </>
        ) : open ? (
          <DiskReleaseForm
            segments={segments}
            pending={release.isPending}
            error={release.error}
            onSubmit={(body) => release.mutate(body)}
            onCancel={() => setOpen(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

/**
 * The restricted banner of a disk job page (RT20). Admins (`org.update`) get "Release…", which
 * releases every restricted segment in one acknowledged request and then offers to clear the
 * AI / TI flags segment by segment; everyone else is told to ask an admin.
 */
export function DiskSensitivityBanner({
  orgId,
  jobId,
  evidenceId,
  investigationId,
  segments,
  restriction,
  canRelease,
}: {
  orgId: string;
  jobId: string;
  evidenceId: string;
  investigationId?: string;
  segments: readonly SegmentRef[];
  restriction: DiskRestriction;
  canRelease: boolean;
}) {
  if (restriction === "none") return null;
  if (restriction === "released") {
    return (
      <Alert className="mb-6">
        <AlertTitle>Disk image released by an admin</AlertTitle>
        <AlertDescription>
          AI and threat-intel use follows each segment&apos;s share policy. Files exported from this image are released
          separately.
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <Alert className="mb-6 border-destructive/50" data-testid="disk-sensitivity-banner">
      <AlertTitle className="flex flex-wrap items-center gap-2">
        <TlpBadge tlp="red" />
        Restricted disk image
      </AlertTitle>
      <AlertDescription className="flex flex-wrap items-center gap-3">
        <span>{DISK_RESTRICTED_BANNER}</span>
        {restriction === "restricted" && canRelease ? (
          <ReleaseDiskButton
            orgId={orgId}
            jobId={jobId}
            evidenceId={evidenceId}
            investigationId={investigationId}
            segments={segments}
          />
        ) : restriction === "restricted" ? (
          <span className="text-xs text-muted-foreground">Only an admin can release it: ask an admin.</span>
        ) : null}
      </AlertDescription>
    </Alert>
  );
}
