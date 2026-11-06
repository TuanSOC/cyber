"use client";

import Link from "next/link";
import { useId, useState } from "react";

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
import { apiErrorText } from "@/lib/http-errors";
import { RELEASE_ACK, RELEASE_REASON_MAX, RELEASE_REASON_MIN, releaseReady } from "@/lib/memory-sensitivity";
import { orgPath } from "@/lib/nav";
import { useReleaseMemory } from "@/lib/use-memory-job";

/**
 * The body of the release dialog (also rendered alone in tests): the acknowledgement checkbox
 * and the reason; Release stays disabled until both are given.
 */
export function ReleaseForm({
  pending,
  error,
  onSubmit,
  onCancel,
}: {
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
        if (!ready || pending) return;
        onSubmit({ acknowledge: true, reason: reason.trim() });
      }}
    >
      <p className="text-sm">
        Releasing is recorded in the audit log and happens once. It does not change the share policy by itself: after
        the release, the AI and threat-intel exclusions of this evidence can be cleared in its share policy.
      </p>
      <label className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-sm font-medium">
        <input
          type="checkbox"
          className="mt-1"
          checked={ack}
          required
          name="acknowledge"
          onChange={(event) => setAck(event.target.checked)}
        />
        <span>{RELEASE_ACK}</span>
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
          onChange={(event) => setReason(event.target.value)}
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
          {pending ? "Releasing…" : "Release"}
        </Button>
      </DialogFooter>
    </form>
  );
}

/** What to do after a release: the analyst clears the flags in the evidence share policy. */
export function ReleasedNext({ orgId, evidenceId }: { orgId: string; evidenceId: string }) {
  return (
    <p className="text-sm">
      Released. AI and threat-intel stay excluded until the flags are cleared in the{" "}
      <Link className="underline underline-offset-4" href={orgPath(orgId, `evidence/${evidenceId}`)}>
        evidence share policy
      </Link>
      .
    </p>
  );
}

/**
 * "Release…" for admins (`org.update`; the caller checks it, the API re-checks): a dialog with
 * the acknowledgement and a reason, then a link to the evidence share policy.
 */
export function ReleaseButton({ orgId, evidenceId, filename }: { orgId: string; evidenceId: string; filename: string }) {
  const [open, setOpen] = useState(false);
  const release = useReleaseMemory(orgId, evidenceId);
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
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Release this memory image</DialogTitle>
          <DialogDescription className="break-all">{filename}</DialogDescription>
        </DialogHeader>
        {release.isSuccess ? (
          <>
            <ReleasedNext orgId={orgId} evidenceId={evidenceId} />
            <DialogFooter>
              <Button type="button" onClick={() => setOpen(false)}>
                Close
              </Button>
            </DialogFooter>
          </>
        ) : open ? (
          <ReleaseForm
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
