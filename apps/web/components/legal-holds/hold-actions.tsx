"use client";

import { type QueryClient, useMutation, useQueryClient } from "@tanstack/react-query";
import { Lock, LockOpen } from "lucide-react";
import { useId, useState } from "react";
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
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { errorMessage } from "@/lib/api";
import { apiErrorText } from "@/lib/http-errors";
import {
  HOLD_REASON_MAX,
  type LegalHold,
  checkReason,
  holdKeys,
  placeHold,
  releaseHold,
  releaseProtectsUntil,
} from "@/lib/legal-holds";
import { formatDay } from "@/lib/retention";

/** A hold changes `legal_hold` on cases and evidence: refresh them with the hold lists. */
export async function refreshAfterHoldChange(queryClient: QueryClient, orgId: string): Promise<void> {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: holdKeys.all(orgId) }),
    queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigation"] }),
    queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigations"] }),
    queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence"] }),
  ]);
}

function holdError(error: unknown): string {
  return apiErrorText(error) ?? errorMessage(error);
}

/** The text shown before a release is confirmed (RT1: the data stays protected for the delay). */
export function releaseNotice(until: Date, delayDays: number): string {
  return `The data stays protected for ${delayDays} more days after the release, until ${formatDay(until)}. Retention can purge it only after that date, if a policy selects it and no other hold covers it.`;
}

function ReasonField({
  id,
  value,
  onChange,
  label,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  label: string;
}) {
  const error = value ? checkReason(value) : null;
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Textarea
        id={id}
        value={value}
        maxLength={HOLD_REASON_MAX + 50}
        rows={3}
        required
        aria-invalid={error ? true : undefined}
        aria-describedby={`${id}-help`}
        onChange={(event) => onChange(event.target.value)}
      />
      <p id={`${id}-help`} className={error ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
        {error ?? `Required, at most ${HOLD_REASON_MAX} characters. Recorded in the audit log.`}
      </p>
    </div>
  );
}

/** Place an org-wide hold or a hold on one case (`org.update`; the caller hides it otherwise). */
export function PlaceHoldButton({
  orgId,
  investigationId,
  size = "sm",
}: {
  orgId: string;
  investigationId?: string;
  size?: "sm" | "default";
}) {
  const queryClient = useQueryClient();
  const id = useId();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const scope = investigationId ? "investigation" : "org";
  const place = useMutation({
    mutationFn: () => placeHold(orgId, { scope, investigation_id: investigationId ?? null, reason }),
    onSuccess: async () => {
      setOpen(false);
      setReason("");
      await refreshAfterHoldChange(queryClient, orgId);
      toast.success(scope === "org" ? "Organization hold placed" : "Case hold placed");
    },
    onError: (error) => toast.error(holdError(error)),
  });
  const invalid = checkReason(reason) !== null;
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size={size} variant="outline">
          <Lock className="size-4" aria-hidden /> {scope === "org" ? "Place organization hold" : "Place hold"}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (!invalid) place.mutate();
          }}
        >
          <DialogHeader>
            <DialogTitle>{scope === "org" ? "Place a hold on the whole organization?" : "Place a hold on this case?"}</DialogTitle>
            <DialogDescription>
              {scope === "org"
                ? "While the hold is active, retention purges nothing in this organization."
                : "While the hold is active, retention purges nothing from this case, and its evidence and report snapshots are also held in object storage."}{" "}
              This is a data-preservation control, not a legal determination.
            </DialogDescription>
          </DialogHeader>
          <ReasonField id={`${id}-reason`} value={reason} onChange={setReason} label="Reason" />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={invalid || place.isPending}>
              {place.isPending ? "Placing…" : "Place hold"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Release a hold: a reason and an explicit confirmation of the protection delay (RT1). */
export function ReleaseHoldButton({
  orgId,
  hold,
  delayDays,
}: {
  orgId: string;
  hold: Pick<LegalHold, "id" | "scope">;
  delayDays: number;
}) {
  const queryClient = useQueryClient();
  const id = useId();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const release = useMutation({
    mutationFn: () => releaseHold(orgId, hold.id, reason),
    onSuccess: async (released) => {
      setOpen(false);
      setReason("");
      await refreshAfterHoldChange(queryClient, orgId);
      toast.success(
        released.protects_until
          ? `Hold released; data protected until ${formatDay(released.protects_until)}`
          : "Hold released",
      );
    },
    onError: (error) => toast.error(holdError(error)),
  });
  const invalid = checkReason(reason) !== null;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) setNow(Date.now());
        setOpen(next);
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="ghost">
          <LockOpen className="size-4" aria-hidden /> Release
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (!invalid) release.mutate();
          }}
        >
          <DialogHeader>
            <DialogTitle>Release this {hold.scope === "org" ? "organization" : "case"} hold?</DialogTitle>
            <DialogDescription>{releaseNotice(releaseProtectsUntil(now, delayDays), delayDays)}</DialogDescription>
          </DialogHeader>
          <ReasonField id={`${id}-reason`} value={reason} onChange={setReason} label="Reason for the release" />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={invalid || release.isPending}>
              {release.isPending ? "Releasing…" : "Release hold"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
