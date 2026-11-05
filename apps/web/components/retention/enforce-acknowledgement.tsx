"use client";

import { useId } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { KEPT_CITED_NOTE, NEVER_PURGED, PURGED_BY_POLICY, acknowledgementMatches, formatDay } from "@/lib/retention";

/**
 * The typed acknowledgement for retention enforcement (the dialog body). The confirm button is
 * enabled only when the typed text equals the org name after NFC normalization and trimming;
 * the API re-checks `acknowledge_destruction` (422 retention_acknowledgement_required).
 */
export function EnforceAcknowledgement({
  orgName,
  typed,
  onTypedChange,
  enforcementStart,
  note,
  confirmLabel = "Turn on enforcement",
  pending,
  onConfirm,
  onCancel,
}: {
  orgName: string;
  typed: string;
  onTypedChange: (value: string) => void;
  /** When enforcement begins (now + the delay, RT1); null when it is already in effect. */
  enforcementStart: Date | null;
  /** An extra sentence (e.g. lowered values saved together with the acknowledgement). */
  note?: string;
  confirmLabel?: string;
  pending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const id = useId();
  const matches = acknowledgementMatches(typed, orgName);
  return (
    <form
      className="flex flex-col gap-4 text-sm"
      onSubmit={(event) => {
        event.preventDefault();
        if (matches && !pending) onConfirm();
      }}
    >
      {enforcementStart ? (
        <p>
          Enforcement permanently deletes the data the policy selects.{" "}
          <strong>Enforcement begins on {formatDay(enforcementStart)}</strong>, after the delay; until then runs stay
          dry runs and you can turn it off again.
        </p>
      ) : (
        <p>
          Enforcement is in effect: scheduled runs permanently delete the data the policy selects. You can turn it off
          at any time.
        </p>
      )}
      {note ? <p>{note}</p> : null}
      <div>
        <p className="font-medium">Purged when enforced:</p>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
          {PURGED_BY_POLICY.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
      <div>
        <p className="font-medium">Never purged by policy:</p>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
          {NEVER_PURGED.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <p className="mt-1 text-muted-foreground">{KEPT_CITED_NOTE}</p>
        <p className="mt-1 text-muted-foreground">Data covered by a legal hold is never purged.</p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`${id}-org`}>
          Type the organization name <span className="font-mono break-all">{orgName}</span> to confirm
        </Label>
        <Input
          id={`${id}-org`}
          value={typed}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onTypedChange(event.target.value)}
        />
      </div>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={!matches || pending}>
          {pending ? "Saving…" : confirmLabel}
        </Button>
      </div>
    </form>
  );
}
