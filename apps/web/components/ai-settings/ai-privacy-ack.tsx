"use client";

import { Button } from "@/components/ui/button";
import { type AiInclusions, PSEUDONYMIZED_KINDS, disclosedCategories } from "@/lib/ai-settings";

/**
 * Body of the privacy dialog, shown when AI is turned on and again whenever the disclosure
 * widens (strings or case text on, pseudonymization off; RT22). It lists the data categories
 * that leave for the provider under the settings that will apply (`next`). The confirm button
 * stays disabled until the box is ticked; only then is `acknowledge_privacy: true` sent.
 */
export function AiPrivacyAckForm({
  next,
  notice,
  checked,
  onCheckedChange,
  onConfirm,
  onCancel,
  pending,
  confirmLabel,
  error,
}: {
  next: AiInclusions;
  notice: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  onConfirm: () => void;
  onCancel: () => void;
  pending: boolean;
  confirmLabel: string;
  error?: string | null;
}) {
  return (
    <div className="flex flex-col gap-3 text-sm">
      <div>
        <p className="font-medium">Running an analysis sends to the chosen AI provider:</p>
        <ul className="mt-1 list-disc pl-5" data-testid="ai-privacy-categories">
          {disclosedCategories(next).map((category) => (
            <li key={category}>{category}</li>
          ))}
        </ul>
      </div>
      {next.pseudonymize_internal ? (
        <div className="text-muted-foreground">
          <p>Internal names are replaced with pseudonyms before sending. Recognized as internal:</p>
          <ul className="mt-1 list-disc pl-5">
            {PSEUDONYMIZED_KINDS.map((kind) => (
              <li key={kind}>{kind}</li>
            ))}
          </ul>
          <p className="mt-1">Names it cannot recognize are sent as they are; public indicators are always sent.</p>
        </div>
      ) : (
        <p className="rounded-md border border-destructive/40 p-2 text-destructive">
          Pseudonymization is off: internal IP addresses, host names and user names are sent as they are.
        </p>
      )}
      <p className="rounded-md border p-2 text-muted-foreground">{notice}</p>
      <p className="text-muted-foreground">
        The provider&apos;s own terms and retention apply. You can preview exactly what will be sent before every run.
      </p>
      <label htmlFor="ai-ack-privacy" className="flex items-start gap-2">
        <input
          id="ai-ack-privacy"
          type="checkbox"
          className="mt-0.5 size-4 accent-primary"
          checked={checked}
          onChange={(event) => onCheckedChange(event.target.checked)}
        />
        <span>I understand which data leaves CyberLab for the AI provider and accept it for this organization.</span>
      </label>
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button disabled={!checked || pending} onClick={onConfirm} data-testid="ai-privacy-confirm">
          {confirmLabel}
        </Button>
      </div>
    </div>
  );
}
