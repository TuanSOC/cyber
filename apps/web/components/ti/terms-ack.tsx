"use client";

import { ExternalLink } from "lucide-react";

import { Button } from "@/components/ui/button";
import { type Integration, PROVIDER_TERMS_URL, TI_IOC_TYPE_LABELS, httpsPermalink, providerLabel } from "@/lib/ti";

/**
 * Body of the first-enable dialog (RT16): what the provider receives, its terms, and an explicit
 * checkbox. "Enable" stays disabled until the box is ticked; only then is
 * `acknowledge_terms: true` sent.
 */
export function TermsAckForm({
  integration: i,
  checked,
  onCheckedChange,
  onConfirm,
  onCancel,
  pending,
}: {
  integration: Pick<Integration, "name" | "label" | "supported_types" | "tos_note" | "privacy_note">;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  onConfirm: () => void;
  onCancel: () => void;
  pending: boolean;
}) {
  const label = providerLabel(i.name);
  const terms = httpsPermalink(PROVIDER_TERMS_URL[i.name]);
  const checkboxId = `ack-${i.name}`;
  return (
    <div className="flex flex-col gap-3 text-sm">
      <p>
        {label} will receive the indicators your organization enriches with it:{" "}
        {i.supported_types.map((t) => TI_IOC_TYPE_LABELS[t] ?? t).join(", ")}. Each lookup tells {label} what you are
        investigating.
      </p>
      <p className="text-muted-foreground">{i.privacy_note}</p>
      <p className="rounded-md border p-2 text-muted-foreground">{i.tos_note}</p>
      {terms && (
        <a
          href={terms}
          target="_blank"
          rel="noopener noreferrer"
          referrerPolicy="no-referrer"
          className="inline-flex items-center gap-1 self-start text-primary underline-offset-4 hover:underline"
        >
          {label} terms <ExternalLink className="size-3" aria-hidden />
        </a>
      )}
      <label htmlFor={checkboxId} className="flex items-start gap-2">
        <input
          id={checkboxId}
          type="checkbox"
          className="mt-0.5 size-4 accent-primary"
          checked={checked}
          onChange={(event) => onCheckedChange(event.target.checked)}
        />
        <span>
          I confirm that {label} may receive the indicators this organization enriches, and that its terms fit our use.
        </span>
      </label>
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button disabled={!checked || pending} onClick={onConfirm} data-testid="ack-enable">
          Acknowledge and enable
        </Button>
      </div>
    </div>
  );
}
