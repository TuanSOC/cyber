"use client";

import { ExternalLink } from "lucide-react";

import { Button } from "@/components/ui/button";
import { type AiProvider, type AiProviderName, needsPaidTierAck, needsTermsAck } from "@/lib/ai-settings";

const TERMS_LINKS: Record<AiProviderName, readonly { href: string; label: string }[]> = {
  anthropic: [
    { href: "https://www.anthropic.com/legal/commercial-terms", label: "Anthropic Commercial Terms" },
    { href: "https://www.anthropic.com/legal/aup", label: "Anthropic Usage Policy" },
  ],
  gemini: [{ href: "https://ai.google.dev/gemini-api/terms", label: "Gemini API Additional Terms" }],
  mock: [],
};

export type AiAckState = { terms: boolean; paidTier: boolean };

/** Whether every acknowledgement this provider still needs is ticked. */
export function ackComplete(
  p: Pick<AiProvider, "terms_ack_at" | "requires_paid_tier_ack" | "paid_tier_ack_at">,
  ack: AiAckState,
): boolean {
  return (!needsTermsAck(p) || ack.terms) && (!needsPaidTierAck(p) || ack.paidTier);
}

/**
 * Body of a provider's first-enable dialog: what leaves the platform, the provider's terms,
 * and explicit checkboxes. "Acknowledge and enable" stays disabled until every required box
 * is ticked: the terms (`acknowledge_terms`) and, for Gemini, the paid-tier attestation
 * (`acknowledge_paid_tier`, RT5).
 */
export function AiTermsAckForm({
  provider: p,
  ack,
  onAckChange,
  onConfirm,
  onCancel,
  pending,
  error,
}: {
  provider: Pick<
    AiProvider,
    "name" | "label" | "tos_note" | "privacy_note" | "terms_ack_at" | "requires_paid_tier_ack" | "paid_tier_ack_at"
  >;
  ack: AiAckState;
  onAckChange: (ack: AiAckState) => void;
  onConfirm: () => void;
  onCancel: () => void;
  pending: boolean;
  error?: string | null;
}) {
  const termsId = `ai-ack-terms-${p.name}`;
  const paidId = `ai-ack-paid-${p.name}`;
  const askTerms = needsTermsAck(p);
  const askPaid = needsPaidTierAck(p);
  return (
    <div className="flex flex-col gap-3 text-sm">
      <p className="text-muted-foreground">{p.privacy_note}</p>
      <p className="rounded-md border p-2 text-muted-foreground">{p.tos_note}</p>
      {TERMS_LINKS[p.name].length > 0 && (
        <div className="flex flex-wrap gap-3">
          {TERMS_LINKS[p.name].map((link) => (
            <a
              key={link.href}
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              referrerPolicy="no-referrer"
              className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
            >
              {link.label} <ExternalLink className="size-3" aria-hidden />
            </a>
          ))}
        </div>
      )}
      {askTerms && (
        <label htmlFor={termsId} className="flex items-start gap-2">
          <input
            id={termsId}
            type="checkbox"
            className="mt-0.5 size-4 accent-primary"
            checked={ack.terms}
            onChange={(event) => onAckChange({ ...ack, terms: event.target.checked })}
          />
          <span>
            I confirm that {p.label} may receive evidence excerpts from this organization&apos;s analyses, and that
            its terms and usage policy fit our use.
          </span>
        </label>
      )}
      {askPaid && (
        <label htmlFor={paidId} className="flex items-start gap-2 rounded-md border border-amber-500/50 p-2">
          <input
            id={paidId}
            type="checkbox"
            className="mt-0.5 size-4 accent-primary"
            checked={ack.paidTier}
            onChange={(event) => onAckChange({ ...ack, paidTier: event.target.checked })}
          />
          <span>
            This key belongs to a Google Cloud project with billing enabled (paid tier). Free-tier keys may let Google
            use prompts for training and human review, and must not be used.
          </span>
        </label>
      )}
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button disabled={!ackComplete(p, ack) || pending} onClick={onConfirm} data-testid="ai-ack-enable">
          Acknowledge and enable
        </Button>
      </div>
    </div>
  );
}
