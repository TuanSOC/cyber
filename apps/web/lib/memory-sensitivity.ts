/**
 * Memory sensitivity (M8, plan "Sensitivity"): a memory image is TLP:RED material by default.
 * The evidence is `restricted` (AI and threat-intel excluded through the M6 share policy) from a
 * `kind=memory` upload or its first memory job, until an admin releases it once, with an
 * acknowledgement and a reason (audited). The analyst then clears the share-policy flags.
 */
import type { SensitivityState } from "@/lib/memory";

export const RESTRICTED_BANNER =
  "TLP:RED material by default: memory can contain credentials, keys and personal data. Not sent to AI or threat-intel providers.";

export const RELEASE_ACK =
  "I understand that this memory image may contain passwords, keys, tokens, mail and other personal data, and that releasing it lets the share policy allow AI and threat-intel use.";

/** Reason bounds: the API takes 1–500; phase 8 asks for at least 10 characters. */
export const RELEASE_REASON_MIN = 10;
export const RELEASE_REASON_MAX = 500;

export function releaseReady(acknowledged: boolean, reason: string): boolean {
  const length = [...reason.trim()].length;
  return acknowledged && length >= RELEASE_REASON_MIN && length <= RELEASE_REASON_MAX;
}

/**
 * Whether the evidence is restricted: the sensitivity route's state when known, else the
 * evidence record's field. `null` when neither is known yet.
 */
export function restrictionOf(
  state: SensitivityState | null | undefined,
  evidenceField: string | null | undefined,
): "restricted" | "released" | "none" | null {
  if (state) return state;
  if (evidenceField === "restricted" || evidenceField === "released") return evidenceField;
  return evidenceField === null ? "none" : null;
}

/**
 * Why "Enrich" is hidden on a memory job's IOC tab (RT16), or undefined when it may show.
 * Fails closed: an unknown restriction or TI flag hides it (the API refuses either way).
 */
export function enrichDisabledReason(
  restriction: "restricted" | "released" | "none" | null,
  tiExcluded: boolean | null | undefined,
): string | undefined {
  if (restriction === "restricted")
    return "Threat-intel enrichment is off: this memory image is restricted (TLP:RED by default). An admin must release it, then the evidence's threat-intel flag must be cleared.";
  if (tiExcluded === true) return "Threat-intel enrichment is off: the evidence's share policy excludes it from threat-intel lookups.";
  if (restriction === null || tiExcluded === null || tiExcluded === undefined)
    return "Threat-intel enrichment is unavailable until the sensitivity of this memory image is known.";
  return undefined;
}
