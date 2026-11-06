"use client";

import type { Schemas } from "@cyberlab/contracts";

/**
 * "Derived from <disk image>" (M9 slot, mounted once in the evidence page header; phase 11 owns
 * the body): a file exported from a disk image links back to its source evidence
 * (`EvidenceOut.derived_from`, filled by phase 10). Phase 1 renders nothing.
 */
export function DerivedEvidenceBadge(_props: { orgId: string; evidence: Schemas["EvidenceOut"] }) {
  return null;
}
