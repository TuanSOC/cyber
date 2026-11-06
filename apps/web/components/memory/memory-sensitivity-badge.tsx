"use client";

import type { Schemas } from "@cyberlab/contracts";

/**
 * The memory sensitivity of an evidence item (M8 phase 1 slot, mounted once in the evidence
 * page header; phase 8 fills `EvidenceOut.memory_sensitivity`, phase 9 renders the badge, the
 * restricted banner and the admin release). Renders nothing until phase 9.
 */
export function MemorySensitivityBadge(props: { orgId: string; evidence: Schemas["EvidenceOut"] }): null {
  void props;
  return null;
}
