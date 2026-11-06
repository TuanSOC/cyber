"use client";

import type { Schemas } from "@cyberlab/contracts";

/**
 * "Run memory analysis" on an evidence item (M8 phase 1 slot, mounted once in the evidence
 * analyses card; phase 9 implements the dialog: profile triage / full, OS hint, the TLP:RED
 * notice). Memory runs are never automatic. Renders nothing until phase 9.
 */
export function RunMemoryAnalysis(props: {
  orgId: string;
  evidence: Schemas["EvidenceOut"];
  /** The analyses card's own rule (write permission, case and evidence not archived or purged). */
  canRun: boolean;
  /** A memory job of this evidence is already queued or running (the API answers 409). */
  active: boolean;
  /** Called after a run was requested (the card refreshes its list and the custody). */
  onRequested: () => void;
}): null {
  void props;
  return null;
}
