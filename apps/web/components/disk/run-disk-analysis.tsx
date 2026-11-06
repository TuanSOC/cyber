"use client";

import type { Schemas } from "@cyberlab/contracts";

/**
 * "Run disk analysis" (M9 slot, mounted once in `evidence-analyses-card.tsx`; phase 11 owns the
 * body): the ordered segment picker (evidence of this case), profile `triage` / `full` and the OS
 * hint. Never automatic. Phase 1 renders nothing.
 */
export function RunDiskAnalysis(_props: {
  orgId: string;
  evidence: Schemas["EvidenceOut"];
  canRun: boolean;
  active: boolean;
  onRequested: () => void;
}) {
  return null;
}
