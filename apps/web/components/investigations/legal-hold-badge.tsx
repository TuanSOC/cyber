"use client";

import { Lock } from "lucide-react";

import { Badge } from "@/components/ui/badge";

export const LEGAL_HOLD_TITLE = "A legal hold protects this case's data from retention purges.";

/**
 * M7 slot (RT16): the "Legal hold" badge of a case (`InvestigationOut.legal_hold`), mounted in
 * `case-workspace.tsx` above the tab list and in the investigations list. Nothing without a hold.
 */
export function LegalHoldBadge({ legalHold }: { legalHold: boolean }) {
  if (!legalHold) return null;
  return (
    <Badge variant="secondary" className="ml-2 align-middle" title={LEGAL_HOLD_TITLE}>
      <Lock aria-hidden />
      Legal hold
    </Badge>
  );
}
