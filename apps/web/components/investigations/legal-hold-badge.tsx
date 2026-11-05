"use client";

/**
 * Slot (M7 phase 1, RT16): the "legal hold" badge of a case, mounted in `case-workspace.tsx`'s
 * page header and in the investigations list. Phase 9 fills it (`InvestigationOut.legal_hold`).
 * Renders nothing until then.
 */
export function LegalHoldBadge({ legalHold }: { legalHold: boolean }) {
  void legalHold;
  return null;
}
