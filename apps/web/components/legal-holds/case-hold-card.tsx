"use client";

import type { Permission } from "@/lib/roles";

/**
 * Slot (M7 phase 1, RT16): the case's legal hold (place / release), mounted once in
 * `components/investigations/overview-tab.tsx`. Phase 9 fills it from `/orgs/{org}/legal-holds`.
 * Renders nothing until then.
 */
export function CaseHoldCard({
  orgId,
  investigationId,
  legalHold,
  can,
}: {
  orgId: string;
  investigationId: string;
  legalHold: boolean;
  can: (permission: Permission) => boolean;
}) {
  void orgId;
  void investigationId;
  void legalHold;
  void can;
  return null;
}
