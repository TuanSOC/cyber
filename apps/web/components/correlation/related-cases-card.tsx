"use client";

/**
 * Slot (M7 phase 1, RT16): cases sharing observables with this one, mounted once in
 * `components/investigations/overview-tab.tsx`. Phase 8 fills it from
 * `GET /orgs/{org}/investigations/{inv}/related`. Renders nothing until then.
 */
export function RelatedCasesCard({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  void orgId;
  void investigationId;
  return null;
}
