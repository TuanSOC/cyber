/**
 * Legal holds (M7). Placing or releasing a hold needs `org.update`; the API enforces it, the UI
 * only hides the actions. A released hold keeps protecting its data until `protects_until`
 * (`released_at + RETENTION_POLICY_DELAY_DAYS`, RT1). The object-store mirror of a hold (case or org) is
 * set by the retention worker, so a new hold shows "pending" until its `s3_sync` is `synced` (RT5).
 */
import type { Schemas } from "@cyberlab/contracts";

import { api, unwrap } from "@/lib/api";
import { addDays } from "@/lib/retention";

export type LegalHold = Schemas["LegalHoldOut"];
export type LegalHoldPage = Schemas["LegalHoldPage"];
export type LegalHoldCreate = Schemas["LegalHoldCreate"];

export const HOLD_REASON_MAX = 500;
export const HOLD_PAGE_SIZE = 25;
/** `RETENTION_POLICY_DELAY_DAYS` default, until the policy (its `delay_days`) has loaded. */
export const DEFAULT_DELAY_DAYS = 7;

/** Null when the reason is acceptable, else a short message. */
export function checkReason(raw: string): string | null {
  const reason = raw.trim();
  if (!reason) return "A reason is required.";
  if (reason.length > HOLD_REASON_MAX) return `At most ${HOLD_REASON_MAX} characters.`;
  return null;
}

export type HoldState = "active" | "protecting" | "released";

/**
 * active: not released. protecting: released, still protecting until `protects_until`.
 * released: released and the delay has passed.
 */
export function holdState(hold: Pick<LegalHold, "active" | "released_at" | "protects_until">, now: number): HoldState {
  if (!hold.released_at) return "active";
  const until = hold.protects_until ? new Date(hold.protects_until).getTime() : Number.NaN;
  return hold.active || (Number.isFinite(until) && until > now) ? "protecting" : "released";
}

export const HOLD_STATE_LABELS: Record<HoldState, string> = {
  active: "Active",
  protecting: "Released (still protecting)",
  released: "Released",
};

/**
 * The object-store mirror (case and org holds, RT5): "pending" until the worker's sync covered
 * it. The API's `s3_sync` decides: an org hold's `s3_synced_at` can be a resume watermark.
 */
export function s3SyncLabel(hold: Pick<LegalHold, "s3_sync">): string {
  return hold.s3_sync === "synced" ? "Object-store hold: synced" : "Object-store hold: pending";
}

/** When the data stops being protected if the hold is released now (shown before confirming). */
export function releaseProtectsUntil(now: number, delayDays: number): Date {
  return addDays(now, delayDays);
}

/** Holds that still protect data (active, or released within the delay). */
export function protectingHolds(holds: readonly LegalHold[], now: number): LegalHold[] {
  return holds.filter((hold) => holdState(hold, now) !== "released");
}

export function holdScopeLabel(hold: Pick<LegalHold, "scope" | "case_ref">): string {
  return hold.scope === "org" ? "Whole organization" : (hold.case_ref ?? "Case");
}

// ---------------------------------------------------------------------------------------------
// API

export const holdKeys = {
  all: (orgId: string) => ["org", orgId, "legal-holds"] as const,
  list: (orgId: string, query: { investigationId?: string; activeOnly?: boolean; offset?: number }) =>
    ["org", orgId, "legal-holds", query] as const,
};

export async function fetchHolds(
  orgId: string,
  query: { investigationId?: string; activeOnly?: boolean; limit?: number; offset?: number },
): Promise<LegalHoldPage> {
  return unwrap(
    await api.GET("/api/v1/orgs/{org_id}/legal-holds", {
      params: {
        path: { org_id: orgId },
        query: {
          investigation_id: query.investigationId,
          active_only: query.activeOnly ?? false,
          limit: query.limit ?? HOLD_PAGE_SIZE,
          offset: query.offset ?? 0,
        },
      },
    }),
  );
}

export async function placeHold(orgId: string, body: LegalHoldCreate): Promise<LegalHold> {
  return unwrap(
    await api.POST("/api/v1/orgs/{org_id}/legal-holds", {
      params: { path: { org_id: orgId } },
      body: { ...body, reason: body.reason.trim() },
    }),
  );
}

export async function releaseHold(orgId: string, holdId: string, reason: string): Promise<LegalHold> {
  return unwrap(
    await api.POST("/api/v1/orgs/{org_id}/legal-holds/{hold_id}/release", {
      params: { path: { org_id: orgId, hold_id: holdId } },
      body: { reason: reason.trim() },
    }),
  );
}
