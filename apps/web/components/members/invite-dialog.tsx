"use client";

import type { MemberRole } from "@/lib/api";

/**
 * M11 slot (phase 11 implements it): invite a member by email (`POST
 * /api/v1/orgs/{org_id}/invitations`). It replaces the removed direct-add dialog: members join
 * through invitations; inviting an admin or owner asks for a step-up.
 */
export function InviteDialog({ orgId, roles }: { orgId: string; roles: MemberRole[] }) {
  void orgId;
  void roles;
  return null;
}
