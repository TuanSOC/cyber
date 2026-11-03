import type { MemberRole } from "@/lib/api";

// Mirrors app/core/rbac.py for UI affordances only; the API enforces every check.
export type Permission =
  | "org.read"
  | "org.update"
  | "members.read"
  | "members.manage"
  | "investigation.read"
  | "investigation.write"
  | "evidence.read"
  | "evidence.write"
  | "audit.read";

const READ: Permission[] = ["org.read", "members.read", "investigation.read", "evidence.read"];
const ANALYST: Permission[] = [...READ, "investigation.write", "evidence.write"];
const ADMIN: Permission[] = [...ANALYST, "org.update", "members.manage", "audit.read"];

const ROLE_PERMISSIONS: Record<MemberRole, ReadonlySet<Permission>> = {
  owner: new Set(ADMIN),
  admin: new Set(ADMIN),
  analyst: new Set(ANALYST),
  viewer: new Set(READ),
};

export function can(role: MemberRole | undefined, permission: Permission): boolean {
  return role !== undefined && ROLE_PERMISSIONS[role].has(permission);
}

export const ROLE_LABELS: Record<MemberRole, string> = {
  owner: "Owner",
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Viewer",
};

/** Roles the actor may assign (mirrors the API: only owners grant/remove the owner role). */
export function assignableRoles(actor: MemberRole): MemberRole[] {
  return actor === "owner" ? ["owner", "admin", "analyst", "viewer"] : ["admin", "analyst", "viewer"];
}
