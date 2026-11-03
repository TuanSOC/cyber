// Audit action names written by the API (exact-match filter values).
export const AUDIT_ACTIONS = [
  "org.created",
  "org.updated",
  "member.added",
  "member.role_changed",
  "member.removed",
  "investigation.created",
  "investigation.updated",
  "evidence.uploaded",
  "evidence.downloaded",
  "evidence.verified",
  "evidence.archived",
  "evidence.lock_failed",
] as const;
