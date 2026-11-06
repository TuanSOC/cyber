/**
 * Evidence-level sensitivity (M9, RT2): the generic routes `GET /evidence/{id}/sensitivity` and
 * `POST …/sensitivity/release` over M8's table, for every source (`memory`, `disk`, `derived`).
 * M8's memory badge and `lib/memory-sensitivity.ts` stay as they are; this serves disk images
 * and files derived from them.
 */
import type { Schemas } from "@cyberlab/contracts";

export type EvidenceSensitivity = Schemas["EvidenceSensitivityDetailOut"];
export type SensitivitySource = "memory" | "disk" | "derived";

export const SOURCE_LABELS: Record<SensitivitySource, string> = {
  memory: "Memory image",
  disk: "Disk image",
  derived: "File from a disk image",
};

export const DISK_RESTRICTED_BANNER =
  "TLP:RED material by default: a disk image holds everything the machine held (documents, mail, browser data, credentials, keys). Not sent to AI or threat-intel providers.";

export const DISK_RELEASE_ACK =
  "I understand that this evidence may contain passwords, keys, tokens, mail and other personal data, and that releasing it lets the share policy allow AI and threat-intel use.";

/** The sensitivity this generic badge shows: disk and derived evidence only (memory has M8's). */
export function genericSensitivity(
  field: { state: string; source: string } | null | undefined,
): { state: "restricted" | "released"; source: "disk" | "derived" } | null {
  if (!field) return null;
  if (field.source !== "disk" && field.source !== "derived") return null;
  if (field.state !== "restricted" && field.state !== "released") return null;
  return { state: field.state, source: field.source };
}

export function sensitivityKey(orgId: string, evidenceId: string) {
  return ["org", orgId, "evidence", evidenceId, "sensitivity"] as const;
}
