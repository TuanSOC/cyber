/**
 * Analyst notes (M6): plain text only. A note body is never parsed as Markdown or HTML and
 * never becomes a link; the only links are the typed refs, built from the allowlisted M5
 * deep-link helper (`deepLinkHref`), never from note text.
 */
import type { Schemas } from "@cyberlab/contracts";

import { type AiDeepLink, type JobRoute, deepLinkHref, isUuid } from "@/lib/ai";
import { ApiError } from "@/lib/api";
import { formatDate } from "@/lib/format";

export type Note = Schemas["NoteOut"];
export type NoteDetail = Schemas["NoteDetail"];
export type NoteVersion = Schemas["NoteVersionOut"];
export type NoteRef = Schemas["NoteRef"];
export type NoteRefKind = NoteRef["kind"];
export type NoteCreate = Schemas["NoteCreate"];
export type NoteUpdate = Schemas["NoteUpdate"];

export const NOTE_MAX_CHARS = 20_000;
export const NOTE_MAX_REFS = 20;

/** Characters as the API counts them (code points), so the counter matches the 422. */
export function noteLength(body: string): number {
  return Array.from(body).length;
}

export function noteCounter(body: string): { text: string; over: boolean } {
  const n = noteLength(body);
  return { text: `${n.toLocaleString("en-US")} / ${NOTE_MAX_CHARS.toLocaleString("en-US")}`, over: n > NOTE_MAX_CHARS };
}

export function canSubmitNote(body: string): boolean {
  const n = noteLength(body);
  return body.trim().length > 0 && n <= NOTE_MAX_CHARS;
}

/** Pinned first, then the most recently updated; deleted tombstones last. */
export function sortNotes<T extends Pick<Note, "pinned" | "updated_at" | "deleted" | "id">>(notes: readonly T[]): T[] {
  return [...notes].sort((a, b) => {
    if (a.deleted !== b.deleted) return a.deleted ? 1 : -1;
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    const t = Date.parse(b.updated_at) - Date.parse(a.updated_at);
    return t !== 0 ? t : a.id.localeCompare(b.id);
  });
}

/** "edited (v3)" when the note has more than one version. */
export function editedBadge(note: Pick<Note, "edited" | "version">): string | null {
  return note.edited || note.version > 1 ? `edited (v${note.version})` : null;
}

/** "deleted by Name at time" for a tombstone (the name from the member list when known). */
export function tombstoneText(note: Pick<Note, "deleted_at" | "deleted_by">, names: ReadonlyMap<string, string>): string {
  const who = (note.deleted_by && names.get(note.deleted_by)) || "a member";
  const when = note.deleted_at ? formatDate(note.deleted_at).local : "an unknown time";
  return `Deleted by ${who} at ${when}`;
}

/** Only the author or an `org.update` holder edits or deletes a note. */
export function canEditNote(
  note: Pick<Note, "created_by" | "deleted">,
  userId: string | undefined,
  perms: { write: boolean; orgUpdate: boolean },
): boolean {
  if (note.deleted || !perms.write) return false;
  return perms.orgUpdate || (userId !== undefined && note.created_by === userId);
}

/** A `409 stale_note` answer (someone saved a newer version). */
export function isStaleNote(error: unknown): boolean {
  return error instanceof ApiError && error.code === "stale_note";
}

// ---------------------------------------------------------------------------------------------
// Refs

export const NOTE_REF_KIND_LABELS: Record<NoteRefKind, string> = {
  finding: "Finding",
  alert: "Alert",
  ioc: "IOC",
  evidence: "Evidence",
  job: "Analysis",
  timeline: "Capture event",
  capability: "Capability",
  signature: "Signature",
};

const KIND_TAB: Partial<Record<NoteRefKind, { route?: JobRoute; tab: NonNullable<AiDeepLink["tab"]> }>> = {
  finding: { tab: "findings" },
  ioc: { tab: "iocs" },
  alert: { route: "pcap", tab: "alerts" },
  timeline: { route: "pcap", tab: "timeline" },
  capability: { route: "malware", tab: "capabilities" },
  signature: { route: "malware", tab: "signatures" },
};

/**
 * Internal href of a note ref through the M5 deep-link helper, or null. `routes` maps a job id
 * to its module (pcap / malware) from the case's analyses; unknown jobs get no link.
 */
export function noteRefHref(orgId: string, ref: NoteRef, routes: ReadonlyMap<string, JobRoute>): string | null {
  if (ref.kind === "evidence") return deepLinkHref(orgId, { route: "evidence", job_id: null, tab: null, ref: ref.ref_id });
  if (ref.kind === "job") {
    const jobId = ref.job_id ?? ref.ref_id;
    const route = routes.get(jobId);
    return route ? deepLinkHref(orgId, { route, job_id: jobId, tab: null, ref: null }) : null;
  }
  const spec = KIND_TAB[ref.kind];
  if (!spec || !ref.job_id) return null;
  const route = routes.get(ref.job_id);
  if (!route || (spec.route && spec.route !== route)) return null;
  return deepLinkHref(orgId, { route, job_id: ref.job_id, tab: spec.tab, ref: ref.ref_id });
}

/** Chip text of a ref: kind plus a short id (never note text). */
export function noteRefLabel(ref: NoteRef, label?: string): string {
  const kind = NOTE_REF_KIND_LABELS[ref.kind] ?? ref.kind;
  return label ? `${kind} · ${label}` : `${kind} · ${ref.ref_id.slice(0, 8)}`;
}

export function refKey(ref: NoteRef): string {
  return `${ref.kind}:${ref.job_id ?? ""}:${ref.ref_id}`;
}

/** Adds a ref unless already present or the 20-ref cap is reached. */
export function addRef(refs: readonly NoteRef[], ref: NoteRef): NoteRef[] {
  if (refs.length >= NOTE_MAX_REFS || refs.some((r) => refKey(r) === refKey(ref))) return [...refs];
  if (!isUuid(ref.ref_id)) return [...refs];
  return [...refs, ref];
}

export function removeRef(refs: readonly NoteRef[], ref: NoteRef): NoteRef[] {
  return refs.filter((r) => refKey(r) !== refKey(ref));
}
