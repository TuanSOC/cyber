import { describe, expect, it } from "vitest";

import type { JobRoute } from "@/lib/ai";
import { ApiError } from "@/lib/api";
import {
  NOTE_MAX_REFS,
  type NoteRef,
  addRef,
  canEditNote,
  canSubmitNote,
  editedBadge,
  isStaleNote,
  noteCounter,
  noteRefHref,
  removeRef,
  sortNotes,
  tombstoneText,
} from "@/lib/notes";

const ORG = "11111111-1111-4111-8111-111111111111";
const PCAP = "22222222-2222-4222-8222-222222222222";
const STATIC = "33333333-3333-4333-8333-333333333333";
const ROW = "44444444-4444-4444-8444-444444444444";
const routes = new Map<string, JobRoute>([
  [PCAP, "pcap"],
  [STATIC, "malware"],
]);

describe("note refs", () => {
  it("deep-links through the allowlisted M5 routes", () => {
    expect(noteRefHref(ORG, { kind: "finding", ref_id: ROW, job_id: PCAP }, routes)).toBe(
      `/o/${ORG}/pcap/${PCAP}?tab=findings&ref=${ROW}`,
    );
    expect(noteRefHref(ORG, { kind: "capability", ref_id: ROW, job_id: STATIC }, routes)).toBe(
      `/o/${ORG}/malware/${STATIC}?tab=capabilities&ref=${ROW}`,
    );
    expect(noteRefHref(ORG, { kind: "evidence", ref_id: ROW }, routes)).toBe(`/o/${ORG}/evidence/${ROW}`);
    expect(noteRefHref(ORG, { kind: "job", ref_id: PCAP }, routes)).toBe(`/o/${ORG}/pcap/${PCAP}`);
  });

  it("drops links it cannot build safely", () => {
    // Alert on a static job, unknown job, non-uuid ids.
    expect(noteRefHref(ORG, { kind: "alert", ref_id: ROW, job_id: STATIC }, routes)).toBeNull();
    expect(noteRefHref(ORG, { kind: "finding", ref_id: ROW, job_id: ROW }, routes)).toBeNull();
    expect(noteRefHref(ORG, { kind: "evidence", ref_id: "javascript:alert(1)" }, routes)).toBeNull();
    expect(noteRefHref("not-an-org", { kind: "evidence", ref_id: ROW }, routes)).toBeNull();
  });

  it("adds refs once, up to the cap, uuids only", () => {
    const ref: NoteRef = { kind: "evidence", ref_id: ROW, job_id: null };
    expect(addRef([ref], ref)).toHaveLength(1);
    expect(addRef([], { kind: "ioc", ref_id: "<img src=x>", job_id: PCAP })).toHaveLength(0);
    const many = Array.from({ length: NOTE_MAX_REFS }, (_, i) => ({
      kind: "finding" as const,
      ref_id: `44444444-4444-4444-8444-${String(i).padStart(12, "0")}`,
      job_id: PCAP,
    }));
    expect(addRef(many, ref)).toHaveLength(NOTE_MAX_REFS);
    expect(removeRef([ref], ref)).toEqual([]);
  });
});

describe("notes", () => {
  const base = {
    pinned: false,
    deleted: false,
    updated_at: "2026-11-05T10:00:00Z",
  };

  it("sorts pinned first, newest next, tombstones last", () => {
    const sorted = sortNotes([
      { ...base, id: "a" },
      { ...base, id: "b", updated_at: "2026-11-05T12:00:00Z" },
      { ...base, id: "c", pinned: true },
      { ...base, id: "d", deleted: true, updated_at: "2026-11-06T00:00:00Z" },
    ]);
    expect(sorted.map((n) => n.id)).toEqual(["c", "b", "a", "d"]);
  });

  it("counts code points against the 20 000 cap", () => {
    expect(noteCounter("😀").text).toBe("1 / 20,000");
    expect(noteCounter("x".repeat(20_001)).over).toBe(true);
    expect(canSubmitNote("   ")).toBe(false);
    expect(canSubmitNote("ok")).toBe(true);
  });

  it("badges, tombstones and the edit rule", () => {
    expect(editedBadge({ edited: true, version: 3 })).toBe("edited (v3)");
    expect(editedBadge({ edited: false, version: 1 })).toBeNull();
    const names = new Map([["u1", "Alice"]]);
    expect(tombstoneText({ deleted_by: "u1", deleted_at: "2026-11-05T10:00:00Z" }, names)).toMatch(/^Deleted by Alice at /);
    expect(tombstoneText({ deleted_by: "u9", deleted_at: null }, names)).toBe("Deleted by a member at an unknown time");
    const note = { created_by: "u1", deleted: false };
    expect(canEditNote(note, "u1", { write: true, orgUpdate: false })).toBe(true);
    expect(canEditNote(note, "u2", { write: true, orgUpdate: false })).toBe(false);
    expect(canEditNote(note, "u2", { write: true, orgUpdate: true })).toBe(true);
    expect(canEditNote(note, "u1", { write: false, orgUpdate: true })).toBe(false);
    expect(canEditNote({ ...note, deleted: true }, "u1", { write: true, orgUpdate: true })).toBe(false);
    expect(isStaleNote(new ApiError(409, "stale_note", "x"))).toBe(true);
    expect(isStaleNote(new ApiError(409, "other", "x"))).toBe(false);
  });
});
