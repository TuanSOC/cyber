/**
 * Pure helpers of the Forensics (disk) views (M9 phase 11). Everything a disk image yields is
 * attacker-chosen (paths, names, EWF acquisition values, `os_name`, messages): parsed
 * defensively and only ever rendered as text, never as markup, a link target or a download
 * name. Nothing here names a verdict: findings are leads, hash-set matches are "known" or
 * "flagged" by a reference set, and the media hash is "consistent with the hash stored at
 * acquisition", never "verified" (RT17).
 *
 * Types come from the contracts regenerated after M9 (`apps/api/app/modules/disk_forensics/
 * schemas.py`, frozen in phase 1). Unsigned 64-bit values (`media_size`, sectors, inode
 * numbers) arrive as decimal text and stay text (BigInt for arithmetic), never `Number`.
 */
import type { Schemas } from "@cyberlab/contracts";

import { type DiskProfile, type OsHint, knownErrorText } from "@/lib/analysis";
import { ApiError, errorMessage } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { apiErrorText } from "@/lib/http-errors";

export type DiskSummary = Schemas["DiskSummaryOut"];
export type DiskSegment = Schemas["DiskSegmentOut"];
export type DiskStage = Schemas["DiskStageOut"];
export type DiskArtifactStat = Schemas["DiskArtifactStatOut"];
export type DiskHashSet = Schemas["DiskHashSetOut"];
export type DiskPartition = Schemas["PartitionOut"];
export type DiskFile = Schemas["FileOut"];
export type DiskFileDetail = Schemas["FileDetailOut"];
export type DiskEvent = Schemas["EventOut"];
export type MediaHashStatus = NonNullable<DiskSummary["media_hash_status"]>;
export type FsStatus = DiskPartition["fs_status"];
export type DiskRunProfile = Extract<DiskProfile, "triage" | "full">;

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const finite = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

// ---------------------------------------------------------------------------------------------
// Limits (the API does not publish its settings; these are the defaults of `core/config.py`)

/** `DISK_MAX_IMAGE_BYTES`: the sum of a segment set (operators may raise it to 64 GiB). */
export const DISK_MAX_IMAGE_BYTES_DEFAULT = 16 * 1024 ** 3;
/** `DISK_MAX_UPLOAD_BYTES`: one segment (operators may raise it to 16 GiB). */
export const DISK_MAX_UPLOAD_BYTES_DEFAULT = 8 * 1024 ** 3;
/** `cyberlab_jobs.disk.MAX_SEGMENTS`. */
export const DISK_MAX_SEGMENTS = 64;
/** `DISK_EXPORT_MAX_BYTES` / `DISK_EXPORT_MAX_FILES` (phase 10). */
export const DISK_EXPORT_MAX_BYTES = 64 * 1024 ** 2;
export const DISK_EXPORT_MAX_FILES = 20;
/** The API's largest page and offset (`core/pagination.py`: MAX_LIMIT, MAX_OFFSET). */
export const DISK_PAGE = 100;
export const DISK_MAX_OFFSET = 10_000;

// ---------------------------------------------------------------------------------------------
// Inert text

// Bidi controls (RTLO and friends) and other invisible format characters: a file named
// `invoice‮txt.exe` must not display as `invoiceexe.txt`.
const INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
// C0 / C1 controls other than tab.
const CONTROL = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g;

const codePoint = (ch: string) => `⟨U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}⟩`;

/**
 * An attacker-chosen string for display: bidi and invisible format characters become visible
 * `⟨U+202E⟩` markers, controls too; at most `max` characters (with "…"). Rendered as a React
 * text node by the caller (never `dangerouslySetInnerHTML`, never an `href`).
 */
export function inertText(value: string | null | undefined, max = 4096): string {
  if (value === null || value === undefined) return "";
  const shown = value.replace(INVISIBLE, codePoint).replace(CONTROL, codePoint);
  return shown.length > max ? `${shown.slice(0, max)}…` : shown;
}

/** True when the string holds a bidi / invisible character (shown with a marker and a hint). */
export function hasHiddenCharacters(value: string | null | undefined): boolean {
  if (!value) return false;
  INVISIBLE.lastIndex = 0;
  CONTROL.lastIndex = 0;
  const found = INVISIBLE.test(value) || CONTROL.test(value);
  INVISIBLE.lastIndex = 0;
  CONTROL.lastIndex = 0;
  return found;
}

// ---------------------------------------------------------------------------------------------
// Unsigned 64-bit text

const U64 = /^[0-9]{1,20}$/;
const U64_MAX = BigInt("18446744073709551615");
const B10 = BigInt(10);
const B1024 = BigInt(1024);
const B10240 = BigInt(10240);

/** Decimal text of an unsigned 64-bit value as BigInt, or null (anything else, or above 2^64-1). */
export function parseU64(value: unknown): bigint | null {
  if (typeof value === "string" && U64.test(value)) {
    const n = BigInt(value);
    return n <= U64_MAX ? n : null;
  }
  // A JSON number (an older payload): only trusted below 2^53.
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

const GROUPED = new Intl.NumberFormat("en-US");

/** "1,234,567" from u64 text (exact; BigInt formatting), "—" when absent or invalid. */
export function formatU64(value: unknown): string {
  const n = parseU64(value);
  return n === null ? "—" : GROUPED.format(n);
}

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

/** A byte count from u64 text: "16.0 GiB" (exact below 2^53, two-digit BigInt rounding above). */
export function formatU64Bytes(value: unknown): string {
  const n = parseU64(value);
  if (n === null) return "—";
  if (n <= BigInt(Number.MAX_SAFE_INTEGER)) return formatBytes(Number(n));
  let unit = 0;
  let scaled = n * B10;
  while (scaled >= B10240 && unit < UNITS.length - 1) {
    scaled /= B1024;
    unit += 1;
  }
  const whole = scaled / B10;
  return `${whole}.${scaled % B10} ${UNITS[unit]}`;
}

/** Sector count × sector size as an exact byte count text, or null. */
export function sectorBytes(sectors: unknown, sectorSize: number | null | undefined): string | null {
  const n = parseU64(sectors);
  if (n === null || !sectorSize || !Number.isSafeInteger(sectorSize) || sectorSize <= 0) return null;
  return (n * BigInt(sectorSize)).toString();
}

// ---------------------------------------------------------------------------------------------
// Segment sets: natural order, siblings, limits, refusals

type Chunk = string | bigint;

function chunks(name: string): Chunk[] {
  const out: Chunk[] = [];
  for (const part of name.toLowerCase().match(/\d+|\D+/g) ?? []) out.push(/^\d/.test(part) ? BigInt(part) : part);
  return out;
}

/**
 * Natural name order of segment files: `.E01 < .E02 … < .E10 < .EAA`, `.001 < .002 … < .010`,
 * `aa < ab < ba`. Digit runs compare by value (BigInt: no overflow), text runs case-insensitively;
 * ties fall back to the raw name, so the order is total and stable.
 */
export function naturalCompare(a: string, b: string): number {
  const x = chunks(a);
  const y = chunks(b);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    const p = x[i];
    const q = y[i];
    if (typeof p === "bigint" && typeof q === "bigint") {
      if (p !== q) return p < q ? -1 : 1;
      continue;
    }
    if (typeof p === "bigint") return -1; // digits before letters (".001" before ".aa")
    if (typeof q === "bigint") return 1;
    if (p !== q) {
      // A shorter text run that is a prefix of the other sorts first ("image.e" + 99 < "image.eaa").
      return p < q ? -1 : 1;
    }
  }
  if (x.length !== y.length) return x.length - y.length;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function sortByName<T extends { original_filename: string; id?: string }>(items: readonly T[]): T[] {
  return [...items].sort(
    (a, b) => naturalCompare(a.original_filename, b.original_filename) || (a.id ?? "").localeCompare(b.id ?? ""),
  );
}

// A segment extension: EWF (`.E01`…`.E99`, `.EAA`…, also `.Ex01` / `.L01`-like not accepted),
// split raw (`.001`, `.0001`), or split's letter suffixes (`.aa`, `aa` after `x`).
const SEGMENT_EXT = /^(?:e[0-9a-z]{2}|[0-9]{2,4}|[a-z]{2})$/i;
// Common extensions the pattern also matches that are never segments.
const NOT_SEGMENT_EXT: ReadonlySet<string> = new Set(["exe", "eml", "eps", "ear", "js", "py", "sh", "db", "gz", "xz", "7z"]);

function stemAndExt(name: string): { stem: string; ext: string } | null {
  const dot = name.lastIndexOf(".");
  if (dot > 0 && dot < name.length - 1) return { stem: name.slice(0, dot).toLowerCase(), ext: name.slice(dot + 1) };
  // `split -a 2` without a dot: "imageaa", "imageab".
  const match = /^(.+?)([a-z]{2})$/i.exec(name);
  return match ? { stem: match[1].toLowerCase(), ext: match[2] } : null;
}

/** True when the name looks like one segment of a set (`.E01`, `.001`, `.aa`). */
export function isSegmentName(name: string): boolean {
  const parts = stemAndExt(name);
  return parts !== null && SEGMENT_EXT.test(parts.ext) && !NOT_SEGMENT_EXT.has(parts.ext.toLowerCase());
}

/**
 * The candidates that look like segments of the same set as `current` (same stem, a segment
 * extension of the same kind), in natural order, `current` included. A guess for the initial
 * selection only: the analyst confirms the set and its order.
 */
export function siblingSegments<T extends { id: string; original_filename: string }>(
  current: T,
  candidates: readonly T[],
): T[] {
  const mine = stemAndExt(current.original_filename);
  if (!mine || !isSegmentName(current.original_filename)) return [current];
  const kind = (ext: string) => (/^e/i.test(ext) && ext.length === 3 ? "ewf" : /^[0-9]+$/.test(ext) ? "num" : "alpha");
  const same = candidates.filter((c) => {
    if (c.id === current.id) return true;
    const parts = stemAndExt(c.original_filename);
    return parts !== null && parts.stem === mine.stem && isSegmentName(c.original_filename) && kind(parts.ext) === kind(mine.ext);
  });
  if (!same.some((c) => c.id === current.id)) same.push(current);
  return sortByName(same);
}

/** Move the item at `index` one place up (-1) or down (+1); the pinned first item never moves. */
export function moveSegment<T>(items: readonly T[], index: number, delta: -1 | 1, pinnedFirst = true): T[] {
  const target = index + delta;
  const floor = pinnedFirst ? 1 : 0;
  if (index < floor || target < floor || target >= items.length) return [...items];
  const out = [...items];
  [out[index], out[target]] = [out[target], out[index]];
  return out;
}

export type SegmentCheck = {
  total: number;
  /** Above `DISK_MAX_IMAGE_BYTES`: submission is blocked. */
  overSet: boolean;
  /** Segments above `DISK_MAX_UPLOAD_BYTES` (ordinals). */
  overSegment: number[];
  tooMany: boolean;
  /** The current evidence is not the first segment in natural order (EWF / split raw need it). */
  notFirstByName: boolean;
  ok: boolean;
};

export function checkSegments(
  segments: readonly { id: string; original_filename: string; size_bytes: number }[],
  currentId: string,
  limits: { maxImage: number; maxSegment: number } = {
    maxImage: DISK_MAX_IMAGE_BYTES_DEFAULT,
    maxSegment: DISK_MAX_UPLOAD_BYTES_DEFAULT,
  },
): SegmentCheck {
  const total = segments.reduce((sum, s) => sum + (Number.isFinite(s.size_bytes) ? s.size_bytes : 0), 0);
  const overSegment = segments.flatMap((s, i) => (s.size_bytes > limits.maxSegment ? [i] : []));
  const sorted = sortByName(segments);
  const notFirstByName = segments.length > 1 && sorted[0]?.id !== currentId;
  const tooMany = segments.length > DISK_MAX_SEGMENTS;
  const overSet = total > limits.maxImage;
  return {
    total,
    overSet,
    overSegment,
    tooMany,
    notFirstByName,
    ok: segments.length > 0 && segments[0]?.id === currentId && !overSet && overSegment.length === 0 && !tooMany,
  };
}

const SEGMENT_REASON_TEXT: Readonly<Record<string, string>> = {
  first_segment: "The evidence you run the analysis from must be the first segment.",
  too_many: `A segment set has at most ${DISK_MAX_SEGMENTS} segments.`,
  duplicate: "A segment is listed twice.",
  not_found: "A segment is not evidence of this organization (or its upload did not finish).",
  other_investigation: "A segment belongs to another case: every segment must be evidence of this case.",
  purged: "A segment's bytes were deleted by the retention policy.",
  archived: "A segment is archived.",
  empty: "A segment is an empty file.",
};

/** The `disk_segments_invalid` reason as text, with the offending segment when named. */
export function segmentsInvalidText(
  reason: string | null,
  ordinal: number | null,
  names: readonly string[] = [],
): string {
  const base = reason && Object.hasOwn(SEGMENT_REASON_TEXT, reason) ? SEGMENT_REASON_TEXT[reason] : null;
  const which =
    ordinal !== null && ordinal >= 0
      ? ` (segment ${ordinal + 1}${names[ordinal] ? `: ${inertText(names[ordinal], 200)}` : ""})`
      : "";
  return `${base ?? "The segment set was refused."}${which}`;
}

const RUN_ERROR_TEXT: Readonly<Record<string, string>> = {
  analysis_queue_full: "The disk analyzer is busy (its organization-wide queue is full). Try again when a running disk analysis finishes.",
  analysis_active: "A disk analysis of this evidence is already queued or running.",
  evidence_purged: "The evidence bytes were deleted by the retention policy, so they cannot be analyzed.",
  rate_limited: "Too many requests. Try again in a moment.",
  disk_image_set_too_large: `The segments together are larger than this platform accepts (DISK_MAX_IMAGE_BYTES, ${formatBytes(DISK_MAX_IMAGE_BYTES_DEFAULT)} by default).`,
};

const numberField = (error: ApiError, field: string): number | null => {
  const value = Object.hasOwn(error.extra, field) ? error.extra[field] : undefined;
  return typeof value === "number" && Number.isInteger(value) ? value : null;
};

/** The message for a refused disk run (segment reasons first, then the shared texts). */
export function diskRunErrorText(error: unknown, names: readonly string[] = []): string {
  if (error instanceof ApiError) {
    if (error.code === "disk_segments_invalid")
      return segmentsInvalidText(error.extraString("reason"), numberField(error, "ordinal"), names);
    if (error.code === "disk_image_too_large") {
      const ordinal = numberField(error, "ordinal");
      return `A segment is larger than this platform accepts per segment (DISK_MAX_UPLOAD_BYTES)${
        ordinal !== null ? ` (segment ${ordinal + 1}${names[ordinal] ? `: ${inertText(names[ordinal], 200)}` : ""})` : ""
      }.`;
    }
    if (Object.hasOwn(RUN_ERROR_TEXT, error.code)) return RUN_ERROR_TEXT[error.code];
  }
  const shared = apiErrorText(error);
  if (shared) return shared;
  if (error instanceof ApiError) {
    const known = knownErrorText(error.code);
    if (known) return known;
  }
  return errorMessage(error);
}

/** Texts for a refused disk segment upload (`?kind=disk`), or null for any other error. */
export function diskUploadErrorText(error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  if (error.status === 413 || error.code === "disk_image_too_large" || error.code === "payload_too_large")
    return `The segment is larger than this platform accepts (DISK_MAX_UPLOAD_BYTES, ${formatBytes(DISK_MAX_UPLOAD_BYTES_DEFAULT)} per segment by default). Split the image into smaller segments (EWF or split raw) or ask an operator to raise the limit.`;
  if (error.status === 507 || error.code === "insufficient_storage")
    return "Not enough free space to receive this segment right now. Try again later or ask an operator to free space.";
  if (error.code === "disk_image_empty") return "An empty file cannot be uploaded as a disk image segment.";
  return null;
}

// ---------------------------------------------------------------------------------------------
// Run and upload texts

export const DISK_RUN_PROFILES: readonly DiskRunProfile[] = ["triage", "full"];
export const DISK_OS_HINTS: readonly OsHint[] = ["auto", "windows", "linux"];

export const DISK_PROFILE_HINTS: Record<DiskRunProfile, string> = {
  triage:
    "Partitions, the file listing with hashes, known-file sets and YARA over likely executables, and the key artifacts (event logs, registry, Amcache, Prefetch, LNK; or syslog, auth, logins, shell history, cron, packages).",
  full: "Triage plus the $MFT, browser history and the Recycle Bin (Windows) or the systemd journal and browser history (Linux). Takes much longer and needs more temporary disk space.",
};

export const DISK_RUN_NOTICES = {
  download:
    "Every run downloads and re-verifies the whole segment set (there is no image cache), so a large image takes a while before the analysis starts.",
  order:
    "Order matters for split raw images (.001, .002 … or aa, ab …): the segments are joined in this order. EWF (.E01, .E02 …) validates its own set.",
  restricted:
    "All selected segments become restricted (TLP:RED: not sent to AI or threat-intel providers) until an admin releases them; earlier analyses of these segments are covered from now on.",
  never_auto: "Disk images are never analyzed automatically.",
} as const;

export const DISK_UPLOAD_NOTICE =
  "Each file is uploaded as its own segment and is TLP:RED material from the upload: restricted (AI and threat-intel disabled) until an admin releases it. No analysis runs automatically: run the disk analysis from the first segment's evidence page.";

// ---------------------------------------------------------------------------------------------
// Image facts (RT17: only the per-segment sha256s are platform-computed)

export const MEDIA_HASH_TEXT: Record<MediaHashStatus, { label: string; detail: string; tone: "ok" | "warn" | "muted" }> = {
  matched: {
    label: "Consistent with the hash stored at acquisition",
    detail: "The worker reported that the media hash it computed equals the hash stored in the EWF image at acquisition.",
    tone: "ok",
  },
  mismatch: {
    label: "Differs from the hash stored at acquisition",
    detail:
      "The worker reported a media hash that differs from the one stored in the EWF image at acquisition. The image may have changed or been damaged since; this is a lead to check, not a conclusion.",
    tone: "warn",
  },
  absent: {
    label: "No acquisition hash stored",
    detail:
      "The image holds no acquisition hash to compare with (raw and split raw images never do), so corrupted chunks cannot be detected this way.",
    tone: "muted",
  },
  not_verified: {
    label: "Not compared",
    detail: "The worker did not compare the media hash with the acquisition hash (for example, the run stopped early).",
    tone: "muted",
  },
};

export const FORMAT_LABELS: Record<DiskSummary["format"], string> = {
  raw: "Raw (dd)",
  split_raw: "Split raw",
  ewf: "EWF (E01)",
};

export const TIMELINE_ENGINE_LABELS: Record<DiskSummary["timeline_engine"], string> = {
  plaso: "Plaso",
  replay: "Replay (recorded output, not a live run)",
  none: "None",
};

export const FS_STATUS_TEXT: Record<FsStatus, { label: string; detail: string }> = {
  ok: { label: "Opened", detail: "The file system was opened and listed." },
  unsupported: {
    label: "Not supported",
    detail: "This file system type is not one the analyzer opens (NTFS, FAT, exFAT and ext2/3/4 only), so its files are not listed.",
  },
  encrypted: {
    label: "Encrypted",
    detail: "The partition looks encrypted (for example BitLocker or LUKS). Its contents cannot be read without the key, so no files are listed.",
  },
  undetermined: { label: "Unknown", detail: "No known file system was recognized in this partition." },
  error: { label: "Error", detail: "Opening or listing this file system failed; its listing may be missing." },
  truncated: { label: "Cut at a limit", detail: "Listing stopped at a limit: files beyond it are not listed (not evidence of absence)." },
};

export const PARTITION_OS_LABELS: Record<DiskPartition["os"], string> = { windows: "Windows", linux: "Linux", none: "—" };

// ---------------------------------------------------------------------------------------------
// Stages (a partial run is never shown as complete)

export const STAGE_LABELS: Readonly<Record<string, string>> = {
  download: "Download",
  verify: "Verify",
  layout: "Layout",
  walk: "File listing",
  collect: "Artifact collection",
  scan: "Hash sets and YARA",
  timeline: "Timeline",
  extract: "Export",
};

export const STAGE_STATUS_LABELS: Readonly<Record<string, string>> = {
  ok: "OK",
  failed: "Failed",
  timeout: "Timed out",
  skipped: "Skipped",
  truncated: "Truncated",
  unsupported: "Not supported",
};

const STAGE_REASON_TEXT: Readonly<Record<string, string>> = {
  deadline: "not enough job time left",
  profile: "not part of this profile",
  no_filesystem: "no file system to read",
  no_artifacts: "no artifact files found",
  encrypted: "encrypted partition",
  unsupported: "unsupported file system",
};

export function stageLabel(stage: string): string {
  return Object.hasOwn(STAGE_LABELS, stage) ? STAGE_LABELS[stage] : stage.replaceAll("_", " ");
}

export function stageStatusLabel(status: string): string {
  return Object.hasOwn(STAGE_STATUS_LABELS, status) ? STAGE_STATUS_LABELS[status] : status;
}

/** "Skipped (not enough job time left)"; unknown reasons are named verbatim (allow-listed ids). */
export function stageReasonText(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return Object.hasOwn(STAGE_REASON_TEXT, reason) ? STAGE_REASON_TEXT[reason] : reason.replaceAll("_", " ");
}

export type StageCompleteness = { complete: boolean; incomplete: DiskStage[]; truncated: DiskStage[] };

export function stageCompleteness(summary: Pick<DiskSummary, "stages" | "truncated"> | null | undefined): StageCompleteness {
  const stages = summary?.stages ?? [];
  const incomplete = stages.filter((s) => s.status !== "ok" && s.status !== "truncated");
  const truncated = stages.filter((s) => s.truncated || s.status === "truncated");
  return {
    complete: stages.length > 0 && incomplete.length === 0 && truncated.length === 0 && !summary?.truncated,
    incomplete,
    truncated,
  };
}

// ---------------------------------------------------------------------------------------------
// Files

export const FILE_FLAG_LABELS: Readonly<Record<string, string>> = {
  allocated: "Allocated",
  deleted: "Deleted",
  orphan: "Orphan",
  reallocated: "Reallocated",
  name_lossy: "Name not UTF-8",
  path_truncated: "Path cut",
  hard_linked: "Hard-linked",
};

export const FILE_FLAG_HINTS: Readonly<Record<string, string>> = {
  deleted: "The name entry is marked deleted; the content may be overwritten.",
  orphan: "Found without a parent directory (recovered metadata).",
  reallocated: "The metadata entry was reused by another file after this name was deleted.",
  name_lossy: "The original name bytes were not valid UTF-8; the shown name replaces them.",
  path_truncated: "The full path was longer than the analyzer keeps; it was cut.",
  hard_linked: "The same file has other names (hard links); see the detail.",
};

/** The flags worth a badge (allocated is the normal case). */
export function visibleFlags(flags: readonly string[]): string[] {
  return flags.filter((flag) => flag !== "allocated");
}

/** The `flag` filter of `/files` (one at a time, API `FileFlag`). */
export const FILE_FLAG_FILTERS = [
  ["deleted", "Deleted"],
  ["orphan", "Orphan"],
  ["stream", "Alternate data streams"],
  ["hard_linked", "Hard-linked"],
  ["known", "Known bad (reference set)"],
  ["notable", "Notable (reference set)"],
  ["yara", "YARA match"],
] as const;
export type FileFlagFilter = (typeof FILE_FLAG_FILTERS)[number][0];

export const MAGIC_FILTERS = [
  ["pe", "Windows executable (PE)"],
  ["elf", "Linux executable (ELF)"],
  ["script", "Script"],
  ["archive", "Archive"],
  ["document", "Document"],
  ["other", "Other"],
  ["empty", "Empty"],
] as const;
export type MagicFilter = (typeof MAGIC_FILTERS)[number][0];

export const KNOWN_LABELS: Record<NonNullable<DiskFile["known"]>, { label: string; hint: string }> = {
  good: {
    label: "Known (reference set)",
    hint: "Listed in a reference set of known software. Known software, not necessarily benign.",
  },
  bad: { label: "Flagged (reference set)", hint: "Listed in a reference set of files to look at. A lead, not a conclusion." },
  notable: { label: "Notable (reference set)", hint: "Listed in a reference set of notable files (for example, dual-use tools)." },
};

export const HIDE_KNOWN_LABEL = "Hide known files (reference sets)";
export const HIDE_KNOWN_HINT = "Known software, not necessarily benign.";

export const FILE_TYPE_LABELS: Record<DiskFile["type"], string> = {
  reg: "File",
  dir: "Directory",
  lnk: "Symbolic link",
  other: "Other",
};

export const TIME_BASIS_LOCAL = "local time, zone unknown";

const HASH = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;

export type FileFilters = {
  q?: string;
  partition?: number;
  flag?: FileFlagFilter;
  magic?: MagicFilter;
  hash?: string;
  ext?: string;
  from?: string;
  to?: string;
  hideKnown: boolean;
};

export type FileQuery = {
  q?: string;
  partition?: number;
  flag?: FileFlagFilter;
  magic?: MagicFilter;
  hash?: string;
  ext?: string;
  from?: string;
  to?: string;
  include_known: boolean;
};

/** A hash search term: md5 / sha1 / sha256 hex (lowercased), null when not one. */
export function hashTerm(input: string): string | null {
  const value = input.trim();
  return HASH.test(value) ? value.toLowerCase() : null;
}

/** An extension filter: 1–32 characters, no leading dot, no NUL; undefined when blank. */
export function extTerm(input: string): string | undefined {
  const value = input.trim().replace(/^\.+/, "").replace(/\u0000/g, "");
  return value ? value.slice(0, 32) : undefined;
}

/** The `/files` query of the filters (`include_known` is the inverse of "hide known"). */
export function fileQuery(filters: FileFilters): FileQuery {
  const query: FileQuery = { include_known: !filters.hideKnown };
  if (filters.q && filters.q.trim().length >= 1) query.q = filters.q.trim().slice(0, 128);
  if (filters.partition !== undefined) query.partition = filters.partition;
  if (filters.flag) query.flag = filters.flag;
  if (filters.magic) query.magic = filters.magic;
  if (filters.hash) {
    const hash = hashTerm(filters.hash);
    if (hash) query.hash = hash;
  }
  if (filters.ext) query.ext = filters.ext;
  if (filters.from) query.from = filters.from;
  if (filters.to) query.to = filters.to;
  return query;
}

/** The file's display path, with markers for a lossy name or a cut path. */
export function pathMarkers(file: Pick<DiskFile, "flags">): string[] {
  const out: string[] = [];
  if (file.flags.includes("name_lossy")) out.push("Name not UTF-8 (replaced characters)");
  if (file.flags.includes("path_truncated")) out.push("Path cut at the length limit");
  return out;
}

const EXPORT_REFUSAL_TEXT: Readonly<Record<string, string>> = {
  not_allocated: "Only allocated files can be exported (this one is deleted or orphaned).",
  not_regular: "Only regular files can be exported.",
  size_unknown: "The file size is unknown, so it cannot be exported.",
  too_large: `Only files up to ${formatBytes(DISK_EXPORT_MAX_BYTES)} can be exported.`,
  never_collected:
    "This file (under one of its names) is a protected secret store (for example a SAM hive, browser login data or a private key file) and is never exported.",
  never_collect:
    "This file (under one of its names) is a protected secret store (for example a SAM hive, browser login data or a private key file) and is never exported.",
};

export function exportRefusalText(reason: string | null | undefined): string {
  if (reason && Object.hasOwn(EXPORT_REFUSAL_TEXT, reason)) return EXPORT_REFUSAL_TEXT[reason];
  return "This file cannot be exported.";
}

// ---------------------------------------------------------------------------------------------
// Windowed rendering (500 000 rows: only the visible slice is in the DOM)

/** The [start, end) rows to render for a scroll position (with `overscan` rows each side). */
export function windowRange(
  scrollTop: number,
  viewport: number,
  rowHeight: number,
  count: number,
  overscan = 8,
): { start: number; end: number } {
  if (count <= 0 || rowHeight <= 0) return { start: 0, end: 0 };
  const first = Math.floor(Math.max(0, scrollTop) / rowHeight);
  const visible = Math.ceil(Math.max(0, viewport) / rowHeight) + 1;
  const start = Math.max(0, first - overscan);
  const end = Math.min(count, first + visible + overscan);
  return { start, end };
}

/** The next offset of an offset-paged list, or undefined at the end or at the API's offset cap. */
export function nextOffset(loaded: number, total: number, page = DISK_PAGE): number | undefined {
  if (loaded >= total) return undefined;
  const next = Math.ceil(loaded / page) * page;
  return next > DISK_MAX_OFFSET ? undefined : next;
}

/** True when more rows exist than the API can page to (narrow the filters). */
export function pastOffsetCap(loaded: number, total: number): boolean {
  return loaded < total && nextOffset(loaded, total) === undefined;
}

// ---------------------------------------------------------------------------------------------
// Job list facts (the job summary of `AnalysisJobOut`, parsed defensively)

export type DiskJobFacts = {
  format: DiskSummary["format"] | null;
  segments: number | null;
  imageBytes: number | null;
  mediaSize: string | null;
  partitions: number | null;
  files: number | null;
  findings: number | null;
  mediaHashStatus: MediaHashStatus | null;
};

const FORMATS = new Set(["raw", "split_raw", "ewf"]);
const HASH_STATES = new Set(["matched", "mismatch", "absent", "not_verified"]);

export function diskJobFacts(job: { summary?: unknown }): DiskJobFacts {
  const summary = isRecord(job.summary) ? job.summary : {};
  const image = isRecord(summary.image) ? summary.image : {};
  const counts = isRecord(summary.counts) ? summary.counts : {};
  const media = image.media_size;
  return {
    format: typeof image.format === "string" && FORMATS.has(image.format) ? (image.format as DiskSummary["format"]) : null,
    segments: finite(image.segments),
    imageBytes: finite(image.size_bytes),
    mediaSize: parseU64(typeof media === "number" ? media : typeof media === "string" ? media : null)?.toString() ?? null,
    partitions: finite(counts.partitions),
    files: finite(counts.files),
    findings: finite(counts.findings),
    mediaHashStatus:
      typeof image.media_hash_status === "string" && HASH_STATES.has(image.media_hash_status)
        ? (image.media_hash_status as MediaHashStatus)
        : null,
  };
}

/** "N partitions · M files · K findings" counts of the summary, in a fixed order. */
const COUNT_LABELS: [string, string][] = [
  ["partitions", "partitions"],
  ["files", "files"],
  ["events", "events"],
  ["findings", "findings"],
  ["iocs", "IOCs"],
];

export function diskSummaryCounts(counts: unknown): { key: string; label: string; value: number }[] {
  if (!isRecord(counts)) return [];
  return COUNT_LABELS.flatMap(([key, label]) => {
    const value = finite(counts[key]);
    return value === null ? [] : [{ key, label, value }];
  });
}

// ---------------------------------------------------------------------------------------------
// Tabs

export const DISK_TABS = [
  ["partitions", "Partitions"],
  ["files", "Files"],
  ["timeline", "Timeline"],
  ["findings", "Findings"],
  ["iocs", "IOCs"],
  ["exports", "Exports"],
] as const;

export type DiskTab = (typeof DISK_TABS)[number][0] | "overview";

export function parseDiskTab(value: string | null | undefined): DiskTab {
  return value && DISK_TABS.some(([tab]) => tab === value) ? (value as DiskTab) : "overview";
}

/** Tabs whose list reads `?ref=<row id>` (citation deep links). */
export const DISK_REF_TABS: ReadonlySet<string> = new Set(["findings", "iocs", "timeline", "files"]);

// ---------------------------------------------------------------------------------------------
// Sensitivity of a disk job (every segment; RT20)

export type DiskRestriction = "restricted" | "released" | "none" | null;

/**
 * The job's restriction from its segments' sensitivity states: restricted when any segment is,
 * released when every marked segment is released, none when none is marked, null while any is
 * unknown (fails closed in the callers).
 */
export function diskRestriction(states: readonly (string | null | undefined)[]): DiskRestriction {
  if (states.length === 0) return null;
  if (states.some((s) => s === "restricted")) return "restricted";
  if (states.some((s) => s === null || s === undefined)) return null;
  if (states.some((s) => s === "released")) return "released";
  return "none";
}

/**
 * Why "Enrich" is hidden on a disk job's IOC tab (M8 RT16 prop), or undefined when it may show.
 * Fails closed: an unknown restriction or TI flag hides it (the API refuses either way).
 */
export function diskEnrichDisabledReason(restriction: DiskRestriction, tiExcluded: boolean | null | undefined): string | undefined {
  if (restriction === "restricted")
    return "Threat-intel enrichment is off: this disk image is restricted (TLP:RED by default). An admin must release it, then each segment's threat-intel flag must be cleared.";
  if (tiExcluded === true) return "Threat-intel enrichment is off: the evidence's share policy excludes it from threat-intel lookups.";
  if (restriction === null || tiExcluded === null || tiExcluded === undefined)
    return "Threat-intel enrichment is unavailable until the sensitivity of this disk image is known.";
  return undefined;
}

export const DISK_PROFILE_RUN_LABELS: Record<DiskRunProfile, string> = { triage: "Triage", full: "Full" };
