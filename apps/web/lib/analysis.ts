import type { Schemas } from "@cyberlab/contracts";

export type AnalysisJob = Schemas["AnalysisJobOut"];
export type AnalysisStatus = Schemas["AnalysisStatus"];
export type Analyzer = Schemas["Analyzer"];
/** A job's profile: static `full` / `av`, memory `triage` / `full` (M8), disk `triage` / `full` /
 * `extract` (M9); null for pcap. */
export type JobProfile = Schemas["JobProfile"];
export type StaticProfile = Extract<JobProfile, "full" | "av">;
export type MemoryProfile = Extract<JobProfile, "triage" | "full">;
export type DiskProfile = Extract<JobProfile, "triage" | "full" | "extract">;
export type OsHint = Schemas["OsHint"];

/** The static profiles a user picks from (the Malware Lab's run and filter options). */
export const PROFILE_LABELS: Record<StaticProfile, string> = { full: "Full", av: "AV scan" };
/** Any job's profile as text, keyed by the whole `JobProfile` (M8 added `triage`, M9 `extract`). */
export const JOB_PROFILE_LABELS: Record<JobProfile, string> = {
  full: "Full",
  av: "AV scan",
  triage: "Triage",
  // M9: a disk file export job.
  extract: "File export",
};
export const MEMORY_PROFILE_LABELS: Record<MemoryProfile, string> = { triage: "Triage", full: "Full" };
export const DISK_PROFILE_LABELS: Record<DiskProfile, string> = { triage: "Triage", full: "Full", extract: "File export" };
export const OS_HINT_LABELS: Record<OsHint, string> = { auto: "Detect automatically", windows: "Windows", linux: "Linux" };

/** Every analyzer's job page route segment (M8 RT1: one map, no two-way "else"). */
export const ANALYZER_ROUTES: Record<Analyzer, "pcap" | "malware" | "memory" | "forensics"> = {
  pcap: "pcap",
  static: "malware",
  memory: "memory",
  disk: "forensics",
};

/** The module that shows a job, for "open it in ..." text (M8 RT1: every analyzer). */
export const ANALYZER_MODULES: Record<Analyzer, { article: string; module: string; source: string }> = {
  pcap: { article: "a PCAP analysis", module: "the PCAP Analyzer", source: "capture analysis" },
  static: { article: "a static analysis", module: "the Malware Lab", source: "file analysis" },
  memory: { article: "a memory analysis", module: "Memory Analysis", source: "memory analysis" },
  disk: { article: "a disk analysis", module: "Forensics", source: "disk analysis" },
};

/** Short label of what ran: "PCAP", "Static (full)", "AV scan", "Memory (triage)", "Memory (full)",
 * "Disk (triage)", "Disk (full)", "Disk (file export)". */
export function analysisKindLabel(job: Pick<AnalysisJob, "analyzer" | "profile">): string {
  switch (job.analyzer) {
    case "pcap":
      return "PCAP";
    case "memory":
      return job.profile === "full" ? "Memory (full)" : "Memory (triage)";
    case "disk":
      return job.profile === "full" ? "Disk (full)" : job.profile === "extract" ? "Disk (file export)" : "Disk (triage)";
    default:
      return job.profile === "av" ? "AV scan" : "Static (full)";
  }
}

/** Route segment of a job's detail page (each analyzer has its own module). */
export function analysisSegment(job: Pick<AnalysisJob, "id" | "analyzer">): string {
  return `${ANALYZER_ROUTES[job.analyzer]}/${job.id}`;
}

/** A run the user can request from the analyses card: the analyzer plus, for static, its
 * profile. Memory runs have their own dialog (profile + OS hint; `components/memory`). */
export type RunKind = "pcap" | "static_full" | "static_av";

export const RUN_KINDS: Record<RunKind, { label: string; analyzer: Analyzer; profile?: StaticProfile; hint: string }> = {
  pcap: { label: "Analyze capture", analyzer: "pcap", hint: "Zeek, Suricata and TShark over a pcap / pcapng capture" },
  static_full: {
    label: "Static analysis",
    analyzer: "static",
    profile: "full",
    hint: "PE / ELF structure, strings, YARA, capa, FLOSS and ClamAV (never executed)",
  },
  static_av: { label: "AV scan", analyzer: "static", profile: "av", hint: "ClamAV and YARA signature scan only" },
};

export type EvidenceKind = "capture" | "executable" | "other";

const CAPTURE_MIMES = new Set(["application/vnd.tcpdump.pcap", "application/x-pcapng", "application/x-pcap"]);
const EXECUTABLE_MIMES = new Set([
  "application/vnd.microsoft.portable-executable",
  "application/x-dosexec",
  "application/x-msdownload",
  "application/x-executable",
  "application/x-sharedlib",
  "application/x-pie-executable",
  "application/x-object",
]);
const CAPTURE_EXT = /\.(pcap|pcapng|cap)$/i;
const EXECUTABLE_EXT = /\.(exe|dll|sys|scr|cpl|ocx|so|elf|bin)$/i;

/**
 * Best guess of what an evidence file is, for choosing which analyses to offer first. The
 * server decides automatic runs from magic bytes; this only orders buttons (any analysis can
 * still be requested from the menu). Core dumps are not offered static analysis first.
 */
export function evidenceKind(e: {
  detected_mime: string;
  detected_description?: string;
  original_filename: string;
}): EvidenceKind {
  const mime = e.detected_mime.toLowerCase();
  const description = (e.detected_description ?? "").toLowerCase();
  if (CAPTURE_MIMES.has(mime) || /\bpcap(-?ng)?\b|tcpdump capture/.test(description)) return "capture";
  if (mime === "application/x-coredump" || description.includes("core file")) return "other";
  if (EXECUTABLE_MIMES.has(mime) || /^(pe32\+?|elf) /.test(description)) return "executable";
  // libmagic gave up (octet-stream): fall back to the (untrusted, display-only) extension.
  if (mime === "application/octet-stream" || mime === "") {
    if (CAPTURE_EXT.test(e.original_filename)) return "capture";
    if (EXECUTABLE_EXT.test(e.original_filename)) return "executable";
  }
  return "other";
}

/** Runs offered as buttons for an evidence kind (first = primary); the rest go in a menu. */
export function offeredRuns(kind: EvidenceKind): { primary: RunKind[]; more: RunKind[] } {
  switch (kind) {
    case "capture":
      return { primary: ["pcap"], more: ["static_full", "static_av"] };
    case "executable":
      return { primary: ["static_full", "static_av"], more: ["pcap"] };
    default:
      return { primary: ["static_av"], more: ["static_full", "pcap"] };
  }
}

/** The run kind of an existing job (for "an X is already running" checks); null for memory
 * and disk jobs (they are not offered from the run buttons). */
export function runKindOf(job: Pick<AnalysisJob, "analyzer" | "profile">): RunKind | null {
  if (job.analyzer === "pcap") return "pcap";
  if (job.analyzer === "memory" || job.analyzer === "disk") return null;
  return job.profile === "av" ? "static_av" : "static_full";
}

/** Poll cadence while a job is queued or running; polling stops on terminal states. */
export const ANALYSIS_POLL_MS = 3000;

export const ANALYSIS_STATUSES: AnalysisStatus[] = ["queued", "running", "succeeded", "failed"];

export const ANALYSIS_STATUS_LABELS: Record<AnalysisStatus, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
};

export function isActiveStatus(status: AnalysisStatus): boolean {
  return status === "queued" || status === "running";
}

export function anyActive(jobs: readonly Pick<AnalysisJob, "status">[] | undefined): boolean {
  return Boolean(jobs?.some((job) => isActiveStatus(job.status)));
}

/** TanStack Query `refetchInterval`: poll only while something is still in flight. */
export function pollWhileActive(jobs: readonly Pick<AnalysisJob, "status">[] | undefined): number | false {
  return anyActive(jobs) ? ANALYSIS_POLL_MS : false;
}

/** True when a job that was queued/running in `prev` is succeeded in `next` (custody gained an event). */
export function justSucceeded(
  prev: readonly Pick<AnalysisJob, "id" | "status">[] | undefined,
  next: readonly Pick<AnalysisJob, "id" | "status">[],
): boolean {
  if (!prev) return false;
  const before = new Map(prev.map((job) => [job.id, job.status]));
  return next.some((job) => {
    const was = before.get(job.id);
    return was !== undefined && isActiveStatus(was) && job.status === "succeeded";
  });
}

const ERROR_TEXT: Record<string, string> = {
  integrity_mismatch: "The stored evidence no longer matches its recorded hashes, so it was not analyzed.",
  unsupported_capture_format: "Not a supported capture format (pcap or pcapng expected).",
  unparseable_capture: "The capture could not be parsed (corrupt or truncated file).",
  capture_too_large: "The capture is larger than the analyzer accepts.",
  timed_out: "The analysis did not finish in time.",
  never_started: "The analysis was queued but no worker picked it up in time.",
  enqueue_failed: "The analysis could not be queued.",
  zeek_failed: "Zeek failed while processing the capture.",
  zeek_timeout: "Zeek did not finish in time.",
  invalid_result: "The analyzer produced a result that failed validation.",
  ingest_error: "The analyzer result could not be stored.",
  analyzer_error: "The analyzer failed unexpectedly.",
  url_expired: "The analyzer's download link expired before it could fetch the evidence.",
  evidence_unavailable: "The analyzer could not read the stored evidence.",
  result_upload_failed: "The analyzer could not upload its result.",
  result_too_large: "The analysis result exceeded the size limit.",
  tool_timeout: "An analysis tool did not finish in time.",
  // memory analyzer (M8)
  not_implemented: "Memory analysis is not available yet on this platform.",
  symbols_missing:
    "The symbol table for this kernel is not in the platform's symbol store. An operator must import it, then re-run.",
  symbols_corrupt: "A symbol table in the platform's store failed its integrity check. Ask your operator.",
  memory_parse_failed: "The memory image could not be analyzed (the process list did not parse).",
  os_undetermined: "The operating system of the memory image could not be determined.",
  unsupported_memory_format:
    "Not a supported memory image (raw, LiME, AVML, ELF core, VMware .vmem or a Windows crash dump; compressed or archived files are refused).",
  memory_image_too_large: "The memory image is larger than the memory analyzer accepts.",
  memory_image_empty: "An empty file cannot be analyzed as a memory image.",
  insufficient_disk: "The memory analyzer did not have enough free disk space for this image.",
  identify_timeout: "Identifying the memory image did not finish in time.",
  plugin_timeout: "A memory analysis step did not finish in time.",
  plugin_failed: "A memory analysis step failed.",
  engine_unavailable: "The memory analysis engine was not available.",
  // disk analyzer (M9)
  unsupported_disk_format:
    "Not a supported disk image (raw / dd, split raw or EWF E01; VMDK, VHD, QCOW, AFF, L01, compressed or archived files are refused).",
  no_supported_filesystem:
    "No supported file system could be opened (NTFS, FAT, exFAT and ext2/3/4 only; encrypted or unknown partitions are listed in the summary).",
  disk_image_too_large: "A disk image segment is larger than the disk analyzer accepts.",
  disk_image_set_too_large: "The disk image segments together are larger than the disk analyzer accepts.",
  disk_segments_invalid: "The disk image segments must be distinct evidence items of this case, in order.",
  disk_image_empty: "An empty file cannot be analyzed as a disk image.",
  disk_parse_failed: "The disk image could not be analyzed (the file listing did not parse).",
  timeline_failed: "The artifact timeline of the disk image failed.",
  walk_memory: "Listing a file system needed more memory than the disk analyzer allows.",
  stage_timeout: "A disk analysis step did not finish in time.",
  integrity_mismatch: "A segment did not match its stored hash when the analyzer downloaded it.",
  export_hash_mismatch: "An exported file did not match the analyzer's reported hash.",
  disk_export_not_allowed:
    "This file cannot be exported (deleted, not a regular file, too large, not allocated, or a protected secret store).",
  // static analyzer
  sample_too_large: "The file is larger than the static analyzer accepts.",
  av_unavailable: "The antivirus engine (ClamAV) was not available, so the file was not scanned.",
  av_not_fully_scanned:
    "ClamAV could not scan the whole file (size, nesting or archive limits): a missing match is not a clean result.",
  results_not_available: "This analysis has no stored results.",
  report_unavailable: "A report is only available for static analyses with stored results.",
  analysis_not_succeeded: "The analysis has not succeeded, so there is nothing to report yet.",
};

/** Human text for a job / API error code without the "Analysis failed" fallback (null if unknown). */
export function knownErrorText(code: string | null | undefined): string | null {
  return code && Object.hasOwn(ERROR_TEXT, code) ? ERROR_TEXT[code] : null;
}

/** Human text for a job error code; unknown codes are shown verbatim (as plain text). */
export function analysisErrorText(code: string | null | undefined): string | null {
  if (!code) return null;
  return Object.hasOwn(ERROR_TEXT, code) ? ERROR_TEXT[code] : `Analysis failed (${code}).`;
}

/** Compact duration: "850 ms", "42 s", "3 m 05 s", "1 h 02 m". */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h} h ${String(m).padStart(2, "0")} m`;
  if (m > 0) return `${m} m ${String(s).padStart(2, "0")} s`;
  return `${s} s`;
}

/** Run time of a job: started → finished, or started → now while it runs; null if never started. */
export function jobDurationMs(
  job: Pick<AnalysisJob, "started_at" | "finished_at">,
  nowMs: number,
): number | null {
  if (!job.started_at) return null;
  const start = Date.parse(job.started_at);
  const end = job.finished_at ? Date.parse(job.finished_at) : nowMs;
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  return Math.max(0, end - start);
}

export function jobDurationText(job: Pick<AnalysisJob, "started_at" | "finished_at">, nowMs: number): string {
  const ms = jobDurationMs(job, nowMs);
  return ms === null ? "—" : formatDuration(ms);
}

type Summary = Record<string, unknown>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** `tool_versions` from the summary as [name, version] pairs; anything malformed is skipped. */
export function toolVersions(summary: Summary | null | undefined): [string, string][] {
  const raw = summary?.tool_versions;
  if (!isRecord(raw)) return [];
  return Object.entries(raw)
    .filter((entry): entry is [string, string | number] =>
      typeof entry[1] === "string" || typeof entry[1] === "number",
    )
    .map(([name, version]) => [name, String(version)]);
}

export function hasSummary(summary: Summary | null | undefined): boolean {
  return isRecord(summary) && Object.keys(summary).length > 0;
}

/** Jobs of one analyzer (and optionally one profile), order preserved. */
export function jobsOf<T extends Pick<AnalysisJob, "analyzer" | "profile">>(
  jobs: readonly T[],
  analyzer: Analyzer,
  profile?: JobProfile,
): T[] {
  return jobs.filter((job) => job.analyzer === analyzer && (profile === undefined || job.profile === profile));
}

/**
 * Latest job per evidence and kind of run (analyzer + static profile; input newest first, as
 * the API returns it), preserving that order: a file with a PCAP run, a full static analysis
 * and an AV scan keeps one row each.
 */
export function latestPerEvidence<
  T extends Pick<AnalysisJob, "evidence_id"> & { analyzer?: Analyzer; profile?: JobProfile | null },
>(jobs: readonly T[]): T[] {
  const seen = new Set<string>();
  return jobs.filter((job) => {
    const key = `${job.evidence_id}:${job.analyzer ?? ""}:${job.profile ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
