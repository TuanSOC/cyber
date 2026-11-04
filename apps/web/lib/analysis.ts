import type { Schemas } from "@cyberlab/contracts";

export type AnalysisJob = Schemas["AnalysisJobOut"];
export type AnalysisStatus = Schemas["AnalysisStatus"];

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
};

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

/** Latest job per evidence (input newest first, as the API returns it), preserving that order. */
export function latestPerEvidence<T extends Pick<AnalysisJob, "evidence_id">>(jobs: readonly T[]): T[] {
  const seen = new Set<string>();
  return jobs.filter((job) => {
    if (seen.has(job.evidence_id)) return false;
    seen.add(job.evidence_id);
    return true;
  });
}
