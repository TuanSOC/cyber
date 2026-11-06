/**
 * Disk exports (M9 phase 11):
 *
 * - the **interop downloads** of a disk job (`GET …/disk/exports/{name}`, audited; RT12): a
 *   fixed catalog of four names. Download requests are built from the job id and this catalog
 *   only, never from row text; the saved file name is the server's;
 * - the **file exports** (`POST …/disk/file-exports`, RT29; `GET /disk-exports/{id}`;
 *   `POST /disk-exports/{id}/promote`, phase 10): state texts, and the ids this browser
 *   requested per source job (the API has no per-job list route yet; see `remember*`).
 *
 * `worker_sha256` is reported by the worker and is never shown as trusted; promotion re-hashes
 * on the trusted side and the new evidence carries the platform's own hashes (RT17).
 */
import type { Schemas } from "@cyberlab/contracts";

import { isUuid } from "@/lib/ai";
import { ApiError, errorMessage } from "@/lib/api";
import { DISK_EXPORT_MAX_FILES } from "@/lib/disk";
import { apiErrorText } from "@/lib/http-errors";

export type DiskExport = Schemas["DiskExportOut"];
export type ExportState = DiskExport["state"];

export const INTEROP_EXPORTS = [
  {
    name: "bodyfile",
    label: "Body file",
    purpose: "TSK body file of the file-system times, for mactime.",
    fallback: "bodyfile.txt",
  },
  {
    name: "timeline.csv",
    label: "Timeline (CSV)",
    purpose: "The merged timeline with the Timesketch import columns (message, datetime, timestamp_desc) plus ours.",
    fallback: "timeline.csv",
  },
  {
    name: "timeline.jsonl",
    label: "Timeline (JSONL)",
    purpose: "The same timeline as JSON lines with the Timesketch import columns.",
    fallback: "timeline.jsonl",
  },
  {
    name: "notable-hashes.txt",
    label: "Notable hashes",
    purpose: "An Autopsy hash-set import: the md5 of each flagged file, one per line.",
    fallback: "notable-hashes.txt",
  },
] as const;

export type InteropExportName = (typeof INTEROP_EXPORTS)[number]["name"];

const INTEROP_NAMES: ReadonlySet<string> = new Set(INTEROP_EXPORTS.map((e) => e.name));

export function isInteropExport(name: string): name is InteropExportName {
  return INTEROP_NAMES.has(name);
}

export const INTEROP_TLP_NOTICE =
  "These files hold data from a restricted disk image: TLP:RED, labelled as such in the file name and the response. Do not share them outside the people working this case.";

/**
 * The API path of one interop download, built from a UUID job id and the fixed catalog only
 * (null otherwise). Used for the request; never rendered as an `href` from row text.
 */
export function interopExportPath(orgId: string, jobId: string, name: string): string | null {
  if (!isUuid(orgId) || !isUuid(jobId) || !isInteropExport(name)) return null;
  return `/api/v1/orgs/${orgId}/analyses/${jobId}/disk/exports/${name}`;
}

export const EXPORT_STATE_LABELS: Record<ExportState, string> = {
  pending: "Exporting…",
  ready: "Ready",
  failed: "Failed",
  promoted: "Added to the case",
  expired: "Expired",
};

export const EXPORT_STATE_HINTS: Record<ExportState, string> = {
  pending: "The export job re-downloads and re-verifies the image, then copies the file out.",
  ready: "Copied out. The size and sha256 are reported by the worker (unverified) until it is added to the case.",
  failed: "The file could not be exported.",
  promoted: "Added to the case as new evidence with the platform's own hashes.",
  expired: "The exported copy was deleted after its retention period (7 days). Export the file again if you need it.",
};

export const EXPORT_REQUEST_NOTICE =
  "Exporting starts a new job that re-downloads and re-verifies the whole image (about as long as the analysis download), then copies the selected files out. The copies are kept for 7 days unless added to the case.";

export const PROMOTE_NOTICE =
  "Adding to the case stores the file as new evidence of this case. The platform re-hashes it (the worker's hash is only accepted if it matches), keeps the restriction of the disk image, and runs the usual static analysis.";

export function isPendingExport(item: Pick<DiskExport, "state">): boolean {
  return item.state === "pending";
}

const FILE_EXPORT_ERROR_TEXT: Readonly<Record<string, string>> = {
  export_hash_mismatch:
    "The platform's hash of the exported copy did not match the worker's report, so nothing was added. Export the file again.",
  disk_export_not_allowed: "This file cannot be exported (deleted, not a regular file, too large, not allocated, or a protected secret store).",
};

/** The error text of a refused export / promote request, or of a failed export row. */
export function fileExportErrorText(error: unknown): string {
  if (typeof error === "string") return Object.hasOwn(FILE_EXPORT_ERROR_TEXT, error) ? FILE_EXPORT_ERROR_TEXT[error] : `Failed (${error}).`;
  if (error instanceof ApiError && error.code === "not_implemented") return "File export is not available on this platform yet.";
  return apiErrorText(error) ?? errorMessage(error);
}

/** Selected file ids to request: distinct, UUIDs, in order, at most `DISK_EXPORT_MAX_FILES`. */
export function exportSelection(ids: Iterable<string>): string[] {
  const out: string[] = [];
  for (const id of ids) {
    if (!isUuid(id) || out.includes(id)) continue;
    out.push(id);
    if (out.length >= DISK_EXPORT_MAX_FILES) break;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The ids of the exports requested from this browser (until the API lists a job's exports)

const STORE_PREFIX = "cyberlab:disk-exports:";
const STORE_MAX = 200;

type Storage = Pick<globalThis.Storage, "getItem" | "setItem">;

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

/** Export ids remembered for a source job (UUIDs only; empty when storage is unavailable). */
export function rememberedExports(jobId: string, store: Storage | null = storage()): string[] {
  if (!store) return [];
  try {
    const raw = store.getItem(STORE_PREFIX + jobId);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === "string" && isUuid(id)).slice(0, STORE_MAX) : [];
  } catch {
    return [];
  }
}

/** Adds export ids (newest first, deduplicated, capped). Best effort: storage may be blocked. */
export function rememberExports(jobId: string, ids: readonly string[], store: Storage | null = storage()): string[] {
  const merged = [...ids.filter(isUuid), ...rememberedExports(jobId, store)].filter((id, i, all) => all.indexOf(id) === i).slice(0, STORE_MAX);
  if (store) {
    try {
      store.setItem(STORE_PREFIX + jobId, JSON.stringify(merged));
    } catch {
      // private mode / quota: the list lives for this page only
    }
  }
  return merged;
}

// ---------------------------------------------------------------------------------------------
// Derived evidence ("Exported from disk job …")

export type DerivedOrigin = {
  /** The source disk job (UUID), null when the custody event does not name it. */
  jobId: string | null;
  partition: number | null;
  /** The path inside the image: attacker-chosen text (shown inert, never a link). */
  path: string | null;
};

/**
 * Where derived evidence came from, read from its `derived_from` custody event (phase 10:
 * source job, segment ids, partition, path, `meta_addr`), parsed defensively; null when absent.
 */
export function derivedOrigin(events: readonly { action: string; details?: unknown }[] | null | undefined): DerivedOrigin | null {
  const event = events?.find((e) => e.action === "derived_from");
  if (!event) return null;
  const details = typeof event.details === "object" && event.details !== null && !Array.isArray(event.details) ? (event.details as Record<string, unknown>) : {};
  const job = details.source_job_id ?? details.job_id;
  const partition = details.partition_index ?? details.partition;
  const path = details.path;
  return {
    jobId: typeof job === "string" && isUuid(job) ? job : null,
    partition: typeof partition === "number" && Number.isInteger(partition) && partition >= 0 ? partition : null,
    path: typeof path === "string" && path !== "" ? path : null,
  };
}
