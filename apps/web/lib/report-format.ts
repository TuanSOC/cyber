/**
 * Text and link rules of the report viewer (M6 phase 7). Pure helpers, no React.
 *
 * - `vis`: invisible characters (controls, bidi, zero-width, tags) become visible `⟨U+XXXX⟩`
 *   markers, from the materialized range table `vis-rules.json` (a byte-identical copy of the
 *   renderer's `cyberlab_jobs/vis_rules.json`, RT24). No runtime Unicode category is read, so
 *   the viewer and the PDF agree. Nothing is defanged or refanged here: the snapshot already
 *   holds the defanged text.
 * - `citationHref`: the "open current record" link of an appendix entry, built from ids only
 *   (UUID-shaped, known kinds and tabs) through the M5 `deepLinkHref`. The snapshot's own `path`
 *   is never used as an href; it only tells whether the version carries links at all (`null`
 *   in `external` snapshots, RT8) and, as a fallback, which job route the row belongs to.
 */
import type { Schemas } from "@cyberlab/contracts";

import { type AiDeepLink, deepLinkHref, isUuid } from "@/lib/ai";
import { formatBytes } from "@/lib/format";
import { formatCount } from "@/lib/pcap-results";
import visRules from "@/lib/vis-rules.json";

export type ReportCitation = Schemas["Citation"];
export type ReportJobItem = Schemas["JobItem"];

// ---------------------------------------------------------------------------------------------
// vis (RT24)

const RANGES = visRules.ranges as unknown as [number, number, string][];
const STARTS = RANGES.map((range) => range[0]);
const ENDS = RANGES.map((range) => range[1]);
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

export function isInvisible(cp: number): boolean {
  let lo = 0;
  let hi = STARTS.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (STARTS[mid] <= cp) {
      found = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return found >= 0 && cp <= ENDS[found];
}

export function visMarker(cp: number): string {
  return `⟨U+${cp.toString(16).toUpperCase().padStart(4, "0")}⟩`;
}

/** Every listed code point replaced by its visible marker; everything else unchanged. */
export function vis(text: string | null | undefined): string {
  if (!text) return "";
  if (PRINTABLE_ASCII.test(text)) return text;
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    out += isInvisible(cp) ? visMarker(cp) : ch;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Deep links (internal routes only, from ids)

type JobRoute = "pcap" | "malware" | "memory" | "forensics";
type Tab = NonNullable<AiDeepLink["tab"]>;

/** The tab of each cited kind on each job route; a kind missing here links to the job overview. */
const KIND_TABS: Record<string, Partial<Record<JobRoute, Tab>>> = {
  finding: { pcap: "findings", malware: "findings", memory: "findings", forensics: "findings" },
  alert: { pcap: "alerts" },
  flow: { pcap: "flows" },
  ioc: { pcap: "iocs", malware: "iocs", memory: "iocs", forensics: "iocs" },
  ti_result: { pcap: "iocs", malware: "iocs", memory: "iocs", forensics: "iocs" },
  timeline: { pcap: "timeline", memory: "timeline", forensics: "timeline" },
  signature: { malware: "signatures" },
  capability: { malware: "capabilities" },
  string: { malware: "strings" },
  pe_summary: { malware: "sections" },
};
const JOB_KINDS = new Set([...Object.keys(KIND_TABS), "job", "record", "sample"]);
const PATH_ROUTE = /^\/o\/[0-9a-f-]{36}\/(pcap|malware|memory|forensics)\//i;

export function jobRouteFor(analyzer: string | null | undefined): JobRoute | null {
  if (analyzer === "pcap") return "pcap";
  if (analyzer === "static") return "malware";
  if (analyzer === "memory") return "memory";
  if (analyzer === "disk") return "forensics";
  return null;
}

/** job id -> route, from the snapshot's jobs section. */
export function jobRoutes(jobs: readonly ReportJobItem[]): Map<string, JobRoute> {
  const out = new Map<string, JobRoute>();
  for (const job of jobs) {
    const route = jobRouteFor(job.analyzer);
    if (route && isUuid(job.job_id)) out.set(job.job_id.toLowerCase(), route);
  }
  return out;
}

/**
 * The internal href of a cited row's live record, or null. Null when the snapshot carries no
 * path (external profile), for non-UUID ids, unknown kinds or routes. Never absolute, never a
 * value copied from the snapshot.
 */
export function citationHref(
  orgId: string,
  citation: Pick<ReportCitation, "kind" | "ref_id" | "job_id" | "path">,
  routes: ReadonlyMap<string, JobRoute>,
  investigationId?: string | null,
): string | null {
  if (!citation.path || !isUuid(orgId)) return null;
  const kind = citation.kind;
  if (kind === "evidence") {
    return deepLinkHref(orgId, { route: "evidence", job_id: null, tab: null, ref: citation.ref_id });
  }
  if (kind === "note" || kind === "investigation") {
    if (!isUuid(investigationId)) return null;
    return deepLinkHref(orgId, { route: "investigation", job_id: null, tab: null, ref: investigationId });
  }
  if (!JOB_KINDS.has(kind) || !isUuid(citation.job_id)) return null;
  const route = routes.get(citation.job_id.toLowerCase()) ?? pathRoute(citation.path);
  if (!route) return null;
  const tab = KIND_TABS[kind]?.[route];
  if (!tab) return deepLinkHref(orgId, { route, job_id: citation.job_id, tab: "overview", ref: null });
  return deepLinkHref(orgId, { route, job_id: citation.job_id, tab, ref: citation.ref_id });
}

function pathRoute(path: string): JobRoute | null {
  const match = PATH_ROUTE.exec(path);
  return match ? (match[1].toLowerCase() as JobRoute) : null;
}

/** In-app routes of the reports module (ids checked, URL-encoded). */
export function reportsHref(orgId: string, reportId?: string, version?: number): string {
  const base = `/o/${encodeURIComponent(orgId)}/reports`;
  if (!reportId) return base;
  const report = `${base}/${encodeURIComponent(reportId)}`;
  return version === undefined ? report : `${report}/v/${Math.trunc(version)}`;
}

// ---------------------------------------------------------------------------------------------
// Formatting

/** `2026-11-06 09:00 UTC` (paper-stable: the viewer never shows local time in the document). */
export function formatUtc(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return vis(iso);
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** "Showing 500 of 3,412." when a section was capped, otherwise null. */
export function truncationNote(included: number, total: number): string | null {
  if (!(total > included)) return null;
  return `Showing ${formatCount(included)} of ${formatCount(total)}.`;
}

export function percentOf(value: number, max: number): number {
  if (!(max > 0) || !Number.isFinite(value)) return 0;
  return Math.round((value / max) * 1000) / 10;
}

export function sizeAgainstLimit(bytes: number, max: number): string {
  return `${formatBytes(bytes)} of ${formatBytes(max)} (${percentOf(bytes, max)} %)`;
}

export function unitsAgainstBudget(units: number, max: number): string {
  return `${formatCount(units)} of ${formatCount(max)} render units (${percentOf(units, max)} %)`;
}

/** Hash prefix for headings; the full value is always shown next to it. */
export function shortSha(sha: string, size = 12): string {
  return sha.slice(0, size);
}

const ALLOWED_EXTENSIONS = [".pdf", ".html", ".md", ".json"];

/**
 * A safe local filename from the server's Content-Disposition (RFC 5987 or plain), keeping one
 * of the known extensions; `fallback` otherwise.
 */
export function downloadFilename(disposition: string | null | undefined, fallback: string): string {
  let name: string | null = null;
  if (disposition) {
    const extended = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(disposition);
    if (extended) {
      try {
        name = decodeURIComponent(extended[2].trim());
      } catch {
        name = null;
      }
    }
    if (!name) {
      const plain = /filename\s*=\s*("([^"]*)"|[^;]+)/i.exec(disposition);
      name = plain ? (plain[2] ?? plain[1]).trim() : null;
    }
  }
  if (!name) return fallback;
  const safe = name.replace(/[\u0000-\u001f\u007f/\\:*?"<>|]+/g, "_").replace(/^\.+/, "").slice(0, 200);
  if (!safe) return fallback;
  const lower = safe.toLowerCase();
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext)) ? safe : fallback;
}
