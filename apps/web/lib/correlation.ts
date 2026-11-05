/**
 * Deterministic correlation (M7 phase 8): typed clients for the job pivot ("also seen in"), the
 * key lookup and related cases, plus the display helpers. Counts only, no scores, and neutral
 * wording: an observable is "also observed in" another case; nothing here claims the cases share
 * an actor. Values are normalized by the server only (RT8), never in the browser.
 *
 * RT13: the key lookup is a POST with the value in the JSON body; an observable value never goes
 * in a request URL (it would land in the access logs), in storage or in the console.
 */
import type { Schemas } from "@cyberlab/contracts";

import { type JobRoute, deepLinkHref, isUuid } from "@/lib/ai";
import { ApiError, api, unwrap } from "@/lib/api";
import { caseTabHref } from "@/lib/case";
import type { LookupType } from "@/lib/ti";

export type CorrelationKind = Schemas["SeenInOut"]["kind"];
export type SeenIn = Schemas["SeenInOut"];
export type CaseRef = Schemas["CaseRefOut"];
export type JobCorrelations = Schemas["JobCorrelationsOut"];
export type Occurrence = Schemas["OccurrenceOut"];
export type CorrelationLookup = Schemas["CorrelationLookupOut"];
export type RelatedCase = Schemas["RelatedCaseOut"];
export type RelatedCases = Schemas["RelatedCasesOut"];
export type SharedKey = Schemas["SharedKeyOut"];
export type CollectionRef = Schemas["CollectionRefOut"];
export type LookupIn = Schemas["CorrelationLookupIn"];

export const KIND_LABELS: Readonly<Record<CorrelationKind, string>> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "domain",
  url: "URL",
  email: "email",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  ja3: "JA3",
  ja3s: "JA3S",
  cert_sha256: "certificate SHA-256",
};

export function isCorrelationKind(kind: string): kind is CorrelationKind {
  return Object.hasOwn(KIND_LABELS, kind);
}

export function kindLabel(kind: string): string {
  return Object.hasOwn(KIND_LABELS, kind) ? KIND_LABELS[kind as CorrelationKind] : kind.replaceAll("_", " ");
}

// ---------------------------------------------------------------------------------------------
// Clients

export const correlationKeys = {
  job: (orgId: string, jobId: string) => ["org", orgId, "correlation", "job", jobId] as const,
  // In-memory query cache only (never persisted).
  lookup: (orgId: string, kind: string, value: string) => ["org", orgId, "correlation", "key", kind, value] as const,
  related: (orgId: string, investigationId: string) => ["org", orgId, "correlation", "related", investigationId] as const,
};

type CorrelationClient = Pick<typeof api, "GET" | "POST">;

export type JobCorrelationsQuery = { kind?: CorrelationKind; cursor?: string | null; includeUnique?: boolean };

/**
 * Fetched once per IOC tab (one page of up to 200 keys; `cursor` continues); rows are matched in
 * memory, never one request per row. The query carries ids and filters only, never a value.
 */
export async function fetchJobCorrelations(
  orgId: string,
  jobId: string,
  options: JobCorrelationsQuery = {},
  client: CorrelationClient = api,
): Promise<JobCorrelations> {
  const query: { kind?: CorrelationKind; cursor?: string; include_unique?: boolean } = {};
  if (options.kind) query.kind = options.kind;
  if (options.cursor) query.cursor = options.cursor;
  if (options.includeUnique) query.include_unique = true;
  return unwrap(
    await client.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/correlations", {
      params: { path: { org_id: orgId, job_id: jobId }, query },
    }),
  );
}

/** `POST /correlations/lookup`: the value is in the JSON body only (RT13). `client` is for tests. */
export async function fetchKeyLookup(
  orgId: string,
  kind: CorrelationKind,
  value: string,
  client: CorrelationClient = api,
): Promise<CorrelationLookup> {
  return unwrap(
    await client.POST("/api/v1/orgs/{org_id}/correlations/lookup", {
      params: { path: { org_id: orgId } },
      body: { kind, value },
    }),
  );
}

/** The lookup's `422 search_query_invalid`: the value does not normalize as its kind. */
export function isUnnormalizableError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 422 && error.code === "search_query_invalid";
}

export async function fetchRelatedCases(orgId: string, investigationId: string): Promise<RelatedCases> {
  return unwrap(
    await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/related", {
      params: { path: { org_id: orgId, investigation_id: investigationId } },
    }),
  );
}

/** The threat intel lookup type of a correlation kind, or null (JA3 / certificate hashes). */
export function tiLookupType(kind: CorrelationKind): LookupType | null {
  switch (kind) {
    case "ipv4":
    case "ipv6":
    case "domain":
    case "url":
    case "email":
    case "md5":
    case "sha1":
    case "sha256":
      return kind;
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------------------------
// "Also seen in"

/** Keys seen in other cases first, then by other cases, other jobs, kind and value (stable). */
export function sortSeenIn(items: readonly SeenIn[]): SeenIn[] {
  return [...items].sort(
    (a, b) =>
      Number(a.common) - Number(b.common) ||
      b.other_cases - a.other_cases ||
      b.other_jobs - a.other_jobs ||
      a.kind.localeCompare(b.kind) ||
      a.value.localeCompare(b.value),
  );
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** The IOC row ids of the page that carry a key: `source_ids` joined with the rows (RT8: by id). */
export function seenInByRow(items: readonly SeenIn[], rowIds: Iterable<string>): Map<string, SeenIn> {
  const wanted = new Set(rowIds);
  const out = new Map<string, SeenIn>();
  for (const item of items) {
    for (const id of item.source_ids ?? []) if (wanted.has(id) && !out.has(id)) out.set(id, item);
  }
  return out;
}

/** The keys carried by the given rows first (in row order), then the others (order kept). */
export function rowsFirst(items: readonly SeenIn[], rowIds: readonly string[]): { onPage: SeenIn[]; others: SeenIn[] } {
  const byRow = seenInByRow(items, rowIds);
  const onPage: SeenIn[] = [];
  const picked = new Set<SeenIn>();
  for (const id of rowIds) {
    const item = byRow.get(id);
    if (item && !picked.has(item)) {
      picked.add(item);
      onPage.push(item);
    }
  }
  return { onPage, others: items.filter((item) => !picked.has(item)) };
}

/** The chip: "seen in 3 other cases", or "seen in 2 other jobs of this case". */
export function seenInChipText(item: Pick<SeenIn, "other_cases" | "other_jobs">): string {
  if (item.other_cases > 0) return `seen in ${plural(item.other_cases, "other case")}`;
  return `seen in ${plural(item.other_jobs, "other job")} of this case`;
}

/** The `common` badge: the key is too frequent to rank cases with. */
export function commonBadgeText(jobs: number): string {
  return `common across ${plural(jobs, "job")}; excluded from related cases`;
}

/** The panel's one-line summary. */
export function seenInSummary(data: Pick<JobCorrelations, "items" | "total_keys">): string {
  const n = data.items.length;
  if (n === 0) return "No observable of this job was observed in another job.";
  return `${plural(n, "observable")} of ${data.total_keys} also observed in other jobs of this organization.`;
}

// ---------------------------------------------------------------------------------------------
// Key drawer

export function analyzerRoute(analyzer: Occurrence["analyzer"]): JobRoute {
  return analyzer === "pcap" ? "pcap" : "malware";
}

/** The IOC tab of the job where the value was observed. */
export function occurrenceJobHref(orgId: string, occurrence: Pick<Occurrence, "analyzer" | "job_id">): string | null {
  return deepLinkHref(orgId, { route: analyzerRoute(occurrence.analyzer), job_id: occurrence.job_id, tab: "iocs", ref: null });
}

export function evidenceHref(orgId: string, evidenceId: string): string | null {
  return isUuid(orgId) && isUuid(evidenceId) ? `/o/${orgId}/evidence/${evidenceId}` : null;
}

export function lookupSummary(data: Pick<CorrelationLookup, "jobs" | "cases">): string {
  if (data.jobs === 0) return "Not observed in any job of this organization.";
  return `Also observed in ${plural(data.jobs, "job")} across ${plural(data.cases, "case")}.`;
}

export function tiHistoryText(count: number): string {
  return count === 0 ? "No stored threat intel answers" : `${plural(count, "stored threat intel answer")}`;
}

/** "In 2 IOC collections", "In 25 IOC collections (showing 20)". */
export function collectionsText(shown: number, total: number): string {
  if (total <= 0) return "In no IOC collection";
  const head = `In ${plural(total, "IOC collection")}`;
  return shown < total ? `${head} (showing ${shown})` : head;
}

/** The case IOCs tab, where the case's collections live. */
export function collectionHref(orgId: string, collection: Pick<CollectionRef, "investigation_id">): string | null {
  return isUuid(orgId) && isUuid(collection.investigation_id) ? caseTabHref(orgId, collection.investigation_id, "iocs") : null;
}

// ---------------------------------------------------------------------------------------------
// Related cases

/** "3 domain, 1 IPv4", largest first. */
export function kindsText(kinds: Readonly<Record<string, number>>): string {
  return Object.entries(kinds)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([kind, n]) => `${n} ${kindLabel(kind)}`)
    .join(", ");
}

export function sharedKeysText(n: number): string {
  return `${plural(n, "shared observable")}`;
}

export function excludedText(n: number): string | null {
  if (n <= 0) return null;
  return `${plural(n, "common observable")} excluded from the ranking (seen in too many jobs to be informative).`;
}
