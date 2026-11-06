/**
 * The org's job metrics (M7, `audit.read`): counts, failure rate, p50 / p95 run and queue
 * latency and parse success per analyzer, from the org's own jobs. Plain numbers and tables, no
 * chart library. Platform-wide metrics are served to operators at `/internal/metrics`.
 */
import type { Schemas } from "@cyberlab/contracts";

import { isUuid } from "@/lib/ai";
import { ANALYZER_ROUTES, type AnalysisJob, analysisKindLabel } from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";

export type OrgOpsMetrics = Schemas["OrgOpsMetricsOut"];
export type KindMetrics = Schemas["KindMetricsOut"];
export type OpsWindow = OrgOpsMetrics["window"];
export type OutcomeKind = KindMetrics["kind"];
export type RecentFailure = Schemas["RecentFailureOut"];

/** The windows offered in the UI (the API also accepts 1h). */
export const WINDOWS: readonly { value: OpsWindow; label: string }[] = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
];

export const KINDS: readonly OutcomeKind[] = ["pcap", "static", "memory", "disk", "ti", "ai", "report"];

export const KIND_LABELS: Record<OutcomeKind, string> = {
  pcap: "PCAP analysis",
  static: "Static analysis",
  memory: "Memory analysis",
  disk: "Disk analysis",
  ti: "Threat-intel enrichment",
  ai: "AI analyst",
  report: "Report rendering",
};

export const PLATFORM_METRICS_NOTE = "Platform-wide metrics are served to operators at /internal/metrics.";

/** "12.5 %" (one decimal), "0 %", "—" when nothing finished. */
export function formatRatio(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return "—";
  const pct = Math.min(100, Math.max(0, ratio * 100));
  const rounded = Math.round(pct * 10) / 10;
  return `${Number.isInteger(rounded) ? rounded.toFixed(0) : rounded.toFixed(1)} %`;
}

/** "850 ms", "4.2 s", "3 min 05 s", "2 h 10 min"; "—" when unknown. */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const totalSeconds = Math.round(seconds);
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) return `${minutes} min ${String(totalSeconds % 60).padStart(2, "0")} s`;
  const hours = Math.floor(minutes / 60);
  return `${hours} h ${String(minutes % 60).padStart(2, "0")} min`;
}

export function formatCount(value: number): string {
  return value.toLocaleString("en-US");
}

/** "PCAP analysis · full", from the kind and its subkind (profile, provider or format). */
export function kindLabel(item: Pick<KindMetrics, "kind" | "subkind">): string {
  const base = Object.hasOwn(KIND_LABELS, item.kind) ? KIND_LABELS[item.kind] : item.kind;
  const sub = item.subkind ? item.subkind.replace(/[^\w.-]/g, "").slice(0, 40) : "";
  return sub ? `${base} · ${sub}` : base;
}

/** The rows in a fixed kind order, then by subkind. */
export function sortedItems(items: readonly KindMetrics[]): KindMetrics[] {
  return [...items].sort(
    (a, b) => KINDS.indexOf(a.kind) - KINDS.indexOf(b.kind) || (a.subkind ?? "").localeCompare(b.subkind ?? ""),
  );
}

/** "parse 2, infra 1": non-zero error classes, largest first. */
export function errorClassSummary(classes: Readonly<Record<string, number>>): string {
  const parts = Object.entries(classes)
    .filter(([name, count]) => /^[a-z]{1,16}$/.test(name) && Number.isFinite(count) && count > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([name, count]) => `${name} ${count}`);
  return parts.length ? parts.join(", ") : "—";
}

export type ErrorClass = RecentFailure["error_class"];

const ERROR_CLASSES: ReadonlySet<string> = new Set<ErrorClass>(["parse", "infra", "policy", "provider", "input", "other"]);

/** The API's error class as display text (classified server-side; anything unknown is "other"). */
export function errorClassText(value: string | null | undefined): ErrorClass {
  return value && ERROR_CLASSES.has(value) ? (value as ErrorClass) : "other";
}

/** An error code as display text (codes are `[a-z0-9_]`; anything else shows as "other"). */
export function errorCodeText(code: string | null | undefined): string {
  return code && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "other";
}

export const RECENT_FAILURES = 5;

/** "PCAP", "Static (full)", "AV scan", "Memory (triage)" (the analyses list wording). */
export function failureKindLabel(failure: Pick<RecentFailure, "kind" | "subkind">): string {
  return analysisKindLabel({ analyzer: failure.kind, profile: failure.subkind as AnalysisJob["profile"] });
}

/** The job page of a failure, under `/o/{org}` (built from the id, never from free text). */
export function failureHref(orgId: string, failure: Pick<RecentFailure, "kind" | "job_id">): string | null {
  if (!isUuid(orgId) || !isUuid(failure.job_id)) return null;
  return `/o/${orgId}/${ANALYZER_ROUTES[failure.kind]}/${failure.job_id}`;
}

/** Total active jobs, runs and renders (queued or running) across the known kinds. */
export function activeTotal(active: Readonly<Record<string, number>>): number {
  return KINDS.reduce((sum, kind) => sum + (Object.hasOwn(active, kind) && Number.isFinite(active[kind]) ? active[kind] : 0), 0);
}

// ---------------------------------------------------------------------------------------------
// API

export const opsKeys = {
  metrics: (orgId: string, window: OpsWindow) => ["org", orgId, "ops", "metrics", window] as const,
};

export async function fetchOpsMetrics(orgId: string, window: OpsWindow): Promise<OrgOpsMetrics> {
  return unwrap(
    await api.GET("/api/v1/orgs/{org_id}/ops/metrics", { params: { path: { org_id: orgId }, query: { window } } }),
  );
}

/** The five most recent failed analyses (the metrics answer's `recent_failures`, newest first). */
export function recentFailures(metrics: Pick<OrgOpsMetrics, "recent_failures">): RecentFailure[] {
  return (metrics.recent_failures ?? []).slice(0, RECENT_FAILURES);
}
