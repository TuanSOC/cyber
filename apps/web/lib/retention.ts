/**
 * Retention policy, preview and runs (M7). The UI only helps the admin: the API enforces the
 * floors, the delay before any loosening takes effect (RT1), the typed acknowledgement and every
 * permission. Run samples and items carry table names and ids only (labels, never content) and
 * are always rendered as text.
 */
import type { Schemas } from "@cyberlab/contracts";

import { isUuid } from "@/lib/ai";
import { api, unwrap } from "@/lib/api";

export type RetentionPolicy = Schemas["RetentionPolicyOut"];
export type RetentionPolicyIn = Schemas["RetentionPolicyIn"];
export type RetentionValues = Schemas["RetentionValues"];
export type RetentionPreview = Schemas["RetentionPreviewOut"];
export type RetentionPreviewIn = Schemas["RetentionPreviewIn"];
export type RetentionCategoryCount = Schemas["RetentionCategoryCount"];
export type RetentionCandidate = Schemas["RetentionCandidateOut"];
export type RetentionRun = Schemas["RetentionRunOut"];
export type RetentionRunPage = Schemas["RetentionRunPage"];
export type RetentionRunDetail = Schemas["RetentionRunDetail"];
export type RetentionRunItem = Schemas["RetentionRunItemOut"];
export type RetentionCategory = RetentionCandidate["category"];
export type RetentionOutcome = RetentionRunItem["outcome"];
export type RetentionMode = RetentionRun["mode"];
export type RetentionRunStatus = RetentionRun["status"];

export type RetentionField = keyof RetentionValues;
export type RetentionDraft = Record<RetentionField, number | null>;

/** The schema's upper bound (100 years); the lower bound is the floor the API returns. */
export const MAX_DAYS = 36_500;
export const DAY_MS = 86_400_000;

export const RETENTION_FIELDS: readonly RetentionField[] = ["ti_results_days", "ai_runs_days", "closed_case_days"];

export const RETENTION_FIELD_TEXT: Record<RetentionField, { label: string; help: string }> = {
  ti_results_days: {
    label: "Threat-intel history",
    help: "Threat-intel results older than this, with their run items, once no newer run reuses them.",
  },
  ai_runs_days: {
    label: "AI runs",
    help: "Completed AI runs older than this (inputs, references, outputs, citations), as whole run trees.",
  },
  closed_case_days: {
    label: "Closed cases",
    help: "Evidence bytes, bulk analysis rows and report renditions of cases closed or archived this long ago.",
  },
};

const PENDING: Record<RetentionField, "pending_ti_results_days" | "pending_ai_runs_days" | "pending_closed_case_days"> = {
  ti_results_days: "pending_ti_results_days",
  ai_runs_days: "pending_ai_runs_days",
  closed_case_days: "pending_closed_case_days",
};

export const CATEGORY_FIELD: Record<RetentionCategory, RetentionField> = {
  ti_results: "ti_results_days",
  ai_runs: "ai_runs_days",
  closed_case: "closed_case_days",
};

export const CATEGORIES: readonly RetentionCategory[] = ["ti_results", "ai_runs", "closed_case"];

export const CATEGORY_LABELS: Record<RetentionCategory, string> = {
  ti_results: "Threat-intel history",
  ai_runs: "AI runs",
  closed_case: "Closed cases",
};

export const OUTCOMES: readonly RetentionOutcome[] = [
  "purged",
  "skipped_hold",
  "skipped_locked",
  "object_delete_failed",
  "kept_cited",
];

export const OUTCOME_LABELS: Record<RetentionOutcome, string> = {
  purged: "Purged",
  skipped_hold: "Skipped: legal hold",
  skipped_locked: "Skipped: object lock",
  object_delete_failed: "Object delete failed",
  kept_cited: "Kept: cited by a report",
};

export const MODE_LABELS: Record<RetentionMode, string> = { dry_run: "Dry run", enforce: "Enforce" };
export const TRIGGER_LABELS: Record<RetentionRun["trigger"], string> = { schedule: "Scheduled", manual: "Manual" };
export const RUN_STATUS_LABELS: Record<RetentionRunStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
};

/**
 * What enforcement deletes and what it never deletes (the plan's lists, M7 "Retention, purge
 * and legal hold"). Shown in the enforce dialog; the copy is reviewed in phase 11.
 */
export const PURGED_BY_POLICY: readonly string[] = [
  "Threat-intel history (by age): a result goes only together with its run items, and only when every item that references it (later runs reuse results as cached) belongs to a run finished before the cutoff.",
  "AI runs (by age): completed AI runs (with inputs, refs, outputs, citations), as whole run trees: a run goes only when every run linked to it (parent or superseded run) is eligible and uncited.",
  "Closed cases: for cases closed or archived at least N days ago (a case closed before status history existed is never selected, and a case with a queued or running job is skipped): evidence bytes, the bulk derived rows (network flows, network records, analysis timeline, malware strings, sections, imports, exports and resources), their results objects and report renditions (re-renderable from the signed snapshot).",
];

export const NEVER_PURGED: readonly string[] = [
  "case, evidence and job metadata;",
  "hashes, custody, audit logs;",
  "notes and their versions, IOC collections, status events;",
  "findings, alerts, IOCs, malware samples, signatures and capabilities (small and citable, so citations and collections keep resolving);",
  "correlation keys and their index state: they derive only from kept rows, so a closed case keeps correlating;",
  "signed report snapshots, versions and citations.",
];

export const KEPT_CITED_NOTE =
  "AI runs, threat-intel rows and bulk rows cited by a report version are kept (kept: cited by a report).";

// ---------------------------------------------------------------------------------------------
// Policy values

/** "Keep forever" for null, else "N days". */
export function formatDays(days: number | null): string {
  if (days === null) return "Keep forever";
  return days === 1 ? "1 day" : `${days.toLocaleString("en-US")} days`;
}

/** The pending (lowered) value of a field, or null when nothing is pending for it. */
export function pendingValue(policy: RetentionPolicy, field: RetentionField): number | null {
  return policy.effective_at ? policy[PENDING[field]] : null;
}

/**
 * The values the admin last asked for: a pending lowered value, else the effective one. A PUT
 * sends these when only `enforce` changes, so pending values are kept, not cancelled.
 */
export function targetValues(policy: RetentionPolicy): RetentionDraft {
  const out = {} as RetentionDraft;
  for (const field of RETENTION_FIELDS) out[field] = pendingValue(policy, field) ?? policy[field];
  return out;
}

/** True when `next` loosens `current` (shorter, or a limit where there was none): it waits for the delay. */
export function isLowering(current: number | null, next: number | null): boolean {
  return next !== null && (current === null || next < current);
}

/** The fields whose new value is lower than the effective one (they take effect after the delay). */
export function loweredFields(policy: RetentionValues, draft: RetentionDraft): RetentionField[] {
  return RETENTION_FIELDS.filter((field) => isLowering(policy[field], draft[field]));
}

/** The confirmation shown before saving lowered values: it names the delay and the date (RT1). */
export function loweringNotice(fields: readonly RetentionField[], delayDays: number, now: number): string {
  const names = fields.map((field) => RETENTION_FIELD_TEXT[field].label).join(", ");
  return `Lowering ${names} takes effect after the ${delayDays}-day delay, on ${formatDay(addDays(now, delayDays))}. Until then the current values apply; raising a value applies at once.`;
}

/** Null when the value is acceptable, else a short reason (the API re-checks: 422 policy_floor). */
export function checkDays(value: number | null, floor: number | null): string | null {
  if (value === null) return null;
  if (!Number.isInteger(value)) return "Whole days only.";
  const min = Math.max(1, floor ?? 1);
  if (value < min) return `At least ${min} days (the platform minimum).`;
  if (value > MAX_DAYS) return `At most ${MAX_DAYS.toLocaleString("en-US")} days.`;
  return null;
}

/** A days input: "" is null (only with keep forever), digits only, else NaN (invalid). */
export function parseDays(raw: string): number | null {
  const value = raw.trim();
  if (!value) return null;
  return /^\d{1,6}$/.test(value) ? Number(value) : Number.NaN;
}

export function draftEquals(a: RetentionDraft, b: RetentionDraft): boolean {
  return RETENTION_FIELDS.every((field) => a[field] === b[field]);
}

/** `iso + days`, as a Date (the end of the delay, RT1). */
export function addDays(iso: string | number | Date, days: number): Date {
  return new Date(new Date(iso).getTime() + days * DAY_MS);
}

const DAY = new Intl.DateTimeFormat("en-US", { dateStyle: "medium" });
const DAY_TIME = new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" });

/** "Nov 13, 2026" (local day), for "takes effect on …". */
export function formatDay(value: string | number | Date): string {
  return DAY.format(new Date(value));
}

export function formatDayTime(value: string | number | Date): string {
  return DAY_TIME.format(new Date(value));
}

// ---------------------------------------------------------------------------------------------
// Enforcement

export type EnforceState = "off" | "pending" | "on";

export function enforceState(policy: Pick<RetentionPolicy, "enforce" | "pending_enforce">): EnforceState {
  if (policy.enforce) return "on";
  return policy.pending_enforce ? "pending" : "off";
}

/** Unicode NFC and trimmed: what the admin typed is compared to the org name in this form. */
export function normalizeName(value: string): string {
  return value.normalize("NFC").trim();
}

/** The typed acknowledgement: the org name, after NFC normalization and trimming. */
export function acknowledgementMatches(typed: string, orgName: string): boolean {
  const expected = normalizeName(orgName);
  return expected.length > 0 && normalizeName(typed) === expected;
}

/** When enforcement starts if it is turned on now (the API answers the exact time). */
export function enforcementStart(policy: Pick<RetentionPolicy, "delay_days" | "enforce_effective_at">, now: number): Date {
  return policy.enforce_effective_at ? new Date(policy.enforce_effective_at) : addDays(now, policy.delay_days);
}

/** The PUT body. `acknowledge_destruction` is sent only when turning enforcement on. */
export function policyBody(values: RetentionDraft, enforce: boolean, acknowledge = false): RetentionPolicyIn {
  const body: RetentionPolicyIn = { ...values, enforce };
  if (enforce && acknowledge) body.acknowledge_destruction = true;
  return body;
}

/** Whether the switch should be on: enforcement effective or pending. */
export function enforceRequested(policy: Pick<RetentionPolicy, "enforce" | "pending_enforce">): boolean {
  return enforceState(policy) !== "off";
}

// ---------------------------------------------------------------------------------------------
// Preview and runs

/** The preview body: `{}` previews the effective policy; with pending values, the target ones. */
export function previewBody(policy: RetentionPolicy, includePending: boolean): RetentionPreviewIn {
  return includePending ? targetValues(policy) : {};
}

export function hasPending(policy: RetentionPolicy): boolean {
  return RETENTION_FIELDS.some((field) => pendingValue(policy, field) !== null);
}

/** The known categories of a counts map, in a fixed order (other keys are ignored). */
export function categoryRows(
  counts: Readonly<Record<string, RetentionCategoryCount>>,
): { category: RetentionCategory; count: RetentionCategoryCount }[] {
  return CATEGORIES.filter((category) => Object.hasOwn(counts, category)).map((category) => ({
    category,
    count: counts[category],
  }));
}

export function countTotals(counts: Readonly<Record<string, RetentionCategoryCount>>): RetentionCategoryCount {
  const total: RetentionCategoryCount = { candidates: 0, rows: 0, bytes: 0, skipped_hold: 0, skipped_locked: 0, kept_cited: 0 };
  for (const { count } of categoryRows(counts)) {
    for (const key of Object.keys(total) as (keyof RetentionCategoryCount)[]) total[key] += count[key];
  }
  return total;
}

export type OutcomeFilter = RetentionOutcome | "all";

/** Items per page of the run detail (the API pages and filters them: `limit`, `offset`, `outcome`). */
export const RUN_ITEMS_PAGE = 50;

export type RunItemsQuery = { outcome: OutcomeFilter; offset: number };

export const FIRST_ITEMS_PAGE: RunItemsQuery = { outcome: "all", offset: 0 };

/** The query of one page of a run's items (no `outcome` means every outcome). */
export function runItemsParams(query: RunItemsQuery): { limit: number; offset: number; outcome?: RetentionOutcome } {
  const offset = Number.isFinite(query.offset) && query.offset > 0 ? Math.trunc(query.offset) : 0;
  const params: { limit: number; offset: number; outcome?: RetentionOutcome } = { limit: RUN_ITEMS_PAGE, offset };
  if (query.outcome !== "all") params.outcome = query.outcome;
  return params;
}

/** "Purged (12)": an outcome option with the run's count of it (0 when the API sent none). */
export function outcomeOptionText(outcome: OutcomeFilter, counts: Readonly<Partial<Record<string, number>>>, total: number): string {
  if (outcome === "all") return `All (${total.toLocaleString("en-US")})`;
  const n = Object.hasOwn(counts, outcome) ? (counts[outcome] ?? 0) : 0;
  return `${OUTCOME_LABELS[outcome]} (${n.toLocaleString("en-US")})`;
}

/** The run's items with one outcome, filtered locally (older servers sent only the first items). */
export function filterItems(items: readonly RetentionRunItem[], outcome: OutcomeFilter): RetentionRunItem[] {
  return outcome === "all" ? [...items] : items.filter((item) => item.outcome === outcome);
}

export function isActiveRun(run: Pick<RetentionRun, "status">): boolean {
  return run.status === "queued" || run.status === "running";
}

/** C0 / C1 controls, zero-width and bidi override characters (they can disguise a label). */
function isInvisible(code: number): boolean {
  return (
    code <= 0x1f ||
    (code >= 0x7f && code <= 0x9f) ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

/** A label from the server (table name, id) as display text: control characters removed, capped. */
export function labelText(value: string | null | undefined, max = 80): string {
  if (!value) return "—";
  const clean = [...value].filter((char) => !isInvisible(char.codePointAt(0) ?? 0)).join("");
  return clean.length > max ? `${clean.slice(0, max)}…` : clean || "—";
}

// ---------------------------------------------------------------------------------------------
// API

export const retentionKeys = {
  policy: (orgId: string) => ["org", orgId, "retention", "policy"] as const,
  preview: (orgId: string) => ["org", orgId, "retention", "preview"] as const,
  runs: (orgId: string) => ["org", orgId, "retention", "runs"] as const,
  run: (orgId: string, runId: string) => ["org", orgId, "retention", "runs", runId] as const,
  runPage: (orgId: string, runId: string, query: RunItemsQuery) =>
    ["org", orgId, "retention", "runs", runId, query.outcome, query.offset] as const,
};

export async function fetchPolicy(orgId: string): Promise<RetentionPolicy> {
  return unwrap(await api.GET("/api/v1/orgs/{org_id}/retention/policy", { params: { path: { org_id: orgId } } }));
}

export async function putPolicy(orgId: string, body: RetentionPolicyIn): Promise<RetentionPolicy> {
  return unwrap(await api.PUT("/api/v1/orgs/{org_id}/retention/policy", { params: { path: { org_id: orgId } }, body }));
}

export async function fetchPreview(orgId: string, body: RetentionPreviewIn): Promise<RetentionPreview> {
  return unwrap(await api.POST("/api/v1/orgs/{org_id}/retention/preview", { params: { path: { org_id: orgId } }, body }));
}

export async function fetchRuns(orgId: string, limit: number, offset: number): Promise<RetentionRunPage> {
  return unwrap(
    await api.GET("/api/v1/orgs/{org_id}/retention/runs", {
      params: { path: { org_id: orgId }, query: { limit, offset } },
    }),
  );
}

/** A run with one page of its items (server-side paging and outcome filter). */
export async function fetchRun(orgId: string, runId: string, query: RunItemsQuery = FIRST_ITEMS_PAGE): Promise<RetentionRunDetail> {
  return unwrap(
    await api.GET("/api/v1/orgs/{org_id}/retention/runs/{retention_run_id}", {
      params: { path: { org_id: orgId, retention_run_id: runId }, query: runItemsParams(query) },
    }),
  );
}

/** The retention run page (`audit.read`), e.g. the run that purged an evidence's bytes. */
export function runHref(orgId: string, runId: string): string | null {
  return isUuid(orgId) && isUuid(runId) ? `/o/${orgId}/settings/retention/runs/${runId}` : null;
}

/** A manual run from the UI is always a dry run (the mode otherwise comes from the DB, RT1). */
export async function startDryRun(orgId: string): Promise<RetentionRun> {
  return unwrap(
    await api.POST("/api/v1/orgs/{org_id}/retention/runs", {
      params: { path: { org_id: orgId } },
      body: { dry_run: true },
    }),
  );
}
