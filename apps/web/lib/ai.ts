/**
 * Pure helpers for the AI analyst views. Every string inside a run's output is model-derived
 * and therefore untrusted: it is rendered as React text only (never HTML or markdown) and never
 * becomes a link. The only links are built here from the API's deep-link descriptors of
 * verified citations, mapped onto an allowlist of internal routes and tabs.
 */
import type { Schemas } from "@cyberlab/contracts";

export type AiTask = Schemas["AiTask"];
export type AiRunStatus = Schemas["AiRunStatus"];
export type AiProviderName = Schemas["AiProviderName"];
export type AiRun = Schemas["AiRunOut"];
export type AiRunDetail = Schemas["AiRunDetail"];
export type AiChildRun = Schemas["AiChildRunOut"];
export type AiOutput = Schemas["AiOutputOut"];
export type AiClaim = Schemas["AiClaimOut"];
export type AiHypothesis = Schemas["AiHypothesisOut"];
export type AiCitation = Schemas["AiCitationOut"];
export type AiDeepLink = Schemas["AiDeepLink"];
export type AiTimelineEntry = Schemas["AiTimelineOut"];
export type AiAttack = Schemas["AiAttackOut"];
export type AiNextStep = Schemas["AiNextStepOut"];
export type AiContextPreview = Schemas["AiContextPreviewOut"];
export type AiRunContext = Schemas["AiRunContextOut"];
export type AiContextStats = Schemas["ContextStats"];
export type AiInclusions = Schemas["AiInclusions"];
export type AiProvider = Schemas["AiProviderOut"];
export type AiSettings = Schemas["AiSettingsOut"];
export type AiRunCreate = Schemas["AiRunCreate"];
export type ClaimStatus = Schemas["ClaimStatus"];
export type CitationStatus = Schemas["CitationStatus"];
export type CitationReason = Schemas["CitationReason"];
export type OutputFlag = Schemas["OutputFlag"];
export type RefKind = Schemas["RefKind"];
export type Confidence = AiClaim["confidence"];

/** The fixed notice shown on every AI view. */
export const AI_BANNER =
  "AI-generated interpretation of the cited evidence. Verify before acting. CyberLab never acts on AI output.";

// ---------------------------------------------------------------------------------------------
// Tasks

export const TASK_LABELS: Record<AiTask, string> = {
  explain_finding: "Explain finding",
  explain_alert: "Explain alert",
  summarize_pcap: "Summarize capture",
  explain_static: "Explain static findings",
  ioc_correlation: "IOC correlation",
  attack_mapping: "ATT&CK mapping",
  incident_summary: "Incident summary",
  job_digest: "Per-job digest",
  // M10: one function of a reverse-engineering job (refused until phase 9).
  explain_function: "Explain function",
};

export function taskLabel(task: string): string {
  return Object.hasOwn(TASK_LABELS, task) ? TASK_LABELS[task as AiTask] : task;
}

/** Task buttons of the AI Analyst tab per job page. */
export const JOB_TASKS: Record<"pcap" | "static" | "memory" | "disk" | "reverse", AiTask[]> = {
  pcap: ["summarize_pcap", "ioc_correlation", "attack_mapping"],
  static: ["explain_static", "ioc_correlation", "attack_mapping"],
  // M8: no memory-specific AI task (generic tasks only after an admin releases the evidence).
  memory: [],
  // M9: none either (disk evidence is restricted until released; generic tasks only).
  disk: [],
  // M10: `explain_function` is per function (the function view's button, phase 10), never a
  // job-level task button.
  reverse: [],
};

/** Tasks shown as filters on the runs list (job digests are internal children). */
export const LISTED_TASKS: AiTask[] = [
  "summarize_pcap",
  "explain_static",
  "explain_finding",
  "explain_alert",
  "ioc_correlation",
  "attack_mapping",
  "incident_summary",
];

// ---------------------------------------------------------------------------------------------
// Run states

export const AI_RUN_STATUSES: AiRunStatus[] = ["queued", "running", "waiting", "completed", "partial", "failed", "refused"];

export const AI_STATUS_LABELS: Record<AiRunStatus, string> = {
  queued: "Queued",
  running: "Running",
  waiting: "Waiting",
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
  refused: "Declined",
};

export function isActiveAiRun(status: AiRunStatus | undefined | null): boolean {
  return status === "queued" || status === "running" || status === "waiting";
}

export function hasOutput(status: AiRunStatus | undefined | null): boolean {
  return status === "completed" || status === "partial";
}

const POLL_MS = 2_000;
const POLL_MAX_MS = 15_000;
const WAIT_MAX_MS = 60_000;

/**
 * Poll interval for one run: 2 s while queued / running (slowly backing off after a minute of
 * polls), while waiting until just after `resume_at` (bounded); false once final.
 */
export function aiPollMs(
  run: { status: AiRunStatus; resume_at?: string | null } | undefined,
  updates: number,
  nowMs: number,
): number | false {
  if (!run || !isActiveAiRun(run.status)) return false;
  if (run.status === "waiting") {
    const resume = run.resume_at ? Date.parse(run.resume_at) : Number.NaN;
    if (Number.isFinite(resume)) return Math.min(WAIT_MAX_MS, Math.max(POLL_MS, resume - nowMs + 500));
    return Math.min(WAIT_MAX_MS, Math.round(POLL_MS * 1.5 ** Math.max(0, updates - 1)));
  }
  return updates <= 30 ? POLL_MS : Math.min(POLL_MAX_MS, Math.round(POLL_MS * 1.25 ** (updates - 30)));
}

/** Message per failure code (`ai_runs.error_code`); unknown codes are named verbatim. */
export const AI_ERROR_TEXT: Record<string, string> = {
  budget_exhausted: "Today's AI token budget of this organization is spent. No provider call was made.",
  spend_limit: "The provider account reached its spend limit. Check the billing of the provider key.",
  auth_failed: "The provider rejected the API key. An admin can replace or verify it under Integrations.",
  max_tokens: "The answer did not fit in the output limit and was discarded.",
  invalid_output: "The provider's answer did not match the required structure twice and was discarded.",
  deadline: "The run did not finish before its deadline.",
  canary_leak:
    "The answer echoed a hidden marker of the request, a sign of prompt injection in the evidence. The output is withheld.",
  provider_unavailable: "The provider is not available in this deployment.",
  provider_disabled: "The provider was disabled for this organization before the run started.",
  provider_error: "The provider returned an error. You can try again later.",
  overloaded: "The provider stayed overloaded; the run gave up after its retries.",
  context_too_large: "The evidence context was too large for the model.",
  ai_disabled: "AI was turned off for this organization before the run started.",
  no_digest: "No per-job digest finished, so no incident summary could be written.",
  not_implemented: "This analysis is not available yet.",
  refused: "The provider declined this request. No retry is made.",
  policy_blocked: "The case or evidence share policy changed to \"do not send to AI\" before the provider call. Nothing was sent.",
};

export function aiErrorText(code: string | null | undefined): string {
  if (!code) return "The run failed.";
  return Object.hasOwn(AI_ERROR_TEXT, code) ? AI_ERROR_TEXT[code] : `The run failed (${code}).`;
}

/** Messages for errors of `POST …/ai/runs` and `…/ai/context-preview` (by API error code). */
const REQUEST_ERROR_TEXT: Record<string, string> = {
  ai_disabled: "AI is off for this organization.",
  no_provider_enabled: "No AI provider is enabled (with its terms acknowledged and a key).",
  provider_unavailable: "This AI provider is not available in this deployment.",
  model_not_allowed: "This model is not on the provider's allowlist.",
  job_not_ready: "Only a succeeded analysis can be analyzed.",
  budget_exhausted: "Today's AI token budget of this organization is spent.",
  ai_busy: "Too many AI runs are active right now. Try again when some have finished.",
  target_not_found: "The finding or alert is not part of this analysis.",
  task_not_applicable: "This task does not apply to this analysis.",
  context_empty: "There is no evidence to analyze.",
  policy_blocked: "The case or evidence share policy does not allow sending this to AI. Nothing was sent.",
};

export function aiRequestErrorText(code: string | undefined, fallback: string): string {
  return code && Object.hasOwn(REQUEST_ERROR_TEXT, code) ? REQUEST_ERROR_TEXT[code] : fallback;
}

export type RunStateView = { tone: "active" | "neutral" | "error"; title: string; detail?: string };

/** What the run-state notice says for a run that has (or will have) no output to show. */
export function runStateView(
  run: Pick<AiRun, "status" | "error_code" | "refusal_category" | "resume_at">,
  formatTime: (iso: string) => string = (iso) => iso,
): RunStateView | null {
  switch (run.status) {
    case "queued":
      return { tone: "active", title: "Queued for the AI analyst…" };
    case "running":
      return { tone: "active", title: "The AI analyst is working…" };
    case "waiting":
      return {
        tone: "active",
        title: run.resume_at
          ? `Provider rate-limited, retrying at ${formatTime(run.resume_at)}`
          : "Provider rate-limited, retrying shortly",
      };
    case "refused":
      return {
        tone: "neutral",
        title: `The provider declined this request (category: ${run.refusal_category || "unspecified"}). No retry is made.`,
      };
    case "failed":
      return { tone: "error", title: "The run failed", detail: aiErrorText(run.error_code) };
    case "partial":
      return {
        tone: "neutral",
        title: "Partial result",
        detail: "Some per-job digests did not finish; the summary covers the jobs that did.",
      };
    default:
      return null;
  }
}

export const DEDUPLICATED_TEXT = "Showing the existing analysis of identical evidence.";

// ---------------------------------------------------------------------------------------------
// Claims, confidence and flags

export const CONFIDENCE_LABEL = "Confidence in this interpretation";

export function confidenceText(level: Confidence): string {
  return `${CONFIDENCE_LABEL}: ${level}`;
}

/** Why a citation was not verified / a claim is not supported (plain text, no judgement words). */
export const REASON_TEXT: Record<CitationReason, string> = {
  unknown_label: "unknown reference",
  digest_not_evidence: "a digest statement, not evidence",
  field_not_allowed: "field not citable for this record",
  out_of_scope: "outside this case",
  row_missing: "record not found",
  quote_mismatch: "quote not found in record",
  quote_too_short: "quote too short to check",
  quote_required: "no quote given",
  weak_anchor: "quote does not support this statement",
  no_verified_citation: "no verified evidence cited",
  invalid_attack: "technique not in the ATT&CK index",
  no_timestamp: "cited record has no time",
};

export function reasonText(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return Object.hasOwn(REASON_TEXT, reason) ? REASON_TEXT[reason as CitationReason] : reason.replaceAll("_", " ");
}

/** The support line of a claim: "backed by cited evidence", never "verified" or "true" (RT21). */
export function claimSupportText(claim: { status: ClaimStatus; reason?: CitationReason | null }): string {
  if (claim.status === "supported") return "backed by cited evidence";
  if (claim.status === "hypothesis") return "hypothesis";
  return `not supported: ${reasonText(claim.reason) ?? "no verified evidence cited"}`;
}

export function hiddenClaimsText(count: number): string {
  return count === 1
    ? "1 statement hidden: not supported by verified evidence"
    : `${count} statements hidden: not supported by verified evidence`;
}

/** Shown (supported / hypothesis) vs hidden (unsupported) items of one section, order kept. */
export function partitionClaims<T extends { status: ClaimStatus }>(items: readonly T[]): { shown: T[]; hidden: T[] } {
  const shown: T[] = [];
  const hidden: T[] = [];
  for (const item of items) (item.status === "unsupported" ? hidden : shown).push(item);
  return { shown, hidden };
}

/** Long sections show this many items before a "Show all" toggle. */
export const SECTION_COLLAPSE_AFTER = 10;

export function visibleSlice<T>(items: readonly T[], expanded: boolean, limit = SECTION_COLLAPSE_AFTER): T[] {
  return expanded ? [...items] : items.slice(0, limit);
}

export const FLAG_TEXT: Record<OutputFlag, string> = {
  verdict_language:
    "The model used conclusive wording about the evidence. CyberLab does not issue such conclusions; read it as an interpretation to check.",
  command_like:
    "Some next steps look like shell commands. They are shown as text only: CyberLab never runs commands.",
  external_url: "The output mentions web addresses. They stay defanged as text and are never opened or linked.",
  canary_leak: "The output echoed a hidden request marker (possible prompt injection) and is withheld.",
};

export function flagText(flag: string): string {
  return Object.hasOwn(FLAG_TEXT, flag) ? FLAG_TEXT[flag as OutputFlag] : `Output note: ${flag.replaceAll("_", " ")}.`;
}

/** Child flags that matter on an incident parent (RT23), deduplicated, in a stable order. */
export function childFlags(children: readonly Pick<AiChildRun, "flags">[]): OutputFlag[] {
  const seen = new Set<OutputFlag>(children.flatMap((child) => child.flags));
  return (["verdict_language", "external_url", "command_like", "canary_leak"] as OutputFlag[]).filter((f) => seen.has(f));
}

/** Every citation of an output (for stale counts and ATT&CK-free summaries). */
export function allCitations(output: AiOutput): AiCitation[] {
  return [
    ...output.observed.flatMap((c) => c.citations),
    ...output.interpretation.flatMap((c) => c.citations),
    ...output.hypotheses.flatMap((h) => [...h.supporting, ...h.contradicting]),
    ...output.next_steps.flatMap((s) => s.refs),
    ...output.attack_techniques.flatMap((t) => t.citations),
    ...output.timeline.flatMap((t) => t.citations),
  ];
}

export function staleCount(output: AiOutput): number {
  return allCitations(output).filter((c) => c.stale).length;
}

/** Model output truncated by the presentation caps (`verification.truncation`), as notes. */
export function outputTruncationNotes(truncation: Record<string, number> | null | undefined): string[] {
  return Object.entries(truncation ?? {})
    .filter(([, n]) => Number.isFinite(n) && n > 0)
    .map(([key, n]) => `${key.replaceAll("_", " ")}: ${n} item${n === 1 ? "" : "s"} over the display cap not shown`);
}

// ---------------------------------------------------------------------------------------------
// Citations and deep links

export const KIND_LABELS: Record<RefKind, string> = {
  job: "analysis",
  finding: "finding",
  alert: "alert",
  flow: "flow",
  record: "record",
  ioc: "IOC",
  ti_result: "threat intel",
  sample: "sample",
  signature: "signature",
  capability: "capability",
  pe_summary: "file structure",
  string: "string",
  timeline: "timeline entry",
  evidence: "evidence",
  investigation: "case",
  digest_claim: "digest statement",
  // M10 (G / Q items of explain_function).
  function: "function",
  code: "decompiled code",
};

export function kindLabel(kind: string | null | undefined): string {
  if (!kind) return "reference";
  return Object.hasOwn(KIND_LABELS, kind) ? KIND_LABELS[kind as RefKind] : kind.replaceAll("_", " ");
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string | null | undefined): value is string {
  return typeof value === "string" && UUID.test(value);
}

// Tabs each job route accepts in a link; anything else drops the link.
const PCAP_LINK_TABS = new Set(["overview", "findings", "alerts", "flows", "dns", "http", "tls", "iocs", "timeline"]);
const MALWARE_LINK_TABS = new Set(["overview", "findings", "signatures", "capabilities", "sections", "strings", "imports", "iocs"]);
// M8: the memory job page's shared tabs a citation may target.
const MEMORY_LINK_TABS = new Set(["overview", "findings", "iocs", "timeline"]);
// M9: the disk job page (`/forensics/{job}`) has the same shared tabs.
const FORENSICS_LINK_TABS = new Set(["overview", "findings", "iocs", "timeline"]);
// M10: the RE job page (`/reverse-engineering/{job}`); phase 9 / 10 add the function links.
const RE_LINK_TABS = new Set(["overview", "findings", "iocs", "functions", "imports", "strings"]);
const LINK_TABS: Record<JobRoute, ReadonlySet<string>> = {
  pcap: PCAP_LINK_TABS,
  malware: MALWARE_LINK_TABS,
  memory: MEMORY_LINK_TABS,
  forensics: FORENSICS_LINK_TABS,
  "reverse-engineering": RE_LINK_TABS,
};
const MAX_REF = 128;

const enc = encodeURIComponent;

/**
 * Internal href of a deep-link descriptor, or null. Only known routes and tabs; job, evidence
 * and investigation ids must be UUIDs; every path and query part is URL-encoded (a flow ref is
 * an analyzer-written Zeek uid, RT16). Never produces an absolute or external URL.
 */
export function deepLinkHref(orgId: string, link: AiDeepLink | null | undefined): string | null {
  if (!link || !isUuid(orgId)) return null;
  const base = `/o/${enc(orgId)}`;
  switch (link.route) {
    case "evidence":
      return isUuid(link.ref) ? `${base}/evidence/${enc(link.ref)}` : null;
    case "investigation":
      return isUuid(link.ref) ? `${base}/investigations/${enc(link.ref)}` : null;
    case "pcap":
    case "malware":
    case "memory":
    case "forensics":
    case "reverse-engineering": {
      if (!isUuid(link.job_id)) return null;
      const tabs = LINK_TABS[link.route];
      const tab = link.tab ?? "overview";
      if (!tabs.has(tab)) return null;
      const params = new URLSearchParams();
      if (tab !== "overview") params.set("tab", tab);
      if (link.ref) {
        if (link.ref.length > MAX_REF) return null;
        params.set("ref", link.ref);
      }
      const query = params.toString();
      return `${base}/${link.route}/${enc(link.job_id)}${query ? `?${query}` : ""}`;
    }
    default:
      return null;
  }
}

export type CitationChipView = {
  text: string;
  kind: string;
  title: string;
  /** Internal href: verified citations with a known descriptor only. */
  href: string | null;
  status: CitationStatus;
};

/** Label, kind, tooltip and (for verified citations only) the internal link of one chip. */
export function citationChip(orgId: string, c: AiCitation): CitationChipView {
  const kind = kindLabel(c.kind);
  const text = `${c.label} · ${kind}`;
  if (c.status === "verified") {
    const parts = [`Cited ${kind} ${c.label}`];
    if (c.field) parts.push(`field: ${c.field}`);
    if (c.quote) parts.push(`quote: “${c.quote}”`);
    if (c.stale) parts.push("the record changed after this analysis (stale)");
    return { text, kind, title: parts.join("\n"), href: deepLinkHref(orgId, c.link), status: c.status };
  }
  const reason = reasonText(c.reason) ?? (c.status === "invalid" ? "unknown reference" : "quote not found in record");
  return {
    text,
    kind,
    title: `${c.status === "invalid" ? "Invalid" : "Unverified"} citation: ${reason}`,
    href: null,
    status: c.status,
  };
}

// ---------------------------------------------------------------------------------------------
// Model text

// Bidi overrides / isolates and zero-width marks: shown as visible markers, never applied.
const BIDI = /[‎‏‪-‮⁦-⁩]/g;

/** Model text for display: bidi controls made visible; everything else stays literal. */
export function displayText(value: string | null | undefined): string {
  if (!value) return "";
  return value.replace(BIDI, (ch) => `[U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}]`);
}

// ---------------------------------------------------------------------------------------------
// Context stats ("what will be sent")

export type KindCountRow = { kind: string; label: string; included: number; total: number };

export function kindCountRows(stats: AiContextStats | null | undefined): KindCountRow[] {
  return Object.entries(stats?.per_kind ?? {})
    .map(([kind, row]) => ({ kind, label: kindLabel(kind), included: row.included, total: row.total }))
    .sort((a, b) => b.total - a.total || a.label.localeCompare(b.label));
}

/** Truncation and omission notes of a context, or [] when everything was sent. */
export function contextTruncationNotes(stats: AiContextStats | null | undefined): string[] {
  if (!stats) return [];
  const notes: string[] = [];
  const omitted = kindCountRows(stats).filter((row) => row.included < row.total);
  if (stats.truncated || omitted.length > 0 || stats.omitted > 0) {
    notes.push(
      `The context was capped: ${
        omitted.length
          ? omitted.map((row) => `${row.included} of ${row.total} ${row.label} items`).join(", ")
          : `${stats.omitted} items left out`
      } were sent, in priority order.`,
    );
  }
  const fields = Object.entries(stats.truncated_fields ?? {}).filter(([, n]) => n > 0);
  if (fields.length > 0) {
    notes.push(`Long values were cut at 256 characters: ${fields.map(([key, n]) => `${key} (${n})`).join(", ")}.`);
  }
  if (stats.jobs_omitted > 0) {
    notes.push(`${stats.jobs_omitted} analysis job${stats.jobs_omitted === 1 ? " was" : "s were"} left out of the incident (job cap).`);
  }
  if (stats.dropped_keys > 0) notes.push(`${stats.dropped_keys} attribute keys with unexpected names were dropped.`);
  return notes;
}

const PSEUDONYM_LABELS: Record<string, string> = {
  ip: "internal IPs",
  host: "internal hostnames",
  user: "usernames",
};

/** "3 internal IPs, 1 internal hostnames" or null when nothing was pseudonymized. */
export function pseudonymizationText(stats: AiContextStats | null | undefined): string | null {
  const parts = Object.entries(stats?.pseudonymized ?? {})
    .filter(([, n]) => n > 0)
    .map(([key, n]) => `${n} ${Object.hasOwn(PSEUDONYM_LABELS, key) ? PSEUDONYM_LABELS[key] : key.replaceAll("_", " ")}`);
  return parts.length ? `Replaced by pseudonyms before sending: ${parts.join(", ")}.` : null;
}

const CATEGORY_LABELS: Record<string, string> = {
  job_summary: "analysis summary",
  finding_text: "finding text",
  alert_text: "alert text",
  network_flows: "network flows (IPs, ports)",
  network_records: "DNS / HTTP / TLS records",
  indicators: "indicators (IPs, domains, defanged URLs, hashes)",
  threat_intel_results: "threat intel summaries",
  file_facts: "file facts",
  signature_matches: "signature matches",
  capabilities: "capabilities",
  strings: "extracted strings",
  timeline: "timeline entries",
  evidence_metadata: "evidence metadata",
  case_text: "case title and description",
  digest_claims: "statements from per-job digests",
};

export function categoryLabel(category: string): string {
  return Object.hasOwn(CATEGORY_LABELS, category) ? CATEGORY_LABELS[category] : category.replaceAll("_", " ");
}

export const INCLUSION_LABELS: [keyof AiInclusions, string][] = [
  ["pseudonymize_internal", "Pseudonymize internal names"],
  ["include_ti", "Include threat intel results"],
  ["include_strings", "Include extracted strings"],
  ["include_case_text", "Include case title and description"],
];

/** The exact context as indented JSON text (rendered inside <pre>, never parsed as markup). */
export function contextJson(items: unknown): string {
  try {
    return JSON.stringify(items, null, 2);
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------------------------
// Footer formatting

const COUNT = new Intl.NumberFormat("en-US");

export function formatTokens(value: number | null | undefined): string {
  return value === null || value === undefined || !Number.isFinite(value) ? "—" : COUNT.format(value);
}

/** "≈ $0.0123" (always approximate: catalog prices), or "—". */
export function formatCost(micros: number | null | undefined): string {
  if (micros === null || micros === undefined || !Number.isFinite(micros)) return "—";
  const usd = micros / 1_000_000;
  return `≈ $${usd < 0.1 ? usd.toFixed(4) : usd.toFixed(2)}`;
}

export function formatAccuracy(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return "—";
  return `${Math.round(Math.min(1, Math.max(0, ratio)) * 100)}%`;
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 12) : "—";
}

/** Run time from start to finish (or to now while active), "—" before it starts. */
export function runDurationText(
  run: Pick<AiRun, "started_at" | "finished_at" | "created_at">,
  nowMs: number,
): string {
  const start = Date.parse(run.started_at ?? run.created_at);
  const end = run.finished_at ? Date.parse(run.finished_at) : nowMs;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "—";
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${seconds % 60} s`;
}

// ---------------------------------------------------------------------------------------------
// Targets (runs list)

export type JobRoute = "pcap" | "malware" | "memory" | "forensics" | "reverse-engineering";

/** Route of a job-scoped run when the task alone determines it, else null (look the job up). */
export function routeForTask(task: AiTask): JobRoute | null {
  if (task === "summarize_pcap" || task === "explain_alert") return "pcap";
  if (task === "explain_static") return "malware";
  if (task === "explain_function") return "reverse-engineering";
  return null;
}

/** Internal link to a run's target (job tab / cited row / investigation), or null. */
export function runTargetHref(
  orgId: string,
  run: Pick<AiRun, "scope" | "job_id" | "investigation_id" | "target_kind" | "target_id">,
  route: JobRoute | null,
): string | null {
  if (run.scope === "investigation") {
    return deepLinkHref(orgId, { route: "investigation", job_id: null, tab: null, ref: run.investigation_id });
  }
  if (!route) return null;
  const tab =
    run.target_kind === "alert"
      ? "alerts"
      : run.target_kind === "finding"
        ? "findings"
        : run.target_kind === "function"
          ? "functions"
          : "ai";
  if (tab === "ai") {
    return isUuid(orgId) && isUuid(run.job_id) ? `/o/${enc(orgId)}/${route}/${enc(run.job_id)}?tab=ai` : null;
  }
  return deepLinkHref(orgId, { route, job_id: run.job_id, tab, ref: run.target_id });
}

export function runTargetText(run: Pick<AiRun, "scope" | "target_kind" | "task">): string {
  if (run.scope === "investigation") return "Investigation";
  if (run.target_kind === "finding") return "Finding";
  if (run.target_kind === "alert") return "Alert";
  if (run.target_kind === "function") return "Function";
  return "Analysis";
}

/** The newest run per task (runs come newest first from the API). */
export function latestByTask<T extends { task: AiTask }>(runs: readonly T[]): Map<AiTask, T> {
  const out = new Map<AiTask, T>();
  for (const run of runs) if (!out.has(run.task)) out.set(run.task, run);
  return out;
}

/** Ids of runs that a newer run of the same task and target supersedes. */
export function supersededIds(runs: readonly Pick<AiRun, "id" | "supersedes_run_id">[]): Set<string> {
  return new Set(runs.flatMap((run) => (run.supersedes_run_id ? [run.supersedes_run_id] : [])));
}

/** "n of m digests finished" progress of an incident's children. */
export function digestProgress(children: readonly Pick<AiChildRun, "status">[]): { done: number; total: number } {
  return { done: children.filter((child) => !isActiveAiRun(child.status)).length, total: children.length };
}

/** Child runs that ended without a usable digest. */
export function failedChildren<T extends Pick<AiChildRun, "status">>(children: readonly T[]): T[] {
  return children.filter((child) => child.status === "failed" || child.status === "refused");
}
