/**
 * Reports (M6 phase 7): types from the frozen contracts, API wrappers with typed errors, the
 * draft helpers and the autosave state machine. The API enforces every rule (revision, TLP,
 * distribution, selections, budget); the UI explains them.
 */
import type { Schemas } from "@cyberlab/contracts";

import { type AiRun, isUuid } from "@/lib/ai";
import { ApiError, api, unwrap } from "@/lib/api";
import { type Tlp, needsDistribution } from "@/lib/tlp";

export type Report = Schemas["ReportOut"];
export type ReportDetail = Schemas["ReportDetail"];
export type ReportPage = Schemas["ReportPage"];
export type ReportDraft = Schemas["ReportDraft"];
export type DraftInclude = Schemas["DraftInclude"];
export type DraftSections = Schemas["DraftSections"];
export type ReportProfile = Schemas["ReportProfile"];
export type ReportUpdate = Schemas["ReportUpdate"];
export type ReportCreate = Schemas["ReportCreate"];
export type ReportFinalize = Schemas["ReportFinalize"];
export type ReportPreview = Schemas["ReportPreviewOut"];
export type ReportVersion = Schemas["ReportVersionSummary"];
export type ReportVersionDetail = Schemas["ReportVersionDetail"];
export type ReportSnapshot = Schemas["ReportSnapshot"];
export type SectionCount = Schemas["SectionCount"];
export type RenderOut = Schemas["RenderOut"];
export type RenderFormat = RenderOut["format"];
export type RenderStatus = RenderOut["status"];
export type CitedRowRef = Schemas["CitedRowRef"];
export type CitedKind = CitedRowRef["kind"];
export type Severity = Schemas["SeveritySelection"]["min_severity"];
export type TimelineKind = NonNullable<Schemas["TimelineSelection"]["kinds"]>[number];
export type AttackStatus = Schemas["AttackSelection"]["statuses"][number];

// Limits mirrored from `reports/schemas.py` (the API answers 422 above them).
export const TITLE_MAX_CHARS = 200;
export const SECTION_MAX_CHARS = 20_000;
export const DISTRIBUTION_MAX_CHARS = 500;
export const CHANGE_NOTE_MAX_CHARS = 500;
export const MAX_AI_RUNS = 10;
export const MAX_CITED_ROWS = 200;
export const MAX_SELECTED_IDS = 200;
export const FINDINGS_MAX = 500;
export const ALERTS_MAX = 500;
export const IOCS_MAX = 2000;
export const TIMELINE_MAX = 1000;

export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];
export const TIMELINE_KINDS: readonly TimelineKind[] = ["custody", "job", "timeline", "alert", "finding", "note", "status"];
export const TIMELINE_KIND_LABELS: Record<TimelineKind, string> = {
  custody: "Custody",
  job: "Analyses",
  timeline: "Capture events",
  alert: "Alerts",
  finding: "Findings",
  note: "Notes",
  status: "Status changes",
};
export const RENDER_FORMATS: readonly RenderFormat[] = ["pdf", "html", "md"];
export const FORMAT_LABELS: Record<RenderFormat, string> = { pdf: "PDF (PDF/A-3a)", html: "HTML", md: "Markdown" };

// ---------------------------------------------------------------------------------------------
// Analyst sections

export const ANALYST_SECTIONS: readonly { key: keyof DraftSections; label: string; hint: string }[] = [
  { key: "executive_summary", label: "Executive summary", hint: "What happened, the impact and what was done, for readers who stop here." },
  { key: "scope", label: "Scope", hint: "Systems, evidence and time range covered." },
  { key: "methodology", label: "Methodology", hint: "How the evidence was acquired and analysed." },
  { key: "impact", label: "Impact", hint: "Affected systems, data and operations." },
  { key: "root_cause", label: "Root cause", hint: "How the incident started, as far as the evidence shows." },
  { key: "actions_taken", label: "Actions taken", hint: "Containment, eradication and recovery steps." },
  { key: "recommendations", label: "Recommendations", hint: "What to change next." },
  { key: "lessons_learned", label: "Lessons learned", hint: "What to keep and what to improve." },
];

export function emptySections(): DraftSections {
  return {
    executive_summary: "",
    scope: "",
    methodology: "",
    impact: "",
    root_cause: "",
    actions_taken: "",
    recommendations: "",
    lessons_learned: "",
  };
}

/** The API defaults of `DraftInclude` (`reports/schemas.py`). */
export function defaultInclude(): DraftInclude {
  return {
    evidence: true,
    custody: true,
    jobs: "latest",
    findings: { min_severity: "low", max: FINDINGS_MAX },
    alerts: { min_severity: "low", max: ALERTS_MAX },
    iocs: { case_iocs: true, collections: [], max: IOCS_MAX },
    ti: true,
    attack: { statuses: ["confirmed"] },
    timeline: { kinds: null, from: null, to: null, max: TIMELINE_MAX },
    notes: [],
    ai_runs: [],
    cited_rows: [],
  };
}

export function defaultDraft(): ReportDraft {
  return { sections: emptySections(), include: defaultInclude() };
}

/** "123 / 20,000" with the state of a length-limited field. */
export function charCounter(value: string, max: number): { text: string; over: boolean; near: boolean } {
  const length = [...value].length;
  return {
    text: `${length.toLocaleString("en-US")} / ${max.toLocaleString("en-US")}`,
    over: length > max,
    near: length > max * 0.9,
  };
}

/** Distribution is required on the cover of TLP:RED, TLP:AMBER+STRICT and external reports. */
export function distributionRequired(tlp: Tlp, profile: ReportProfile): boolean {
  return needsDistribution(tlp) || profile === "external";
}

export type DraftFields = {
  title: string;
  tlp: Tlp;
  profile: ReportProfile;
  distribution: string;
  draft: ReportDraft;
};

/** Problems that block finalize (the API checks them again). */
export function draftProblems(fields: DraftFields): string[] {
  const problems: string[] = [];
  if (!fields.title.trim()) problems.push("The report needs a title.");
  if ([...fields.title].length > TITLE_MAX_CHARS) problems.push(`The title is over ${TITLE_MAX_CHARS} characters.`);
  if (distributionRequired(fields.tlp, fields.profile) && !fields.distribution.trim()) {
    problems.push(
      fields.profile === "external"
        ? "External reports need a distribution statement (who may receive it)."
        : "TLP:RED and TLP:AMBER+STRICT reports need a distribution statement (who may receive it).",
    );
  }
  if ([...fields.distribution].length > DISTRIBUTION_MAX_CHARS) {
    problems.push(`The distribution statement is over ${DISTRIBUTION_MAX_CHARS} characters.`);
  }
  for (const section of ANALYST_SECTIONS) {
    if ([...fields.draft.sections[section.key]].length > SECTION_MAX_CHARS) {
      problems.push(`${section.label} is over ${SECTION_MAX_CHARS.toLocaleString("en-US")} characters.`);
    }
  }
  if (fields.draft.include.ai_runs.length > MAX_AI_RUNS) problems.push(`Select at most ${MAX_AI_RUNS} AI runs.`);
  if (fields.draft.include.cited_rows.length > MAX_CITED_ROWS) problems.push(`Cite at most ${MAX_CITED_ROWS} rows.`);
  return problems;
}

export const PROFILE_TEXT: Record<ReportProfile, { label: string; summary: string }> = {
  internal: {
    label: "Internal",
    summary: "Full detail and real names, for your organization.",
  },
  external: {
    label: "External",
    summary:
      "For recipients outside your organization. Internal IP addresses, host names and user names are replaced by pseudonyms (one map for the whole report); analyst notes, custody IP addresses and user agents, record links and the platform address are left out; people are shown by role.",
  },
};

/** RT8: the pseudonymization is pattern-based; a human has to read the preview. */
export const EXTERNAL_REVIEW_WARNING =
  "Pseudonymization is pattern-based: a name that matches no rule and appears in no structured field (for example a host or person named only in free text) can pass. Review the preview for internal names before you finalize.";

export const EXTERNAL_REVIEW_ACK = "I reviewed the preview for internal names";

// ---------------------------------------------------------------------------------------------
// Selections

export type AddRowResult = { draft: ReportDraft; added: boolean; reason?: "duplicate" | "full" };

function sameRow(a: CitedRowRef, b: CitedRowRef): boolean {
  return a.kind === b.kind && a.ref_id === b.ref_id && (a.job_id ?? null) === (b.job_id ?? null);
}

/** Add a cited row (deduplicated, at most MAX_CITED_ROWS). */
export function addCitedRow(draft: ReportDraft, row: CitedRowRef): AddRowResult {
  const rows = draft.include.cited_rows;
  if (rows.some((existing) => sameRow(existing, row))) return { draft, added: false, reason: "duplicate" };
  if (rows.length >= MAX_CITED_ROWS) return { draft, added: false, reason: "full" };
  return { draft: { ...draft, include: { ...draft.include, cited_rows: [...rows, row] } }, added: true };
}

const CITED_KINDS: Record<CitedKind, true> = {
  finding: true,
  alert: true,
  ioc: true,
  evidence: true,
  job: true,
  timeline: true,
  capability: true,
  signature: true,
  flow: true,
  record: true,
  ti_result: true,
  sample: true,
  pe_summary: true,
  string: true,
  custody: true,
  note: true,
};

/**
 * The cited-row reference of a case row (an "Add to report" target), or null when that kind
 * cannot be cited (a status change, an AI run) or the id is not a plain row id. A `flow` needs
 * its job id; other kinds keep it only as a hint.
 */
export function citedRowRef(kind: string, refId: string | null | undefined, jobId?: string | null): CitedRowRef | null {
  if (!Object.hasOwn(CITED_KINDS, kind) || !refId || !/^[A-Za-z0-9_.:-]{1,64}$/.test(refId)) return null;
  if (kind === "flow" && !jobId) return null;
  return { kind: kind as CitedKind, ref_id: refId, ...(jobId ? { job_id: jobId } : {}) };
}

export function removeCitedRow(draft: ReportDraft, row: CitedRowRef): ReportDraft {
  return {
    ...draft,
    include: { ...draft.include, cited_rows: draft.include.cited_rows.filter((existing) => !sameRow(existing, row)) },
  };
}

/** Toggle an id in a list selection (notes, AI runs, collections, jobs), keeping order. */
export function toggleId(list: readonly string[], id: string, on: boolean, max = MAX_SELECTED_IDS): string[] {
  const has = list.includes(id);
  if (on && !has) return list.length >= max ? [...list] : [...list, id];
  if (!on && has) return list.filter((item) => item !== id);
  return [...list];
}

/**
 * AI runs that may go into a report: completed, of this case's scope, never refused or
 * withheld for a canary leak (the API re-checks, `422 selection_out_of_scope`).
 */
export function isSelectableAiRun(run: Pick<AiRun, "status" | "error_code" | "refusal_category">): boolean {
  return run.status === "completed" && run.error_code !== "canary_leak" && !run.refusal_category;
}

export function clampInt(value: string | number, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

/** `datetime-local` value <-> ISO (UTC). Empty or invalid -> null. */
export function localInputToIso(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function isoToLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// ---------------------------------------------------------------------------------------------
// Errors

/**
 * An ApiError with given extra body fields. `unwrap` of `lib/api` already keeps them
 * (`ApiError.extra`); this subclass remains for the report wrappers and hand-built errors.
 */
export class ReportApiError extends ApiError {
  constructor(base: ApiError, extra: Readonly<Record<string, unknown>>) {
    super(base.status, base.code, base.message, base.details, base.retryAfterSeconds, { ...base.extra, ...extra });
  }
}

/** `unwrap` for the report wrappers: the error keeps the whole `error` object of the body. */
export function unwrapReport<T>(result: { data?: T; error?: unknown; response: Response }): T {
  try {
    return unwrap(result);
  } catch (error) {
    if (error instanceof ApiError && !(error instanceof ReportApiError)) throw new ReportApiError(error, error.extra);
    throw error;
  }
}

export const REPORT_ERROR_TEXT: Record<string, string> = {
  stale_draft: "This draft was changed somewhere else (another tab or person). Reload it to continue.",
  selection_out_of_scope:
    "A selection is not part of this case any more (an analysis, AI run, note or IOC collection). Remove it and save again.",
  report_has_versions: "A report with signed versions cannot be discarded.",
  investigation_archived: "The case is archived: its reports are read-only.",
  report_too_large: "The report is over the 8 MiB snapshot limit. Narrow the selections listed below.",
  report_too_large_to_render:
    "The report is over the render budget, so its PDF could never be produced. Narrow the sections listed below.",
  tlp_below_case: "The case TLP is now more restrictive than this report's TLP.",
  external_review_required: "Confirm that you reviewed the preview for internal names.",
  distribution_required: "This report needs a distribution statement (who may receive it).",
  integrity_failed: "Integrity check failed: the stored snapshot does not match its recorded hash.",
  render_busy: "Too many renders are running. Try again in a minute.",
  not_implemented: "This part of reports is not available yet.",
};

export function reportErrorText(error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  return Object.hasOwn(REPORT_ERROR_TEXT, error.code) ? REPORT_ERROR_TEXT[error.code] : null;
}

export function hasCode(error: unknown, code: string): error is ApiError {
  return error instanceof ApiError && error.code === code;
}

export function isStaleDraft(error: unknown): boolean {
  return hasCode(error, "stale_draft");
}

function numberRecord(value: unknown): Record<string, number> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const out: Record<string, number> = {};
  for (const [key, n] of Object.entries(value)) {
    if (typeof n === "number" && Number.isFinite(n)) out[key] = n;
  }
  return Object.keys(out).length ? out : null;
}

/** Per-section units of a `422 report_too_large_to_render` (in the error body or its details). */
export function sectionUnitsOf(error: unknown): Record<string, number> | null {
  if (!(error instanceof ApiError)) return null;
  const extra = error.extra;
  const details = error.details && typeof error.details === "object" ? (error.details as Record<string, unknown>) : {};
  return numberRecord(extra.section_units) ?? numberRecord(details.section_units);
}

/** Per-section counts of a `422 report_too_large` / `_to_render` (`{section: {included, total}}`). */
export function sectionCountsOf(error: unknown): Record<string, SectionCount> | null {
  if (!(error instanceof ApiError)) return null;
  const extra = error.extra;
  const details = error.details && typeof error.details === "object" ? (error.details as Record<string, unknown>) : {};
  const raw = (extra.section_counts ?? details.section_counts ?? extra.counts ?? details.counts) as unknown;
  if (!raw || typeof raw !== "object") return null;
  const out: Record<string, SectionCount> = {};
  for (const [key, value] of Object.entries(raw)) {
    const v = value as Partial<SectionCount> | null;
    if (v && typeof v.included === "number" && typeof v.total === "number") out[key] = { included: v.included, total: v.total };
  }
  return Object.keys(out).length ? out : null;
}

// ---------------------------------------------------------------------------------------------
// Preview and budget (RT1)

export const SECTION_LABELS: Record<string, string> = {
  report: "Cover",
  case: "Case",
  sections: "Analyst sections",
  status_history: "Status history",
  evidence: "Evidence",
  custody: "Chain of custody",
  jobs: "Analyses",
  findings: "Findings",
  alerts: "Alerts",
  iocs: "IOCs",
  ti: "Threat intelligence",
  attack: "ATT&CK",
  timeline: "Timeline",
  notes: "Notes",
  ai: "AI sections",
  citations: "Citations",
};

/** What to narrow, per section, when a report is too large to render. */
export const SECTION_HINTS: Record<string, string> = {
  sections: "Shorten the analyst sections.",
  evidence: "Turn off the evidence inventory.",
  custody: "Turn off the chain of custody.",
  jobs: "Pick specific analyses instead of the latest of each evidence.",
  findings: "Raise the minimum severity or lower the maximum of findings.",
  alerts: "Raise the minimum severity or lower the maximum of alerts.",
  iocs: "Turn off the case-wide IOCs, pick fewer collections or lower the maximum.",
  ti: "Turn off threat intelligence.",
  attack: "Include confirmed techniques only.",
  timeline: "Narrow the timeline kinds or time range, or lower the maximum.",
  notes: "Select fewer notes.",
  ai: "Select fewer AI runs.",
  citations: "Cite fewer rows (each citation copies its record into the appendix).",
};

export function sectionLabel(key: string): string {
  return Object.hasOwn(SECTION_LABELS, key) ? SECTION_LABELS[key] : key.replaceAll("_", " ");
}

export type BudgetRow = { key: string; label: string; units: number; share: number; hint: string | null };

/** Sections by render units, largest first, with what to narrow. Fixed parts get no hint. */
export function budgetRows(sectionUnits: Readonly<Record<string, number>>): BudgetRow[] {
  const entries = Object.entries(sectionUnits).filter(
    ([key, units]) => Number.isFinite(units) && units > 0 && key !== "schema_version",
  );
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  return entries
    .map(([key, units]) => ({
      key,
      label: sectionLabel(key),
      units,
      share: total > 0 ? Math.round((units / total) * 1000) / 10 : 0,
      hint: Object.hasOwn(SECTION_HINTS, key) ? SECTION_HINTS[key] : null,
    }))
    .sort((a, b) => b.units - a.units || a.label.localeCompare(b.label));
}

export type CountRow = { key: string; label: string; included: number; total: number; truncated: boolean };

export function countRows(counts: Readonly<Record<string, SectionCount>>): CountRow[] {
  return Object.entries(counts).map(([key, count]) => ({
    key,
    label: sectionLabel(key),
    included: count.included,
    total: count.total,
    truncated: count.total > count.included,
  }));
}

const SNAPSHOT_KEYS = [
  "report",
  "case",
  "sections",
  "evidence",
  "custody",
  "jobs",
  "findings",
  "alerts",
  "iocs",
  "ti",
  "attack",
  "timeline",
  "notes",
  "ai",
  "citations",
] as const;

/** A shape check before rendering a snapshot (the API validated it; this guards the viewer). */
export function asSnapshot(value: unknown): ReportSnapshot | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (record.schema_version !== "cyberlab.report.v1") return null;
  for (const key of SNAPSHOT_KEYS) {
    if (!record[key] || typeof record[key] !== "object") return null;
  }
  return value as ReportSnapshot;
}

// ---------------------------------------------------------------------------------------------
// Renders

export function isFinalRender(status: RenderStatus): boolean {
  return status === "succeeded" || status === "failed";
}

/** Poll every 3 s while a render is queued or running; stop once every render is final. */
export function renderPollMs(renders: readonly Pick<RenderOut, "status">[] | undefined): number | false {
  return renders?.some((render) => !isFinalRender(render.status)) ? 3000 : false;
}

/** The newest render of each format (by creation time). */
export function latestRenders(renders: readonly RenderOut[]): Partial<Record<RenderFormat, RenderOut>> {
  const out: Partial<Record<RenderFormat, RenderOut>> = {};
  for (const render of renders) {
    const current = out[render.format];
    if (!current || render.created_at > current.created_at) out[render.format] = render;
  }
  return out;
}

export const RENDER_STATUS_LABELS: Record<RenderStatus, string> = {
  queued: "Queued",
  running: "Rendering",
  succeeded: "Ready",
  failed: "Failed",
};

const NARROW = "Finalize a narrower version (fewer rows or sections) or use Markdown.";
const RETRY = "Request the render again. If it fails again, tell an admin.";

export const RENDER_ERROR_TEXT: Record<string, { text: string; hint: string }> = {
  not_implemented: { text: "The renderer is not available yet.", hint: "Try again after the renderer is deployed." },
  snapshot_mismatch: { text: "The renderer received a snapshot that did not match its hash.", hint: RETRY },
  fetch_blocked: {
    text: "The document tried to load an outside resource and was stopped.",
    hint: "Tell an admin: report templates must never load resources.",
  },
  timeout: { text: "Rendering took too long.", hint: NARROW },
  oom: { text: "Rendering ran out of memory.", hint: NARROW },
  too_large: { text: "The rendered file is over the size limit (32 MiB).", hint: NARROW },
  too_many_pages: { text: "The document is over the 300-page limit.", hint: NARROW },
  invalid_output: { text: "The renderer produced an invalid file.", hint: RETRY },
  renderer_error: { text: "The renderer failed.", hint: RETRY },
};

export function renderErrorText(code: string | null | undefined): { text: string; hint: string } {
  if (code && Object.hasOwn(RENDER_ERROR_TEXT, code)) return RENDER_ERROR_TEXT[code];
  return { text: code ? `Rendering failed (${code.replaceAll("_", " ")}).` : "Rendering failed.", hint: RETRY };
}

// ---------------------------------------------------------------------------------------------
// Autosave (debounced, carries `revision`; a stale draft is never overwritten)

export type SaveStatus = "saved" | "dirty" | "saving" | "conflict" | "error";
export type DraftPatch = Omit<ReportUpdate, "revision" | "acknowledge_tlp_downgrade"> & {
  acknowledge_tlp_downgrade?: boolean;
};
export type SaveDraft = (body: ReportUpdate) => Promise<ReportDetail>;
export type SaverState = { status: SaveStatus; revision: number; error: unknown };

/**
 * Debounced autosave of a draft. Changes are merged into one pending patch and sent with the
 * last known `revision`; the answer's revision is used for the next write. On `409 stale_draft`
 * the saver stops (status `conflict`) and keeps the unsaved patch: the UI shows a banner and
 * only an explicit reload (`reset`) continues. Other errors keep the patch for a retry.
 */
export class DraftSaver {
  private state: SaverState;
  private pending: DraftPatch | null = null;
  private inFlight: Promise<void> | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly listeners = new Set<() => void>();

  constructor(
    revision: number,
    private readonly save: SaveDraft,
    private readonly delayMs = 1200,
    private readonly onSaved?: (detail: ReportDetail) => void,
  ) {
    this.state = { status: "saved", revision, error: null };
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getState = (): SaverState => this.state;

  get hasPending(): boolean {
    return this.pending !== null;
  }

  private set(next: Partial<SaverState>) {
    this.state = { ...this.state, ...next };
    for (const listener of this.listeners) listener();
  }

  change(patch: DraftPatch): void {
    if (this.state.status === "conflict") return;
    this.pending = { ...this.pending, ...patch };
    this.set({ status: this.inFlight ? "saving" : "dirty", error: null });
    this.schedule();
  }

  private schedule() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.send();
    }, this.delayMs);
  }

  /** Send now (preview, finalize, leaving the page); resolves once nothing is pending. */
  async flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    while (this.inFlight || (this.pending && this.state.status !== "conflict")) {
      if (this.inFlight) await this.inFlight;
      else {
        await this.send();
        if (this.state.status === "error") return;
      }
    }
  }

  /** Retry after an error (not after a conflict: that needs a reload). */
  retry(): void {
    if (this.state.status === "error") void this.send();
  }

  private send(): Promise<void> {
    if (this.inFlight || !this.pending || this.state.status === "conflict") return this.inFlight ?? Promise.resolve();
    const patch = this.pending;
    this.pending = null;
    const body: ReportUpdate = {
      ...patch,
      acknowledge_tlp_downgrade: patch.acknowledge_tlp_downgrade ?? false,
      revision: this.state.revision,
    };
    this.set({ status: "saving", error: null });
    const run = (async () => {
      try {
        const detail = await this.save(body);
        this.onSaved?.(detail);
        this.set({ revision: detail.report.revision, status: this.pending ? "dirty" : "saved" });
        if (this.pending) this.schedule();
      } catch (error) {
        // Keep the unsaved values: newer edits win over the failed patch.
        this.pending = { ...patch, ...this.pending };
        this.set({ status: isStaleDraft(error) ? "conflict" : "error", error });
      } finally {
        this.inFlight = null;
      }
    })();
    this.inFlight = run;
    return run;
  }

  /** Another write (finalize) answered `409 stale_draft`: stop like an autosave conflict. */
  markConflict(error: unknown): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.set({ status: "conflict", error });
  }

  /** After a reload: start over from the server's revision, dropping the unsaved patch. */
  reset(revision: number): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.pending = null;
    this.set({ status: "saved", revision, error: null });
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.listeners.clear();
  }
}

export const SAVE_STATUS_TEXT: Record<SaveStatus, string> = {
  saved: "All changes saved",
  dirty: "Unsaved changes",
  saving: "Saving…",
  conflict: "Not saved: changed elsewhere",
  error: "Not saved",
};

// ---------------------------------------------------------------------------------------------
// API wrappers

const path = (orgId: string) => ({ org_id: orgId });

export async function listReports(
  orgId: string,
  query: { investigation_id?: string | null; status?: "draft" | "discarded" | null; cursor?: string | null } = {},
): Promise<ReportPage> {
  return unwrapReport(await api.GET("/api/v1/orgs/{org_id}/reports", { params: { path: path(orgId), query } }));
}

export async function listCaseReports(orgId: string, investigationId: string, cursor?: string | null): Promise<ReportPage> {
  return unwrapReport(
    await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/reports", {
      params: { path: { org_id: orgId, investigation_id: investigationId }, query: cursor ? { cursor } : {} },
    }),
  );
}

export async function createReport(orgId: string, investigationId: string, body: ReportCreate): Promise<Report> {
  return unwrapReport(
    await api.POST("/api/v1/orgs/{org_id}/investigations/{investigation_id}/reports", {
      params: { path: { org_id: orgId, investigation_id: investigationId } },
      body,
    }),
  );
}

export async function getReport(orgId: string, reportId: string): Promise<ReportDetail> {
  return unwrapReport(
    await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}", { params: { path: { org_id: orgId, report_id: reportId } } }),
  );
}

export async function updateReport(orgId: string, reportId: string, body: ReportUpdate): Promise<ReportDetail> {
  return unwrapReport(
    await api.PATCH("/api/v1/orgs/{org_id}/reports/{report_id}", {
      params: { path: { org_id: orgId, report_id: reportId } },
      body,
    }),
  );
}

export async function discardReport(orgId: string, reportId: string): Promise<ReportDetail> {
  return unwrapReport(
    await api.POST("/api/v1/orgs/{org_id}/reports/{report_id}/discard", {
      params: { path: { org_id: orgId, report_id: reportId } },
    }),
  );
}

export async function previewReport(orgId: string, reportId: string): Promise<ReportPreview> {
  return unwrapReport(
    await api.POST("/api/v1/orgs/{org_id}/reports/{report_id}/preview", {
      params: { path: { org_id: orgId, report_id: reportId } },
    }),
  );
}

export async function finalizeReport(orgId: string, reportId: string, body: ReportFinalize): Promise<ReportVersion> {
  return unwrapReport(
    await api.POST("/api/v1/orgs/{org_id}/reports/{report_id}/finalize", {
      params: { path: { org_id: orgId, report_id: reportId } },
      body,
    }),
  );
}

export async function listVersions(orgId: string, reportId: string): Promise<ReportVersion[]> {
  const page = unwrapReport(
    await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}/versions", {
      params: { path: { org_id: orgId, report_id: reportId } },
    }),
  );
  return page.items;
}

const versionPath = (orgId: string, reportId: string, version: number) => ({
  org_id: orgId,
  report_id: reportId,
  version,
});

export async function getVersion(orgId: string, reportId: string, version: number): Promise<ReportVersionDetail> {
  return unwrapReport(
    await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}/versions/{version}", {
      params: { path: versionPath(orgId, reportId, version) },
    }),
  );
}

export async function getVersionContent(orgId: string, reportId: string, version: number): Promise<ReportSnapshot> {
  return unwrapReport(
    await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}/versions/{version}/content", {
      params: { path: versionPath(orgId, reportId, version) },
    }),
  );
}

export async function listRenders(orgId: string, reportId: string, version: number): Promise<RenderOut[]> {
  const page = unwrapReport(
    await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}/versions/{version}/renders", {
      params: { path: versionPath(orgId, reportId, version) },
    }),
  );
  return page.items;
}

export async function requestRender(
  orgId: string,
  reportId: string,
  version: number,
  format: RenderFormat,
): Promise<RenderOut> {
  return unwrapReport(
    await api.POST("/api/v1/orgs/{org_id}/reports/{report_id}/versions/{version}/renders", {
      params: { path: versionPath(orgId, reportId, version) },
      body: { format },
    }),
  );
}

export type Download = { blob: Blob; disposition: string | null };

export async function downloadRender(orgId: string, renderId: string): Promise<Download> {
  if (!isUuid(renderId)) throw new Error("invalid render id");
  const result = await api.GET("/api/v1/orgs/{org_id}/report-renders/{render_id}/download", {
    params: { path: { org_id: orgId, render_id: renderId } },
    parseAs: "blob",
  });
  return { blob: unwrapReport(result) as Blob, disposition: result.response.headers.get("content-disposition") };
}

export async function downloadSnapshot(orgId: string, reportId: string, version: number): Promise<Download> {
  const result = await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}/versions/{version}/snapshot", {
    params: { path: versionPath(orgId, reportId, version) },
    parseAs: "blob",
  });
  return { blob: unwrapReport(result) as Blob, disposition: result.response.headers.get("content-disposition") };
}

export async function downloadSignature(orgId: string, reportId: string, version: number): Promise<Download> {
  const result = await api.GET("/api/v1/orgs/{org_id}/reports/{report_id}/versions/{version}/signature", {
    params: { path: versionPath(orgId, reportId, version) },
    parseAs: "blob",
  });
  return { blob: unwrapReport(result) as unknown as Blob, disposition: result.response.headers.get("content-disposition") };
}

/** Save a Blob as a file through a temporary object URL (no navigation, no new window). */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
