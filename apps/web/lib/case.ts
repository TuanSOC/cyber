/**
 * Case management helpers (M6 phase 6): the case tabs, the status workflow with reasons, the
 * share policy ("do not send to AI / TI", TLP:RED), error texts and the attachment download
 * helper shared by the IOC and timeline exports. Pure functions only; the hooks live in
 * `lib/use-case.ts`. The API enforces every rule; the UI explains them.
 */
import type { Schemas } from "@cyberlab/contracts";

import { ApiError, type ApiErrorBody, ensureOk, errorBodyExtra, errorMessage, unwrap } from "@/lib/api";
import visRules from "@/lib/vis-rules.json";

export type Investigation = Schemas["InvestigationOut"];
export type InvestigationStatus = Schemas["InvestigationStatus"];
export type InvestigationUpdate = Schemas["InvestigationUpdate"];
export type SharePolicy = Schemas["SharePolicyOut"];
export type StatusEvent = Schemas["StatusEventOut"];
export type EvidenceSharePolicy = Schemas["EvidenceSharePolicyOut"];
export type Evidence = Schemas["EvidenceOut"];
export type TimelineEntry = Schemas["TimelineEntryOut"];
export type RefKindName = Schemas["RefKindName"];

// ---------------------------------------------------------------------------------------------
// Visible invisibles (RT24): the materialized range table shared with the API and renderer.

type VisRange = [number, number, string];
const VIS_RANGES: readonly VisRange[] = (visRules as unknown as { ranges: VisRange[] }).ranges;

function isInvisible(cp: number): boolean {
  let lo = 0;
  let hi = VIS_RANGES.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = VIS_RANGES[mid];
    if (cp < start) hi = mid - 1;
    else if (cp > end) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * Analyst or evidence text for display: bidi overrides, zero-width and control characters
 * (except tab and newline) become visible markers such as `⟨U+202E⟩`; everything else stays
 * literal. The result is still rendered as a React text node only.
 */
export function visText(value: string | null | undefined): string {
  if (!value) return "";
  let out = "";
  for (const ch of value) {
    const cp = ch.codePointAt(0) ?? 0;
    out += isInvisible(cp) ? `⟨U+${cp.toString(16).toUpperCase().padStart(4, "0")}⟩` : ch;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Tabs (`?tab=`)

export const CASE_TABS = [
  ["overview", "Overview"],
  ["evidence", "Evidence"],
  ["notes", "Notes"],
  ["iocs", "IOCs"],
  ["attack", "ATT&CK"],
  ["timeline", "Timeline"],
  ["ai", "AI"],
  ["reports", "Reports"],
] as const;

export type CaseTab = (typeof CASE_TABS)[number][0];

const TAB_SET: ReadonlySet<string> = new Set(CASE_TABS.map(([value]) => value));

/** The tab of a `?tab=` value; anything unknown falls back to the overview. */
export function parseCaseTab(value: string | null | undefined): CaseTab {
  return value && TAB_SET.has(value) ? (value as CaseTab) : "overview";
}

/** Internal link to one tab of a case (ids are URL-encoded). */
export function caseTabHref(orgId: string, investigationId: string, tab: CaseTab = "overview", hash?: string): string {
  const base = `/o/${encodeURIComponent(orgId)}/investigations/${encodeURIComponent(investigationId)}`;
  return `${base}${tab === "overview" ? "" : `?tab=${tab}`}${hash ? `#${hash}` : ""}`;
}

/** Anchor of the share-policy card on the overview tab (target of the policy-blocked links). */
export const SHARE_POLICY_ANCHOR = "share-policy";

// ---------------------------------------------------------------------------------------------
// Status workflow

export const STATUS_REASON_MAX = 500;

/**
 * Closing, archiving and reopening (closed → open / in progress) need a reason (the API answers
 * `422 status_reason_required` otherwise). Other moves (open → in progress) do not.
 */
export function needsStatusReason(from: InvestigationStatus, to: InvestigationStatus): boolean {
  if (to === "closed" || to === "archived") return true;
  return from === "closed" && (to === "open" || to === "in_progress");
}

export function statusActionLabel(from: InvestigationStatus, to: InvestigationStatus): string {
  if (to === "closed") return "Close";
  if (to === "archived") return "Archive";
  if (from === "closed") return "Reopen";
  return "Change status";
}

/** The trimmed reason, or a message why it cannot be sent. */
export function checkStatusReason(text: string): { ok: true; reason: string } | { ok: false; message: string } {
  const reason = text.trim();
  if (!reason) return { ok: false, message: "A reason is required." };
  if (reason.length > STATUS_REASON_MAX) return { ok: false, message: `At most ${STATUS_REASON_MAX} characters.` };
  if (reason.includes("\u0000")) return { ok: false, message: "The reason contains an invalid character." };
  return { ok: true, reason };
}

// ---------------------------------------------------------------------------------------------
// Share policy

const SHARE_REASON_TEXT: Record<string, string> = {
  tlp_red: "The case is marked TLP:RED: nothing is sent to AI or threat-intel providers.",
  case_ai_excluded: "The case is marked “do not send to AI”.",
  case_ti_excluded: "The case is marked “do not send to threat-intel providers”.",
  evidence_ai_excluded: "An evidence item of this scope is marked “do not send to AI”.",
  evidence_ti_excluded: "An evidence item of this scope is marked “do not send to threat-intel providers”.",
};

/** Text for one `share_policy.reasons` / `policy_blocked` reason; unknown codes are named verbatim. */
export function shareReasonText(reason: string | null | undefined): string {
  if (!reason) return "The share policy of this case or evidence does not allow this.";
  return Object.hasOwn(SHARE_REASON_TEXT, reason) ? SHARE_REASON_TEXT[reason] : `Blocked by the share policy (${reason}).`;
}

/** One line for the computed policy: what is blocked and why. */
export function sharePolicyLine(policy: SharePolicy): string {
  if (!policy.ai_blocked && !policy.ti_blocked) return "AI and threat-intel lookups are allowed for this case.";
  const blocked = [policy.ai_blocked ? "AI" : null, policy.ti_blocked ? "threat-intel providers" : null]
    .filter(Boolean)
    .join(" and ");
  const reasons = policy.reasons.map(shareReasonText).join(" ");
  return `Nothing from this case is sent to ${blocked}.${reasons ? ` ${reasons}` : ""}`;
}

export type ShareFlag = "ai" | "ti";

export const SHARE_FLAG_LABELS: Record<ShareFlag, string> = {
  ai: "Do not send to AI",
  ti: "Do not send to threat-intel providers",
};

export type ShareToggleState = {
  /** Effective state shown to the user (TLP:RED forces both on). */
  checked: boolean;
  disabled: boolean;
  /** Why the toggle cannot be changed, if so. */
  note: string | null;
};

/**
 * State of one exclusion toggle. Turning a flag on needs the write permission
 * (`investigation.write` on a case, `evidence.write` on an evidence item); turning it off needs
 * `integrations.manage`. TLP:RED forces both flags on (computed, not stored).
 */
export function shareToggleState({
  flag,
  tlpRed,
  canTurnOn,
  canTurnOff,
  readOnly = false,
}: {
  flag: boolean;
  tlpRed: boolean;
  canTurnOn: boolean;
  canTurnOff: boolean;
  readOnly?: boolean;
}): ShareToggleState {
  if (tlpRed) {
    return { checked: true, disabled: true, note: "Forced on by TLP:RED. Lower the TLP to change it." };
  }
  if (readOnly) return { checked: flag, disabled: true, note: "This case is archived and read-only." };
  if (flag && !canTurnOff) {
    return {
      checked: true,
      disabled: true,
      note: "Only an admin (integrations.manage) can turn an exclusion off.",
    };
  }
  if (!flag && !canTurnOn) return { checked: false, disabled: true, note: "You cannot change the share policy." };
  return { checked: flag, disabled: false, note: null };
}

/** Badges for an evidence row excluded from AI / TI (label text, never colour only). */
export function evidenceExclusionBadges(e: Pick<Evidence, "ai_excluded" | "ti_excluded">): string[] {
  const out: string[] = [];
  if (e.ai_excluded) out.push("No AI");
  if (e.ti_excluded) out.push("No TI");
  return out;
}

// ---------------------------------------------------------------------------------------------
// Errors

/**
 * An ApiError with a known `policy_blocked` reason. `unwrap` of `lib/api` already keeps the
 * body's extra fields (`ApiError.extra`), so this is only needed to attach a reason by hand.
 */
export class PolicyApiError extends ApiError {
  constructor(
    base: ApiError,
    readonly reason: string | null,
  ) {
    super(base.status, base.code, base.message, base.details, base.retryAfterSeconds, {
      ...base.extra,
      ...(reason ? { reason } : {}),
    });
  }
}

/** The `error.reason` of an error body, if any (a string of at most 64 characters). */
export function bodyReason(body: unknown): string | null {
  const reason = (body as { error?: { reason?: unknown } } | null | undefined)?.error?.reason;
  return typeof reason === "string" && reason.length > 0 && reason.length <= 64 ? reason : null;
}

/**
 * Attaches the body's `reason` to a `policy_blocked` ApiError that was built without the body's
 * extra fields (kept for callers that construct errors by hand; `unwrap` needs no help).
 */
export function withReason(error: unknown, body: unknown): unknown {
  if (error instanceof ApiError && error.code === "policy_blocked" && error.extraString("reason") === null) {
    const reason = bodyReason(body);
    if (reason) return new PolicyApiError(error, reason);
  }
  return error;
}

/** True for a `409 policy_blocked` answer (AI or TI refused by the share policy). */
export function isPolicyBlocked(error: unknown): error is ApiError {
  return error instanceof ApiError && error.code === "policy_blocked";
}

/** The reason of a `policy_blocked` error when the body carried one, else null. */
export function policyBlockedReason(error: unknown): string | null {
  return isPolicyBlocked(error) ? error.extraString("reason") : null;
}

const CASE_ERROR_TEXT: Record<string, string> = {
  policy_blocked: "The share policy of this case or evidence does not allow this.",
  status_reason_required: "A reason is required to close, reopen or archive a case.",
  tlp_downgrade_forbidden: "Only an admin (org.update) can lower the TLP.",
  tlp_downgrade_not_acknowledged: "Confirm the TLP downgrade to lower the marking.",
  investigation_archived: "This case is archived and read-only.",
  stale_note: "Someone edited this note in the meantime.",
  ref_out_of_scope: "A linked record is not part of this case.",
  collection_exists: "A collection with this name already exists in this case.",
  collection_archived: "This collection is archived.",
  too_many_items: "Too many items in one request (at most 500).",
  invalid_ioc: "This value is not a valid indicator of the chosen type.",
  invalid_technique: "Unknown, revoked or deprecated ATT&CK technique id.",
  mapping_exists: "This technique is already mapped for this case.",
  not_implemented: "This feature is not available yet on this server.",
};

/** Clear text for case-management errors: the stable codes first, then 403 / 404 / generic. */
export function caseErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "policy_blocked") return shareReasonText(policyBlockedReason(error));
    if (Object.hasOwn(CASE_ERROR_TEXT, error.code)) return CASE_ERROR_TEXT[error.code];
    if (error.status === 403) return "Your role does not allow this action.";
    if (error.status === 404) return "Not found. It may have been removed or belong to another organization.";
    if (error.status === 422 && error.code === "validation_error") return "Some fields are not valid.";
  }
  return errorMessage(error);
}

/**
 * `unwrap` of `lib/api` for the case wrappers. The shared `unwrap` keeps the body's `reason`
 * (`ApiError.extra`), so the policy-blocked notice can name it; kept as the case-module entry
 * point.
 */
export function unwrapCase<T>(result: { data?: T; error?: unknown; response: Response }): T {
  return unwrap(result);
}

/** `ensureOk` (204 answers) for the case wrappers. */
export function ensureCaseOk(result: { error?: unknown; response: Response }): void {
  ensureOk(result);
}

// ---------------------------------------------------------------------------------------------
// Timeline kinds

export const TIMELINE_KINDS: readonly RefKindName[] = ["custody", "job", "timeline", "alert", "finding", "note", "status"];

export const TIMELINE_KIND_LABELS: Record<RefKindName, string> = {
  custody: "Custody",
  job: "Analysis",
  timeline: "Capture event",
  alert: "Alert",
  finding: "Finding",
  note: "Note",
  status: "Status change",
};

export function timelineKindLabel(kind: string): string {
  return Object.hasOwn(TIMELINE_KIND_LABELS, kind) ? TIMELINE_KIND_LABELS[kind as RefKindName] : kind;
}

/** Case events (notes, status changes) have no evidence: shown without an evidence link (RT10). */
export function isCaseEvent(entry: Pick<TimelineEntry, "evidence_id">): boolean {
  return entry.evidence_id === null;
}

/** Row cap of a timeline export (`TIMELINE_EXPORT_MAX_ROWS`). */
export const TIMELINE_EXPORT_MAX_ROWS = 50_000;

// ---------------------------------------------------------------------------------------------
// Attachment downloads

const MAX_FILENAME = 180;

function safeFilename(name: string): string | null {
  // Keep the base name only; drop control characters, path separators and leading dots.
  // Drop control, bidi and zero-width characters (an RLO could disguise the extension).
  const printable = Array.from(name)
    .filter((ch) => {
      const code = ch.codePointAt(0) ?? 0;
      return code >= 0x20 && !isInvisible(code);
    })
    .join("");
  const cleaned = printable
    .replace(/[\\/]/g, "_")
    .replace(/^\.+/, "")
    .trim()
    .slice(0, MAX_FILENAME);
  return cleaned || null;
}

/**
 * Filename of a `Content-Disposition` header: the RFC 5987 `filename*=UTF-8''…` form first,
 * then a quoted or bare `filename=`. Path parts and control characters are removed; null when
 * absent or unusable.
 */
export function filenameFromDisposition(header: string | null | undefined): string | null {
  if (!header) return null;
  const star = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(header);
  if (star) {
    try {
      const decoded = decodeURIComponent(star[2].trim().replace(/^"|"$/g, ""));
      const name = safeFilename(decoded);
      if (name) return name;
    } catch {
      // fall through to the plain form
    }
  }
  const quoted = /filename\s*=\s*"((?:[^"\\]|\\.)*)"/i.exec(header);
  if (quoted) return safeFilename(quoted[1].replace(/\\(.)/g, "$1"));
  const bare = /filename\s*=\s*([^;]+)/i.exec(header);
  return bare ? safeFilename(bare[1].trim()) : null;
}

export type SaveDeps = {
  createObjectURL: (blob: Blob) => string;
  revokeObjectURL: (url: string) => void;
  click: (href: string, filename: string) => void;
};

function browserDeps(): SaveDeps {
  return {
    createObjectURL: (blob) => URL.createObjectURL(blob),
    revokeObjectURL: (url) => URL.revokeObjectURL(url),
    click: (href, filename) => {
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = filename;
      anchor.rel = "noopener";
      anchor.style.display = "none";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    },
  };
}

/** Saves a blob under the server's filename; the object URL is always revoked. */
export function saveBlob(blob: Blob, filename: string, deps: SaveDeps = browserDeps()): void {
  const url = deps.createObjectURL(blob);
  try {
    deps.click(url, filename);
  } finally {
    // Revoke on the next tick: the click has started the download by then.
    setTimeout(() => deps.revokeObjectURL(url), 0);
  }
}

/** Saves an openapi-fetch `parseAs: "blob"` answer under the `Content-Disposition` filename. */
export function saveDownload(
  result: { data?: unknown; error?: unknown; response: Response },
  fallbackName: string,
  deps?: SaveDeps,
): string {
  if (!result.response.ok || !(result.data instanceof Blob)) {
    const body = result.error as ApiErrorBody | undefined;
    throw new ApiError(
      result.response.status,
      body?.error?.code ?? "http_error",
      body?.error?.message ?? `Download failed (${result.response.status})`,
      body?.error?.details,
      undefined,
      errorBodyExtra(body),
    );
  }
  const filename = filenameFromDisposition(result.response.headers.get("content-disposition")) ?? fallbackName;
  saveBlob(result.data, filename, deps);
  return filename;
}
