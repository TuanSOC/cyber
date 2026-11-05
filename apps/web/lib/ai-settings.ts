import type { Schemas } from "@cyberlab/contracts";

import { ApiError, errorMessage } from "@/lib/api";

/*
 * AI settings and providers (M5): types, client-side validators, wording and error mapping for
 * the Integrations page. Nothing here ever holds an API key: keys are write-only, sent once by
 * the key form and never returned by the API.
 */

export type AiProvider = Schemas["AiProviderOut"];
export type AiProviderName = Schemas["AiProviderName"];
export type AiProviderPage = Schemas["AiProviderPage"];
export type AiProviderSaved = Schemas["AiProviderSaved"];
export type AiModel = Schemas["AiModelOut"];
export type AiSettings = Schemas["AiSettingsOut"];
export type AiSettingsUpdate = Schemas["AiSettingsUpdate"];
/** A provider PUT body without the key: only the key form sends `api_key` (`storeAiKey`). */
export type AiProviderUpdateBody = Omit<Schemas["AiProviderUpdate"], "api_key">;
export type AiCeilings = Schemas["AiCeilingsOut"];
export type AiUsage = Schemas["AiUsageOut"];
export type AiUnavailableReason = NonNullable<AiProvider["unavailable_reason"]>;

/** The disclosure toggles (RT22: widening any of them needs the privacy acknowledgement again). */
export type AiInclusions = Pick<
  AiSettings,
  "pseudonymize_internal" | "include_strings" | "include_ti" | "include_case_text"
>;
export type AiInclusionKey = keyof AiInclusions;

export type AiBudgetKey = "daily_token_budget" | "run_token_cap" | "incident_token_cap";

export const AI_MAX_LIST_ENTRIES = 50;

// ---------------------------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------------------------

/** Providers shown on the Integrations page: the mock only when the catalog offers it (dev / test). */
export function visibleAiProviders(items: readonly AiProvider[]): AiProvider[] {
  return items.filter((p) => p.name !== "mock" || p.available);
}

/** Providers an analysis may use: enabled, keyed (own or platform dev key) and available. */
export function usableAiProviders(items: readonly AiProvider[] | undefined): AiProvider[] {
  return (items ?? []).filter((p) => p.enabled && (p.configured || p.platform_key) && p.available);
}

export type AiProviderState = "not_configured" | "unverified" | "valid" | "invalid" | "error";

export const AI_PROVIDER_STATE_LABELS: Record<AiProviderState, string> = {
  not_configured: "not configured",
  unverified: "unverified",
  valid: "valid",
  invalid: "invalid",
  error: "error",
};

export function aiProviderState(p: Pick<AiProvider, "configured" | "platform_key" | "verify_status">): AiProviderState {
  if (!p.configured && !p.platform_key) return "not_configured";
  return p.verify_status ?? "unverified";
}

/** The first enable needs the terms acknowledgement (`acknowledge_terms`). */
export function needsTermsAck(p: Pick<AiProvider, "terms_ack_at">): boolean {
  return p.terms_ack_at === null;
}

/** Gemini's first enable also needs the paid-tier attestation (`acknowledge_paid_tier`, RT5). */
export function needsPaidTierAck(p: Pick<AiProvider, "requires_paid_tier_ack" | "paid_tier_ack_at">): boolean {
  return p.requires_paid_tier_ack && p.paid_tier_ack_at === null;
}

/** An enabled provider needs a key: its own or (dev / test only) the platform key. */
export function canEnable(p: Pick<AiProvider, "configured" | "platform_key" | "available">): boolean {
  return p.available && (p.configured || p.platform_key);
}

const UNAVAILABLE_TEXT: Record<AiUnavailableReason, string> = {
  ai_disabled_platform: "AI analysis is turned off on this deployment (AI_ENABLED=false).",
  prod_mock: "The test analyst is refused in production.",
  gemini_billing_required:
    "Gemini is unavailable: the free tier may use prompts and responses for training and human review. " +
    "An operator must enable billing on the Google Cloud project and set GEMINI_BILLING_ENABLED=true " +
    "before any organization can use Gemini.",
};

export function unavailableText(reason: AiProvider["unavailable_reason"]): string {
  return reason ? UNAVAILABLE_TEXT[reason] : "This provider is not available on this deployment.";
}

const VERIFY_ERROR_TEXT: Record<string, string> = {
  auth_failed: "The provider rejected the key.",
  model_not_found: "The selected model is not available to this key.",
  rate_limited: "The provider rate-limited the check; try again later.",
  overloaded: "The provider is overloaded; try again later.",
  spend_limit: "The key's spend limit is reached.",
  bad_request: "The provider refused the request.",
  timeout: "The provider did not answer in time.",
  transport: "The provider could not be reached.",
  provider_error: "The provider reported an error.",
  provider_unavailable: "The provider is not available on this deployment.",
  internal_error: "The check failed inside CyberLab.",
};

/** Explanation of a provider's `last_error_code` (unknown codes are shown verbatim). */
export function aiVerifyErrorText(code: string | null | undefined): string | null {
  if (!code) return null;
  return Object.hasOwn(VERIFY_ERROR_TEXT, code) ? VERIFY_ERROR_TEXT[code] : `Check failed (${code}).`;
}

const USD = new Intl.NumberFormat("en-US", { maximumFractionDigits: 3 });

/** "$2 / $10 per MTok (in / out)". */
export function priceText(model: Pick<AiModel, "price">): string {
  return `$${USD.format(model.price.input)} / $${USD.format(model.price.output)} per MTok (in / out)`;
}

/** Model select label: name, prices, and "unverified" for ids not yet confirmed by the provider. */
export function modelOptionLabel(model: AiModel): string {
  return `${model.label} · ${priceText(model)}${model.verified ? "" : " · unverified"}`;
}

/** The model a provider runs with: its own choice or the catalog default. */
export function effectiveModel(p: Pick<AiProvider, "model" | "default_model" | "models">): AiModel | undefined {
  const id = p.model ?? p.default_model;
  return p.models.find((m) => m.id === id);
}

// ---------------------------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------------------------

/** Data that leaves the platform for the chosen provider when an analysis runs. */
export function disclosedCategories(next: AiInclusions): string[] {
  return [
    "finding and alert text",
    "IP addresses",
    "domains and hostnames",
    "URLs (query values replaced)",
    "file facts (hashes, names, sizes, structure)",
    ...(next.include_ti ? ["threat intelligence summaries"] : []),
    ...(next.include_strings ? ["decoded strings from files"] : []),
    ...(next.include_case_text ? ["the case title and description"] : []),
  ];
}

/** Exactly what pseudonymization recognizes as internal (the card lists it, see Risk). */
export const PSEUDONYMIZED_KINDS = [
  "private, CGNAT, loopback, link-local and unique-local addresses",
  "your internal CIDRs",
  "special-use and single-label host names, and names under your internal suffixes",
  "user names in C:\\Users\\… and /home/… paths, PDB paths and internal email local parts",
] as const;

/** Whether a settings change widens the disclosure: AI turned on, strings or case text turned on, or pseudonymization turned off (RT22). */
export function needsPrivacyAck(current: AiInclusions & { ai_enabled: boolean }, change: AiSettingsUpdate): boolean {
  return (
    (change.ai_enabled === true && !current.ai_enabled) ||
    (change.include_strings === true && !current.include_strings) ||
    (change.include_case_text === true && !current.include_case_text) ||
    (change.pseudonymize_internal === false && current.pseudonymize_internal)
  );
}

export const INCLUSION_LABELS: Record<AiInclusionKey, { label: string; hint: string }> = {
  pseudonymize_internal: {
    label: "Pseudonymize internal names",
    hint: "Internal IP addresses, host names and user names are replaced (INT_IP_1, INT_HOST_2, USER_3) before sending.",
  },
  include_strings: {
    label: "Include decoded strings",
    hint: "Strings extracted from files can carry internal paths, names and credentials.",
  },
  include_ti: {
    label: "Include threat intelligence results",
    hint: "Summaries of the provider verdicts already stored for the indicators.",
  },
  include_case_text: {
    label: "Include the case title and description",
    hint: "Free text written by your team.",
  },
};

export const INCLUSION_ORDER: readonly AiInclusionKey[] = [
  "pseudonymize_internal",
  "include_strings",
  "include_ti",
  "include_case_text",
];

// ---------------------------------------------------------------------------------------------
// Lists: internal CIDRs and domain suffixes (mirrors the API validators)
// ---------------------------------------------------------------------------------------------

/** Split pasted text into entries (newlines, commas, spaces). */
export function splitEntries(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

const IPV4_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((p) => IPV4_OCTET.test(p));
}

function isIpv6(value: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(value) || !value.includes(":")) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** A canonical CIDR (`10.0.0.0/8`, a bare address as /32 or /128), or an error text. */
export function normalizeCidr(raw: string): { value: string } | { error: string } {
  const text = raw.trim();
  const [address, prefix, ...rest] = text.split("/");
  if (!address || rest.length > 0) return { error: `"${text}" is not a valid CIDR` };
  const v4 = isIpv4(address);
  const v6 = !v4 && isIpv6(address);
  if (!v4 && !v6) return { error: `"${text}" is not a valid CIDR` };
  const max = v4 ? 32 : 128;
  if (prefix === undefined) return { value: `${address.toLowerCase()}/${max}` };
  if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > max) {
    return { error: `"${text}" has an invalid prefix length (0–${max})` };
  }
  return { value: `${address.toLowerCase()}/${Number(prefix)}` };
}

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
const NUMERIC_LABEL = /^(0x[0-9a-f]*|[0-9]+)$/i;
const MAX_DOMAIN_CHARS = 253;

function toAscii(name: string): string | null {
  if (/^[\x00-\x7f]*$/.test(name)) return name;
  try {
    return new URL(`http://${name}/`).hostname;
  } catch {
    return null;
  }
}

/** A domain suffix (`corp.example.org`, leading dots dropped, punycode lowercase), or an error text. */
export function normalizeSuffix(raw: string): { value: string } | { error: string } {
  const text = raw.trim();
  const invalid = { error: `"${text}" is not a valid domain suffix` };
  const name = text.replace(/^\.+/, "").replace(/\.$/, "").toLowerCase();
  if (!name || name.includes("..") || name.startsWith(".")) return invalid;
  const ascii = toAscii(name);
  if (ascii === null) return invalid;
  if (ascii.length > MAX_DOMAIN_CHARS) return { error: `"${text}" is too long` };
  const labels = ascii.split(".");
  if (!labels.every((label) => LABEL.test(label))) return invalid;
  const last = labels[labels.length - 1];
  if (NUMERIC_LABEL.test(last) || !/[a-z]/.test(last)) return invalid;
  return { value: ascii };
}

/**
 * Add the entries of `text` to `list`: valid ones (deduplicated, at most `AI_MAX_LIST_ENTRIES`)
 * and the error texts of the others.
 */
export function addEntries(
  list: readonly string[],
  text: string,
  normalize: (raw: string) => { value: string } | { error: string },
): { list: string[]; errors: string[] } {
  const out = [...list];
  const errors: string[] = [];
  for (const entry of splitEntries(text)) {
    const result = normalize(entry);
    if ("error" in result) {
      errors.push(result.error);
    } else if (!out.includes(result.value)) {
      if (out.length >= AI_MAX_LIST_ENTRIES) {
        errors.push(`At most ${AI_MAX_LIST_ENTRIES} entries.`);
        break;
      }
      out.push(result.value);
    }
  }
  return { list: out, errors };
}

// ---------------------------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------------------------

export const BUDGET_LABELS: Record<AiBudgetKey, { label: string; hint: string }> = {
  daily_token_budget: { label: "Daily tokens", hint: "All analyses of the organization per UTC day." },
  run_token_cap: { label: "Per-run cap", hint: "Tokens reserved for one provider call." },
  incident_token_cap: { label: "Per-incident cap", hint: "All calls of one incident summary together." },
};

export const BUDGET_ORDER: readonly AiBudgetKey[] = ["daily_token_budget", "run_token_cap", "incident_token_cap"];

/** A whole token count between 1 and the ceiling (`1 000 000`, `1,000,000` and `1_000_000` accepted). */
export function parseBudget(text: string, ceiling: number): { value: number | null; error: string | null } {
  const cleaned = text.replace(/[\s,_]/g, "");
  if (cleaned === "") return { value: null, error: "Enter a number of tokens." };
  if (!/^\d+$/.test(cleaned)) return { value: null, error: "Whole tokens only." };
  const value = Number(cleaned);
  if (!Number.isSafeInteger(value) || value < 1) return { value: null, error: "At least 1 token." };
  if (value > ceiling) return { value: null, error: `At most ${formatTokens(ceiling)} (the operator ceiling).` };
  return { value, error: null };
}

const TOKENS = new Intl.NumberFormat("en-US");

export function formatTokens(value: number): string {
  return TOKENS.format(value);
}

/** Estimated cost from micro-dollars: "≈ $0.0123" (prices change, so always an estimate). */
export function formatCostMicros(micros: number): string {
  const usd = micros / 1_000_000;
  if (usd === 0) return "≈ $0";
  if (usd < 0.0001) return "< $0.0001";
  return `≈ $${usd < 1 ? usd.toFixed(4) : usd.toFixed(2)}`;
}

/** Share of the daily budget used, clamped to 0–100. */
export function usedPercent(used: number, budget: number): number {
  if (budget <= 0) return 100;
  return Math.min(100, Math.max(0, Math.round((used / budget) * 100)));
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

const AI_ERROR_TEXT: Record<string, string> = {
  terms_not_acknowledged: "Acknowledge the provider's terms before enabling it.",
  paid_tier_not_acknowledged: "Confirm that the Gemini key belongs to a billing-enabled (paid tier) project.",
  privacy_not_acknowledged:
    "This change sends more data to AI providers: confirm the privacy notice (turning AI on, strings, threat intel or case text on, or pseudonymization off or narrowed).",
  model_not_allowed: "That model is not in the allowed list for this provider.",
  provider_unavailable: "This provider is not available on this deployment.",
  budget_above_ceiling: "A budget is above the operator ceiling.",
  limit_above_ceiling: "The request limit is above this provider's maximum.",
  api_key_required: "Store an API key before enabling this provider.",
  invalid_api_key: "The key must be 8–256 printable ASCII characters.",
  provider_not_configured: "No key is stored for this provider.",
  seal_key_unavailable: "Keys cannot be stored right now (sealing key unavailable).",
  broker_unavailable: "The verification could not be queued; try again shortly.",
  forbidden: "Only owners and admins can change AI settings.",
};

/** Error text for the AI settings and provider routes: known codes get a specific message. */
export function aiErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return AI_ERROR_TEXT.forbidden;
    if (Object.hasOwn(AI_ERROR_TEXT, error.code)) return AI_ERROR_TEXT[error.code];
  }
  return errorMessage(error);
}

/** Error text for the key form: never the server's validation text (keys are not echoed, but be safe). */
export function aiKeyErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.code === "validation_error") return AI_ERROR_TEXT.invalid_api_key;
  return aiErrorMessage(error);
}

type ValidationDetail = { loc?: unknown; msg?: unknown };

/** The server's validation messages for one body field (`internal_cidrs`, …). */
export function fieldErrors(error: unknown, field: string): string[] {
  if (!(error instanceof ApiError) || error.code !== "validation_error" || !Array.isArray(error.details)) return [];
  return (error.details as ValidationDetail[])
    .filter((d) => Array.isArray(d.loc) && d.loc.includes(field) && typeof d.msg === "string")
    .map((d) => (d.msg as string).replace(/^Value error, /, ""));
}

/** Whether the error carries this stable code (`privacy_not_acknowledged`, `budget_above_ceiling`, …). */
export function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof ApiError && error.code === code;
}
