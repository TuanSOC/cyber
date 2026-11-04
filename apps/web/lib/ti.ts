import type { Schemas } from "@cyberlab/contracts";

import { ApiError, errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";

/*
 * Threat intel presentation helpers (M4). Wording rule: every provider statement is attributed
 * ("Reported by VirusTotal on ..."), provider-native scores are quoted with their scale, and
 * nothing here labels an indicator on our own behalf. Provider text is untrusted: it is only
 * ever rendered as plain text, and the only links are server-built https permalinks.
 */

export type ProviderName = Schemas["ProviderName"];
export type Integration = Schemas["IntegrationOut"];
export type IntegrationPage = Schemas["IntegrationPage"];
export type VerifyStatus = Schemas["VerifyStatus"];
export type TiResult = Schemas["ResultOut"];
export type IocEnrichment = Schemas["IocEnrichmentOut"];
export type EnrichedIoc = Schemas["EnrichedIocOut"];
export type Detections = Schemas["Detections"];
export type TiRun = Schemas["RunOut"];
export type TiRunDetail = Schemas["RunDetailOut"];
export type TiRunItem = Schemas["RunItemOut"];
export type ValueReport = Schemas["ValueReportOut"];
export type LookupType = Schemas["LookupType"];
export type TiIocType = Schemas["TiIocType"];
export type ProviderSummary = NonNullable<TiResult["summary"]>;
export type AttackLabel = Schemas["AttackLabel"];
export type AttackMeta = Schemas["AttackMeta"];
export type RunStatus = TiRun["status"];
export type ItemReason = NonNullable<TiRunItem["reason"]>;

export const PROVIDERS: readonly ProviderName[] = [
  "virustotal",
  "abuseipdb",
  "urlhaus",
  "malwarebazaar",
  "otx",
  "misp",
  "mock",
];

export const PROVIDER_LABELS: Record<ProviderName, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlhaus: "URLhaus",
  malwarebazaar: "MalwareBazaar",
  otx: "AlienVault OTX",
  misp: "MISP",
  mock: "Test provider",
};

/** Compact name used inside chips. */
export const PROVIDER_SHORT: Record<ProviderName, string> = {
  virustotal: "VT",
  abuseipdb: "AbuseIPDB",
  urlhaus: "URLhaus",
  malwarebazaar: "MalwareBazaar",
  otx: "OTX",
  misp: "MISP",
  mock: "Test",
};

export function providerLabel(name: string): string {
  return Object.hasOwn(PROVIDER_LABELS, name) ? PROVIDER_LABELS[name as ProviderName] : name;
}

export function providerShort(name: string): string {
  return Object.hasOwn(PROVIDER_SHORT, name) ? PROVIDER_SHORT[name as ProviderName] : name;
}

/**
 * Public terms pages, linked from the acknowledgement dialog. Not part of the API catalog
 * (it carries the `tos_note` text only); MISP is self-hosted and the test provider is local.
 */
export const PROVIDER_TERMS_URL: Partial<Record<ProviderName, string>> = {
  virustotal: "https://docs.virustotal.com/docs/terms-of-service",
  abuseipdb: "https://www.abuseipdb.com/legal",
  urlhaus: "https://abuse.ch/terms-of-use/",
  malwarebazaar: "https://abuse.ch/terms-of-use/",
  otx: "https://otx.alienvault.com/",
};

export const TI_IOC_TYPE_LABELS: Record<TiIocType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  email: "Email",
};

export function tiIocTypeLabel(type: string | null | undefined): string {
  if (!type) return "—";
  return Object.hasOwn(TI_IOC_TYPE_LABELS, type) ? TI_IOC_TYPE_LABELS[type as TiIocType] : type;
}

// ---------------------------------------------------------------------------------------------
// Integrations
// ---------------------------------------------------------------------------------------------

export type IntegrationState = "not_configured" | VerifyStatus;

export const INTEGRATION_STATE_LABELS: Record<IntegrationState, string> = {
  not_configured: "not configured",
  unverified: "unverified",
  valid: "valid",
  invalid: "invalid",
  error: "error",
};

export function integrationState(i: Pick<Integration, "configured" | "verify_status">): IntegrationState {
  if (!i.configured) return "not_configured";
  return i.verify_status ?? "unverified";
}

/** Providers shown on the Integrations page: the test provider only when the catalog offers it. */
export function visibleIntegrations(items: readonly Integration[]): Integration[] {
  return items.filter((i) => i.name !== "mock" || i.available);
}

/** Providers a run may use: enabled, keyed and available. */
export function enabledProviders(items: readonly Integration[] | undefined): Integration[] {
  return (items ?? []).filter((i) => i.enabled && i.configured && i.available);
}

/** The first enable needs an explicit terms acknowledgement (RT16). */
export function needsTermsAck(i: Pick<Integration, "terms_ack_at">): boolean {
  return !i.terms_ack_at;
}

/** Effective limits: the org's own, else the catalog defaults. */
export function effectiveLimits(i: Pick<Integration, "limits" | "default_limits">): {
  per_minute: number | null;
  per_day: number | null;
} {
  return {
    per_minute: i.limits?.per_minute ?? i.default_limits.per_minute,
    per_day: i.limits?.per_day ?? i.default_limits.per_day,
  };
}

/** Parse a limit input: blank = no override; otherwise a positive integer not above the ceiling. */
export function parseLimit(
  input: string,
  ceiling: number | null,
): { value: number | null; error: string | null } {
  const text = input.trim();
  if (text === "") return { value: null, error: null };
  if (!/^\d+$/.test(text)) return { value: null, error: "Whole numbers only" };
  const value = Number(text);
  if (value < 1) return { value: null, error: "At least 1" };
  if (ceiling !== null && value > ceiling) return { value: null, error: `At most ${ceiling}` };
  return { value, error: null };
}

/**
 * Client-side syntax hint for the MISP base URL (the API checks it again and never resolves
 * it; only the worker does). Returns an error message or null.
 */
export function mispUrlHint(input: string): string | null {
  const text = input.trim();
  if (text === "") return "Enter the MISP server URL";
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return "Not a valid URL";
  }
  if (url.protocol !== "https:") return "Only https URLs are accepted";
  if (url.username || url.password) return "No user name or password in the URL";
  if (url.search || url.hash) return "No query string or fragment";
  return null;
}

/** Excluded suffixes as typed (one per line or comma separated), trimmed and de-duplicated. */
export function parseSuffixes(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\n,]/)) {
    const value = part.trim().toLowerCase().replace(/^\.+/, "");
    if (value && !out.includes(value)) out.push(value);
  }
  return out;
}

const VERIFY_ERROR_TEXT: Record<string, string> = {
  auth: "The provider rejected the key.",
  timeout: "The provider did not answer in time.",
  transport: "The provider could not be reached.",
  oversize: "The provider's answer was larger than accepted.",
  bad_json: "The provider's answer could not be read.",
  http_5xx: "The provider reported a server error.",
  unexpected_status: "The provider answered with an unexpected status.",
  redirect: "The provider answered with a redirect, which is not followed.",
  rate_limited: "The provider rate-limited the check; try again later.",
  quota_exhausted: "The provider's daily quota is used up.",
  bad_request: "The provider refused the request.",
  invalid_input: "The provider refused the request.",
  path_not_allowed: "The request was blocked by the provider path allowlist.",
  misp_url_not_public: "The MISP host resolves to a non-public address, so it is never contacted.",
  misp_url_invalid: "The MISP URL is not acceptable.",
  internal_error: "The check failed unexpectedly.",
};

/** Explanation of an integration's `last_error_code` (unknown codes are shown verbatim). */
export function verifyErrorText(code: string | null | undefined): string | null {
  if (!code) return null;
  return Object.hasOwn(VERIFY_ERROR_TEXT, code) ? VERIFY_ERROR_TEXT[code] : `Check failed (${code}).`;
}

const TI_ERROR_TEXT: Record<string, string> = {
  terms_not_acknowledged: "Acknowledge the provider's terms before enabling it.",
  api_key_required: "Store an API key before enabling this provider.",
  key_required_for_url_change: "Changing the MISP URL requires entering the key again.",
  misp_url_invalid: "The MISP URL must be https, without user name, password, query or fragment.",
  misp_url_required: "Enter the MISP server URL.",
  base_url_not_supported: "This provider has no configurable URL.",
  limit_above_ceiling: "A limit is above the allowed maximum.",
  invalid_api_key: "The key must be 8–256 printable ASCII characters.",
  integration_not_configured: "No key is stored for this provider.",
  seal_key_unavailable: "Keys cannot be stored right now (sealing key unavailable).",
  broker_unavailable: "The enrichment queue is unavailable; try again shortly.",
  provider_unavailable: "This provider is not available on this deployment.",
  no_provider_enabled: "No provider is enabled. An admin can enable one under Settings → Integrations.",
  provider_not_enabled: "A selected provider is not enabled.",
  enrichment_busy: "Too many enrichment runs are active; wait for one to finish.",
  job_not_ready: "The analysis has not finished, so its IOCs cannot be enriched yet.",
  too_many_values: "Too many values: at most 20 per lookup.",
  no_values: "Enter at least one value.",
  unknown_provider: "Unknown provider.",
  invalid_ioc: "Not a recognized indicator.",
};

/** Error text for TI API calls: known codes get a specific message. */
export function tiErrorMessage(error: unknown): string {
  if (error instanceof ApiError && Object.hasOwn(TI_ERROR_TEXT, error.code)) return TI_ERROR_TEXT[error.code];
  return errorMessage(error);
}

// ---------------------------------------------------------------------------------------------
// Normalization report: skip reasons and notes
// ---------------------------------------------------------------------------------------------

const SKIP_TEXT: Record<string, string> = {
  not_global_ip: "private address — not sent",
  special_use_name: "special-use or internal name — not sent",
  excluded_suffix: "excluded by your organization's suffix list — not sent",
  single_label: "single-label name — not sent",
  unsupported_type: "type never sent to providers",
  invalid: "not a valid indicator — not sent",
  has_userinfo: "URL with embedded credentials — not sent",
  bad_scheme: "only http(s) URLs are looked up — not sent",
  too_long: "too long — not sent",
};

/** Why a value was never sent anywhere (from the API's skip reason). */
export function skipReasonText(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return Object.hasOwn(SKIP_TEXT, reason) ? SKIP_TEXT[reason] : `not sent (${reason})`;
}

const PROVIDER_SKIP_TEXT: Record<string, string> = {
  unsupported_type: "type not supported",
  excluded_suffix: "excluded suffix",
};

/** Why one provider does not receive a value that others may receive. */
export function providerSkipText(reason: string): string {
  return Object.hasOwn(PROVIDER_SKIP_TEXT, reason) ? PROVIDER_SKIP_TEXT[reason] : (skipReasonText(reason) ?? reason);
}

const NOTE_TEXT: Record<string, string> = {
  query_removed: "query removed before lookup",
  refanged: "refanged",
};

export function noteText(note: string): string {
  return Object.hasOwn(NOTE_TEXT, note) ? NOTE_TEXT[note] : note;
}

/** An observed URL that carries a query string or fragment: removed before any lookup (RT4). */
export function urlQueryRemoved(type: string, value: string): boolean {
  return type === "url" && /[?#]/.test(value);
}

/** M2/M3 IOC row type → the TI lookup type (null: never looked up). */
export function lookupTypeForIoc(type: string): LookupType | null {
  switch (type) {
    case "ip":
    case "domain":
    case "url":
    case "email":
      return type;
    case "file_md5":
      return "md5";
    case "file_sha1":
      return "sha1";
    case "file_sha256":
      return "sha256";
    case "ipv4":
    case "ipv6":
    case "md5":
    case "sha1":
    case "sha256":
      return type;
    default:
      return null;
  }
}

/** Link to the per-IOC history page. */
export function historyHref(orgId: string, type: string | null, value: string): string {
  const params = new URLSearchParams();
  if (type) params.set("type", type);
  params.set("value", value);
  return `/o/${orgId}/intel/ioc?${params.toString()}`;
}

// ---------------------------------------------------------------------------------------------
// Manual lookup input
// ---------------------------------------------------------------------------------------------

export const MAX_LOOKUP_VALUES = 20;
const MAX_VALUE_CHARS = 2048;

/** Display-only refang (the API refangs again): `hxxp`, `[.]`, `(.)`, `[dot]`, `[:]`, `[@]`. */
export function refang(value: string): string {
  return value
    .replace(/^(hxxp|fxp)(s?)(?=(?:\[:\]|:)\/\/)/i, (_m, scheme: string, s: string) =>
      (scheme.toLowerCase() === "hxxp" ? "http" : "ftp") + s.toLowerCase(),
    )
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]|\(@\)|\[at\]/gi, "@");
}

/** One value per line, trimmed, blank lines dropped, duplicates removed (order kept). */
export function parseLookupInput(text: string): { values: string[]; error: string | null } {
  const values: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const value = line.trim();
    if (value && !values.includes(value)) values.push(value);
  }
  if (values.length > MAX_LOOKUP_VALUES) {
    return { values, error: `At most ${MAX_LOOKUP_VALUES} values per lookup (${values.length} entered).` };
  }
  if (values.some((v) => v.length > MAX_VALUE_CHARS)) {
    return { values, error: `Values are limited to ${MAX_VALUE_CHARS} characters.` };
  }
  return { values, error: null };
}

// ---------------------------------------------------------------------------------------------
// Attributed chips and texts
// ---------------------------------------------------------------------------------------------

/**
 * THE template for VirusTotal's engine categories (the only place a provider-native category
 * name is shown, always attributed and with the engine total): "71 engines: 12 report malicious".
 */
export function vtEnginesText(d: Detections): string {
  const parts = [`${d.malicious} report malicious`];
  if (d.suspicious > 0) parts.push(`${d.suspicious} report suspicious`);
  return `${d.total} engines: ${parts.join(", ")}`;
}

type ChipSource = Pick<
  IocEnrichment,
  "provider" | "status" | "found" | "score" | "score_scale" | "detections" | "stale" | "fetched_at"
>;

function scoreText(score: number): string {
  return Number.isInteger(score) ? String(score) : score.toFixed(1);
}

/** Distinct MISP events among the returned attributes. */
export function mispEventCount(summary: Extract<ProviderSummary, { provider: "misp" }>): number {
  const ids = new Set<string>();
  for (const a of summary.attributes) {
    const id = a.event_uuid ?? (a.event_id != null ? String(a.event_id) : null);
    if (id) ids.add(id);
  }
  return ids.size;
}

/**
 * Compact, attributed chip text: "VT 12/71 engines", "AbuseIPDB confidence 87/100",
 * "URLhaus listed", "OTX 3 pulses", "MISP 2 events", "VT not found", "… · stale".
 * `summary` (from the full result) adds OTX pulse and MISP event counts.
 */
export function chipText(e: ChipSource, summary?: ProviderSummary | null): string {
  const short = providerShort(e.provider);
  let text: string;
  if (e.status === "error") text = `${short} lookup error`;
  else if (e.status === "auth_failed") text = `${short} key rejected`;
  else if (e.status === "not_found" || !e.found) text = `${short} not found`;
  else if (e.provider === "virustotal" && e.detections) text = `VT ${e.detections.malicious}/${e.detections.total} engines`;
  else if (e.provider === "abuseipdb" && e.score !== null) text = `AbuseIPDB confidence ${scoreText(e.score)}/100`;
  else if (e.provider === "otx" && summary?.provider === "otx" && summary.pulse_count != null)
    text = `OTX ${summary.pulse_count} ${summary.pulse_count === 1 ? "pulse" : "pulses"}`;
  else if (e.provider === "misp" && summary?.provider === "misp") {
    const n = mispEventCount(summary);
    text = n > 0 ? `MISP ${n} ${n === 1 ? "event" : "events"}` : "MISP listed";
  } else if (e.provider === "mock" && e.score !== null) text = `Test ${scoreText(e.score)} hits`;
  else text = `${short} listed`;
  return e.stale ? `${text} · stale` : text;
}

/** Tooltip of a chip: who said it and when ("Reported by VirusTotal on …: 71 engines: …"). */
export function chipTitle(e: ChipSource): string {
  const when = formatDate(e.fetched_at).local;
  let text = `Reported by ${providerLabel(e.provider)} on ${when}`;
  if (e.status === "ok" && e.found && e.provider === "virustotal" && e.detections) text += `: ${vtEnginesText(e.detections)}`;
  if (e.status === "ok" && e.found && e.provider === "abuseipdb" && e.score !== null)
    text += `: confidence ${scoreText(e.score)} of 100 (AbuseIPDB's own score)`;
  if (e.status === "not_found" || (e.status === "ok" && !e.found)) text += ": no record";
  if (e.status === "error") text += ": the lookup failed";
  if (e.status === "auth_failed") text += ": the provider rejected the key";
  if (e.stale) text += " (stale: past its cache lifetime)";
  return text;
}

/** Attributed one-line statement, e.g. for the history timeline. */
export function attributedText(e: ChipSource): string {
  const when = formatDate(e.fetched_at).local;
  const who = providerLabel(e.provider);
  if (e.status === "error") return `${who} lookup failed on ${when}`;
  if (e.status === "auth_failed") return `${who} rejected the key on ${when}`;
  if (e.status === "not_found" || !e.found) return `Reported by ${who} on ${when}: no record`;
  if (e.provider === "virustotal" && e.detections) return `Reported by ${who} on ${when}: ${vtEnginesText(e.detections)}`;
  if (e.provider === "abuseipdb" && e.score !== null)
    return `Reported by ${who} on ${when}: AbuseIPDB confidence ${scoreText(e.score)}/100`;
  return `Reported by ${who} on ${when}: listed`;
}

export const RESULT_STATUS_LABELS: Record<TiResult["status"], string> = {
  ok: "answered",
  not_found: "no record",
  error: "lookup error",
  auth_failed: "key rejected",
};

/** Only an `https:` permalink without credentials is ever linked; anything else is dropped. */
export function httpsPermalink(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || !parsed.hostname) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

/** MISP TLP labels; RED / AMBER (incl. AMBER+STRICT) are highlighted. */
export function tlpBadges(summary: ProviderSummary | null | undefined): { label: string; highlight: boolean }[] {
  if (!summary || summary.provider !== "misp") return [];
  return summary.tlp.map((tag) => {
    const label = tag.toUpperCase();
    return { label, highlight: /^TLP:(RED|AMBER)/.test(label) };
  });
}

// ---------------------------------------------------------------------------------------------
// Provider summaries → label / value rows
// ---------------------------------------------------------------------------------------------

export type SummaryField = {
  key: string;
  label: string;
  /** Plain text value. */
  text?: string;
  /** ISO date-time value. */
  iso?: string;
  /** Short list (tags, names), rendered as text chips. */
  list?: string[];
  mono?: boolean;
};

const ABUSEIPDB_CATEGORIES: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

const yesNo = (value: boolean) => (value ? "yes" : "no");

function push(out: SummaryField[], field: SummaryField | null): void {
  if (!field) return;
  if (field.list !== undefined && field.list.length === 0) return;
  out.push(field);
}

function textField(key: string, label: string, value: string | number | null | undefined, mono = false) {
  return value === null || value === undefined || value === "" ? null : { key, label, text: String(value), mono };
}

function dateField(key: string, label: string, iso: string | null | undefined) {
  return iso ? { key, label, iso } : null;
}

/** Each provider's summary fields, labelled with the provider's own terms (text only). */
export function summaryFields(summary: ProviderSummary | null | undefined): SummaryField[] {
  const out: SummaryField[] = [];
  if (!summary) return out;
  switch (summary.provider) {
    case "virustotal": {
      const s = summary.last_analysis_stats;
      if (s) {
        const total = s.malicious + s.suspicious + s.harmless + s.undetected + s.timeout;
        push(out, { key: "engines", label: "Last analysis (VirusTotal)", text: vtEnginesText({ ...s, total }) });
      }
      push(out, textField("reputation", "VirusTotal reputation", summary.reputation));
      const v = summary.total_votes;
      if (v && v.malicious + v.harmless > 0) {
        push(out, {
          key: "votes",
          label: "Community votes",
          text: `${v.malicious + v.harmless} votes: ${v.malicious} report malicious`,
        });
      }
      push(out, textField("label", "Suggested label (VirusTotal)", summary.suggested_threat_label));
      push(out, textField("name", "Meaningful name", summary.meaningful_name));
      push(out, textField("type", "Type", summary.type_tag));
      push(out, textField("as_owner", "AS owner", summary.as_owner));
      push(out, textField("country", "Country", summary.country));
      push(out, dateField("first_submission", "First submission", summary.first_submission_date));
      push(out, dateField("last_submission", "Last submission", summary.last_submission_date));
      push(out, dateField("last_analysis", "Last analysis", summary.last_analysis_date));
      push(out, { key: "tags", label: "Tags", list: summary.tags });
      break;
    }
    case "abuseipdb": {
      if (summary.abuse_confidence_score != null) {
        push(out, { key: "confidence", label: "AbuseIPDB confidence", text: `${summary.abuse_confidence_score}/100` });
      }
      push(out, textField("reports", "Reports", summary.total_reports));
      push(out, textField("users", "Distinct reporters", summary.num_distinct_users));
      push(out, dateField("last_reported", "Last reported", summary.last_reported_at));
      push(out, {
        key: "categories",
        label: "Report categories",
        list: summary.categories.map((c) => ABUSEIPDB_CATEGORIES[c] ?? `category ${c}`),
      });
      push(out, textField("isp", "ISP", summary.isp));
      push(out, textField("usage", "Usage type", summary.usage_type));
      push(out, textField("country", "Country", summary.country_code));
      if (summary.is_tor != null) push(out, { key: "tor", label: "Tor exit node", text: yesNo(summary.is_tor) });
      if (summary.is_whitelisted != null)
        push(out, { key: "allowlisted", label: "On AbuseIPDB's allowlist", text: yesNo(summary.is_whitelisted) });
      break;
    }
    case "urlhaus": {
      push(out, textField("lookup", "Lookup", summary.lookup));
      push(out, textField("url_status", "URL status (URLhaus)", summary.url_status));
      push(out, textField("threat", "Threat (URLhaus)", summary.threat));
      push(out, textField("signature", "Signature (URLhaus)", summary.signature));
      push(out, textField("url_count", "URLs listed", summary.url_count));
      push(out, dateField("date_added", "Date added", summary.date_added));
      push(out, dateField("first_seen", "First seen", summary.first_seen));
      push(out, dateField("last_seen", "Last seen", summary.last_seen));
      push(out, dateField("last_online", "Last online", summary.last_online));
      push(out, textField("spamhaus", "Spamhaus DBL", summary.blacklists?.spamhaus_dbl));
      push(out, textField("surbl", "SURBL", summary.blacklists?.surbl));
      push(out, { key: "tags", label: "Tags", list: summary.tags });
      break;
    }
    case "malwarebazaar": {
      push(out, textField("signature", "Signature (MalwareBazaar)", summary.signature));
      push(out, textField("file_type", "File type", summary.file_type));
      push(out, dateField("first_seen", "First seen", summary.first_seen));
      push(out, dateField("last_seen", "Last seen", summary.last_seen));
      push(out, textField("imphash", "Imphash", summary.imphash, true));
      push(out, textField("ssdeep", "ssdeep", summary.ssdeep, true));
      push(out, textField("tlsh", "TLSH", summary.tlsh, true));
      push(out, { key: "vendor_intel", label: "Vendor intel", list: summary.vendor_intel });
      push(out, { key: "tags", label: "Tags", list: summary.tags });
      break;
    }
    case "otx": {
      push(out, textField("pulses", "Pulses (OTX)", summary.pulse_count));
      push(out, textField("reputation", "OTX reputation", summary.reputation));
      push(out, { key: "pulse_names", label: "Pulse names", list: summary.pulses.map((p) => p.name) });
      push(out, {
        key: "families",
        label: "Malware families (pulses)",
        list: [...new Set(summary.pulses.flatMap((p) => p.malware_families))],
      });
      push(out, {
        key: "validation",
        label: "OTX validation",
        list: summary.validation.map((v) => [v.name, v.source, v.message].filter(Boolean).join(" · ")).filter(Boolean),
      });
      break;
    }
    case "misp": {
      push(out, textField("attributes", "Matching attributes", summary.attribute_count));
      push(out, textField("events", "Events", mispEventCount(summary)));
      push(out, {
        key: "event_info",
        label: "Event info",
        list: [...new Set(summary.attributes.map((a) => a.event_info).filter((v): v is string => !!v))],
      });
      push(out, {
        key: "categories",
        label: "Attribute categories",
        list: [...new Set(summary.attributes.map((a) => a.category).filter((v): v is string => !!v))],
      });
      break;
    }
    case "mock": {
      push(out, textField("behaviour", "Behaviour", summary.behaviour));
      push(out, textField("hits", "Hits", summary.hits));
      push(out, textField("label", "Label (test provider)", summary.label));
      push(out, { key: "tags", label: "Tags", list: summary.tags });
      break;
    }
  }
  return out;
}

/** OTX pulse and MISP galaxy ATT&CK ids carried by a summary. */
export function summaryAttackIds(summary: ProviderSummary | null | undefined): string[] {
  if (!summary || summary.provider !== "otx") return [];
  return summary.pulses.flatMap((p) => p.attack_ids);
}

// ---------------------------------------------------------------------------------------------
// History deltas
// ---------------------------------------------------------------------------------------------

type DeltaSource = Pick<TiResult, "id" | "provider" | "status" | "detections" | "score" | "score_scale" | "found">;

/**
 * Changes between consecutive `ok` answers of one provider (input newest first, as the API
 * returns it): "detections 3 → 12", "score 20 → 87". Keyed by the newer row's id.
 */
export function historyDeltas(items: readonly DeltaSource[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  items.forEach((row, index) => {
    if (row.status !== "ok") return;
    const older = items.slice(index + 1).find((r) => r.provider === row.provider && r.status === "ok");
    if (!older) return;
    const deltas: string[] = [];
    if (row.detections && older.detections && row.detections.malicious !== older.detections.malicious) {
      deltas.push(`detections ${older.detections.malicious} → ${row.detections.malicious}`);
    }
    if (row.score !== null && older.score !== null && row.score !== older.score) {
      const name = row.provider === "abuseipdb" ? "confidence" : row.provider === "virustotal" ? "reputation" : "score";
      deltas.push(`${name} ${scoreText(older.score)} → ${scoreText(row.score)}`);
    }
    if (row.found !== older.found) deltas.push(row.found ? "now listed" : "no longer listed");
    if (deltas.length > 0) out.set(row.id, deltas);
  });
  return out;
}

// ---------------------------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------------------------

export const RUN_STATUS_LABELS: Record<RunStatus, string> = {
  queued: "Queued",
  running: "Running",
  waiting: "Waiting",
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
};

export function isActiveRun(status: RunStatus | undefined): boolean {
  return status === "queued" || status === "running" || status === "waiting";
}

/** Poll back-off while a run is active: 2 s, 3 s, 4.5 s, … capped at 10 s; false once final. */
export function runPollMs(status: RunStatus | undefined, updates: number): number | false {
  if (!isActiveRun(status)) return false;
  return Math.min(10_000, Math.round(2_000 * 1.5 ** Math.max(0, updates - 1)));
}

export const ITEM_REASON_TEXT: Record<ItemReason, string> = {
  rate_limited: "rate limited",
  quota_exhausted: "daily quota reached",
  deadline: "run deadline reached",
  auth_failed: "key rejected by the provider",
};

export function itemReasonText(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return Object.hasOwn(ITEM_REASON_TEXT, reason) ? ITEM_REASON_TEXT[reason as ItemReason] : reason;
}

export type ProviderRunRow = {
  provider: string;
  planned: number;
  answered: number;
  notFound: number;
  errors: number;
  authFailed: number;
  cached: number;
  abandoned: { reason: string; count: number }[];
};

const num = (value: unknown): number => (typeof value === "number" && Number.isFinite(value) ? value : 0);
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Per-provider counts from a run summary (planned at creation, outcomes once final). */
export function runProviderRows(summary: Record<string, unknown> | null | undefined): ProviderRunRow[] {
  const providers = summary?.providers;
  if (!isRecord(providers)) return [];
  return Object.entries(providers)
    .filter((entry): entry is [string, Record<string, unknown>] => isRecord(entry[1]))
    .map(([provider, c]) => ({
      provider,
      planned: num(c.planned),
      answered: num(c.ok),
      notFound: num(c.not_found),
      errors: num(c.error),
      authFailed: num(c.auth_failed),
      cached: num(c.cached),
      abandoned: Object.entries(c)
        .filter(([key, value]) => key.startsWith("abandoned_") && num(value) > 0)
        .map(([key, value]) => ({ reason: key.slice("abandoned_".length), count: num(value) })),
    }))
    .sort((a, b) => PROVIDERS.indexOf(a.provider as ProviderName) - PROVIDERS.indexOf(b.provider as ProviderName));
}

/** Total planned lookups of a run (`summary.items`). */
export function runItemTotal(summary: Record<string, unknown> | null | undefined): number {
  return num(summary?.items);
}

/** Values no requested provider may receive, by reason (`summary.skipped`). */
export function runSkipped(summary: Record<string, unknown> | null | undefined): { reason: string; count: number }[] {
  const skipped = summary?.skipped;
  if (!isRecord(skipped)) return [];
  return Object.entries(skipped)
    .filter(([, value]) => num(value) > 0)
    .map(([reason, value]) => ({ reason, count: num(value) }));
}

/** Why a run ended partial / failed, as sentences (empty for other states). */
export function runOutcomeNotes(run: Pick<TiRun, "status" | "summary">): string[] {
  if (run.status !== "partial" && run.status !== "failed") return [];
  const notes: string[] = [];
  for (const row of runProviderRows(run.summary)) {
    for (const { reason, count } of row.abandoned) {
      notes.push(`${providerLabel(row.provider)}: ${count} not looked up (${itemReasonText(reason) ?? reason}).`);
    }
    if (row.errors > 0) notes.push(`${providerLabel(row.provider)}: ${row.errors} lookup errors.`);
    if (row.authFailed > 0) {
      notes.push(`${providerLabel(row.provider)}: the key was rejected; check it under Settings → Integrations.`);
    }
  }
  if (notes.length === 0) {
    notes.push(
      run.status === "failed" ? "No lookup could be made." : "Some lookups could not be made.",
    );
  }
  if (run.status === "partial") {
    notes.push("Free-tier quotas often make large runs partial; the remaining values can be enriched later.");
  }
  return notes;
}

/** "waiting for rate limit until 14:05" while a run is parked. */
export function waitingText(run: Pick<TiRun, "status" | "resume_at">): string | null {
  if (run.status !== "waiting") return null;
  if (!run.resume_at) return "waiting for rate limit";
  const at = new Date(run.resume_at);
  if (Number.isNaN(at.getTime())) return "waiting for rate limit";
  const hhmm = at.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return `waiting for rate limit until ${hhmm}`;
}

// ---------------------------------------------------------------------------------------------
// MITRE ATT&CK
// ---------------------------------------------------------------------------------------------

const ATTACK_ID = /^T\d{4}(?:\.\d{3})?$/;
export const MAX_ATTACK_IDS = 100;

/** Valid, upper-cased, de-duplicated technique ids (the route rejects a batch with any bad id). */
export function attackIds(values: Iterable<string>): string[] {
  const out: string[] = [];
  for (const raw of values) {
    const id = raw.trim().toUpperCase();
    if (ATTACK_ID.test(id) && !out.includes(id)) out.push(id);
    if (out.length >= MAX_ATTACK_IDS) break;
  }
  return out;
}

/** ATT&CK ids from a finding's `attributes.attack` ("T1055.003, T1620" or a list). */
export function attackIdsFromAttributes(attributes: Record<string, unknown> | null | undefined): string[] {
  const raw = attributes?.attack;
  if (typeof raw === "string") return attackIds(raw.split(/[\s,;]+/));
  if (Array.isArray(raw)) return attackIds(raw.filter((v): v is string => typeof v === "string"));
  return [];
}

export type AttackChipModel = { id: string; text: string; title: string; href: string | null };

/** "T1055 · Process Injection"; revoked → "T1xxx (revoked → T1yyy)"; unknown → raw id. */
export function attackChip(
  id: string,
  label: AttackLabel | undefined,
  meta: Pick<AttackMeta, "version"> | undefined,
): AttackChipModel {
  if (!label) {
    return {
      id,
      text: id,
      title: meta ? `${id}: not in ATT&CK v${meta.version}` : id,
      href: null,
    };
  }
  const name = label.parent_name ? `${label.parent_name}: ${label.name}` : label.name;
  const tactics = label.tactics.map((t) => t.name).join(", ");
  const title = [
    `${label.technique_id} · ${name}`,
    tactics ? `Tactics: ${tactics}` : null,
    label.deprecated ? "Deprecated in ATT&CK" : null,
    label.revoked ? `${id} was revoked and replaced by ${label.technique_id}` : null,
  ]
    .filter(Boolean)
    .join("\n");
  const text = label.revoked ? `${id} (revoked → ${label.technique_id})` : `${label.technique_id} · ${name}`;
  return { id, text, title, href: httpsPermalink(label.url) };
}
