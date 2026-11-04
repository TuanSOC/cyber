/**
 * Pure helpers for the PCAP analysis result views. Every value handled here is derived from
 * attacker-controlled packets: it is parsed defensively and only ever rendered as plain text.
 */
import type { Schemas } from "@cyberlab/contracts";

import { toolVersions } from "@/lib/analysis";

export type Finding = Schemas["FindingOut"];
export type FindingSeverity = Schemas["FindingSeverity"];
export type Flow = Schemas["FlowOut"];
export type FlowProto = Schemas["FlowProto"];
export type FlowSort = Schemas["FlowSort"];
export type NetRecord = Schemas["RecordOut"];
export type RecordKind = Schemas["RecordKind"];
export type NetAlert = Schemas["AlertOut"];
export type Ioc = Schemas["IocOut"];
export type IocType = Schemas["IocType"];
export type TimelineItem = Schemas["TimelineOut"];

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const finite = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const text = (value: unknown): string | null => (typeof value === "string" && value !== "" ? value : null);

// ---------------------------------------------------------------------------------------------
// Tabs and URL state

export const RESULT_TABS = [
  ["findings", "Findings"],
  ["alerts", "Alerts"],
  ["flows", "Flows"],
  ["dns", "DNS"],
  ["http", "HTTP"],
  ["tls", "TLS"],
  ["iocs", "IOCs"],
  ["timeline", "Timeline"],
] as const;

export type ResultTab = (typeof RESULT_TABS)[number][0] | "overview";

const TAB_VALUES = new Set<string>(RESULT_TABS.map(([value]) => value));

/** The `tab` search param as a known tab; anything else falls back to the overview. */
export function parseTab(value: string | null | undefined): ResultTab {
  return value && TAB_VALUES.has(value) ? (value as ResultTab) : "overview";
}

/** Query string (with leading "?", or "" when empty) after applying set/delete updates. */
export function withParams(current: string, updates: Record<string, string | number | null | undefined>): string {
  const params = new URLSearchParams(current);
  for (const [key, value] of Object.entries(updates)) {
    if (value === null || value === undefined || value === "") params.delete(key);
    else params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

// ---------------------------------------------------------------------------------------------
// Filters

/** Text filter for an IP: empty = no filter; otherwise it must look like an IPv4/IPv6 address. */
export function parseIpFilter(input: string): { ip?: string; invalid: boolean } {
  const value = input.trim();
  if (!value) return { invalid: false };
  return isIpLike(value) ? { ip: value, invalid: false } : { invalid: true };
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isIpLike(value: string): boolean {
  if (IPV4.test(value)) return true;
  // IPv6 (the API validates it exactly): hex groups, colons, optional dotted IPv4 tail.
  return value.length <= 45 && /^[0-9a-f:.]+$/i.test(value) && (value.match(/:/g)?.length ?? 0) >= 2;
}

export function parsePortFilter(input: string): { port?: number; invalid: boolean } {
  const value = input.trim();
  if (!value) return { invalid: false };
  if (!/^\d{1,5}$/.test(value)) return { invalid: true };
  const port = Number(value);
  return port <= 65535 ? { port, invalid: false } : { invalid: true };
}

/** Free-text search as the API accepts it (trimmed, ≤ 200 chars, no NUL); empty = no filter. */
export function searchTerm(input: string): string | undefined {
  const value = input.replaceAll("\0", "").trim().slice(0, 200);
  return value || undefined;
}

// ---------------------------------------------------------------------------------------------
// Flow links (the flows endpoint filters by ip / port; it has no flow-uid filter)

export type FlowLink = { ip?: string; port?: number; ref?: string };

type EndpointsLike = {
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
};

/**
 * Flows-tab filter that narrows to a flow. For a row's own flow (`exact`), the source ip and
 * source (ephemeral) port nearly identify the connection; for one of several evidence flows of
 * a finding only the source ip and service port are shared. The uid is highlighted when listed.
 */
export function flowLinkFor(e: EndpointsLike, ref: string | null | undefined, exact: boolean): FlowLink {
  const ip = e.src_ip ?? e.dst_ip ?? undefined;
  const port = exact ? (e.src_port ?? e.dst_port ?? undefined) : (e.dst_port ?? undefined);
  return { ip, port, ref: ref ?? undefined };
}

// ---------------------------------------------------------------------------------------------
// Formatting

const COUNT = new Intl.NumberFormat("en-US");
const DECIMAL = new Intl.NumberFormat("en-US", { maximumFractionDigits: 3 });

export function formatCount(value: number | null | undefined): string {
  return value === null || value === undefined || !Number.isFinite(value) ? "—" : COUNT.format(value);
}

export function formatPercent(ratio: number): string {
  if (!Number.isFinite(ratio)) return "—";
  return `${Math.round(Math.min(1, Math.max(0, ratio)) * 100)}%`;
}

/** "10.0.0.1:443", "[2001:db8::1]:53", "10.0.0.1" without a port, "?" when unknown. */
export function endpointText(ip: string | null | undefined, port: number | null | undefined): string {
  const host = ip ? (ip.includes(":") ? `[${ip}]` : ip) : "?";
  return port === null || port === undefined ? host : `${host}:${port}`;
}

/** A finding attribute value (string, number or boolean from the analyzer) as display text. */
export function attributeText(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number") return Number.isFinite(value) ? DECIMAL.format(value) : "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  try {
    return JSON.stringify(value).slice(0, 255);
  } catch {
    return "—";
  }
}

export const FINDING_SEVERITIES: FindingSeverity[] = ["high", "medium", "low", "info"];

/** Suricata alert severity (1 = most severe) on the finding scale, as the analyzer maps it. */
export function alertSeverity(severity: number): FindingSeverity {
  return severity <= 1 ? "high" : severity === 2 ? "medium" : severity === 3 ? "low" : "info";
}

export const FINDING_TYPES: [string, string][] = [
  ["beaconing", "Beaconing"],
  ["port_scan_vertical", "Port scan (vertical)"],
  ["port_scan_horizontal", "Port scan (horizontal)"],
  ["dns_tunneling_like", "DNS tunneling-like"],
  ["dns_nxdomain_burst", "NXDOMAIN burst"],
  ["http_to_ip_literal", "HTTP to IP literal"],
  ["executable_over_http", "Executable over HTTP"],
  ["tls_self_signed", "TLS self-signed"],
  ["tls_expired_certificate", "TLS expired certificate"],
  ["tls_legacy_version", "TLS legacy version"],
  ["service_on_nonstandard_port", "Service on non-standard port"],
];

export const IOC_TYPE_LABELS: Record<IocType, string> = {
  ip: "IP",
  domain: "Domain",
  url: "URL",
  ja3: "JA3",
  ja3s: "JA3S",
  cert_sha256: "Cert SHA-256",
  file_md5: "File MD5",
  file_sha1: "File SHA-1",
  file_sha256: "File SHA-256",
};

// ---------------------------------------------------------------------------------------------
// Engine errors and truncation (header of every result)

const ENGINE_ERROR_TEXT: Record<string, string> = {
  capture_cut_short:
    "The capture ends in the middle of a packet (cut short); everything before the cut was analyzed.",
  zeek_cut_short: "Zeek stopped at the cut in the capture: flows and records cover only the part before it.",
  tshark_failed: "TShark failed: the protocol hierarchy is missing.",
  tshark_timeout: "TShark did not finish in time: the protocol hierarchy is missing.",
  suricata_failed: "Suricata failed: signature alerts and JA3/JA3S fingerprints are missing.",
  suricata_timeout: "Suricata did not finish in time: signature alerts and JA3/JA3S fingerprints are missing.",
  suricata_skipped:
    "Suricata was skipped (no time left in the job): signature alerts and JA3/JA3S fingerprints are missing.",
};

/** Human text for an `engine_errors` code; unknown codes are shown verbatim (as plain text). */
export function engineErrorText(code: string): string {
  return Object.hasOwn(ENGINE_ERROR_TEXT, code)
    ? ENGINE_ERROR_TEXT[code]
    : `An analysis engine reported a problem (${code}).`;
}

const TRUNCATION_LABELS: Record<string, string> = {
  flows: "flows (only the largest flows were kept)",
  conn_log: "Zeek connection log",
  stats_keys: "capture statistics (top talkers and ports)",
  eve_log: "Suricata event log",
  x509_log: "certificate log",
  dns_log: "Zeek DNS log",
  http_log: "Zeek HTTP log",
  tls_log: "Zeek TLS log",
  files_log: "transferred-files log",
  alert: "alerts",
  dns: "DNS records",
  http: "HTTP records",
  tls: "TLS records",
  detector_state: "detector state",
  findings: "findings",
  iocs: "IOCs",
};

export function truncationText(key: string): string {
  const label = Object.hasOwn(TRUNCATION_LABELS, key) ? TRUNCATION_LABELS[key] : key;
  return `Results are partial: ${label} capped.`;
}

// ---------------------------------------------------------------------------------------------
// Summary (analysis_jobs.summary written by ingest)

export type ProtocolStat = { path: string; frames: number; bytes: number };
export type HostStat = { ip: string; bytes: number; packets: number; flows: number };
export type PortStat = { port: number; proto: string; flows: number; bytes: number };

export type CaptureFacts = {
  packets: number | null;
  bytes: number | null;
  firstTs: string | null;
  lastTs: string | null;
  durationS: number | null;
  linkType: string | null;
};

export type CountRow = { key: string; label: string; stored: number };

export type Overview = {
  schemaVersion: string | null;
  captureFormat: string | null;
  capture: CaptureFacts | null;
  hierarchy: ProtocolStat[];
  topSources: HostStat[];
  topDestinations: HostStat[];
  topPorts: PortStat[];
  counts: CountRow[];
  engineErrors: string[];
  truncated: string[];
  toolVersions: [string, string][];
};

// Rows stored per kind (`summary.counts`, computed by ingest). The analyzer's own
// `engine_counts` are untrusted and deliberately not shown.
const COUNT_KINDS: [string, string][] = [
  ["findings", "Findings"],
  ["alerts", "Alerts"],
  ["flows", "Flows"],
  ["dns", "DNS records"],
  ["http", "HTTP records"],
  ["tls", "TLS records"],
  ["iocs", "IOCs"],
  ["timeline", "Timeline entries"],
];

function list<T>(value: unknown, parse: (item: Json) => T | null): T[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const parsed = isRecord(item) ? parse(item) : null;
    return parsed === null ? [] : [parsed];
  });
}

const protocolStat = (item: Json): ProtocolStat | null => {
  const path = text(item.path);
  const frames = finite(item.frames);
  const bytes = finite(item.bytes);
  return path && frames !== null && bytes !== null ? { path, frames, bytes } : null;
};

const hostStat = (item: Json): HostStat | null => {
  const ip = text(item.ip);
  if (!ip) return null;
  return { ip, bytes: finite(item.bytes) ?? 0, packets: finite(item.packets) ?? 0, flows: finite(item.flows) ?? 0 };
};

const portStat = (item: Json): PortStat | null => {
  const port = finite(item.port);
  if (port === null) return null;
  return { port, proto: text(item.proto) ?? "?", flows: finite(item.flows) ?? 0, bytes: finite(item.bytes) ?? 0 };
};

function numbers(value: unknown): Record<string, number> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(
    Object.entries(value).flatMap(([key, n]) => (finite(n) === null ? [] : [[key, n as number]])),
  );
}

export function parseOverview(summary: unknown): Overview {
  const s = isRecord(summary) ? summary : {};
  const capture = isRecord(s.capture) ? s.capture : null;
  const stored = numbers(s.counts);
  return {
    schemaVersion: text(s.schema_version),
    captureFormat: text(s.capture_format),
    capture: capture && {
      packets: finite(capture.packets),
      bytes: finite(capture.bytes),
      firstTs: text(capture.first_ts),
      lastTs: text(capture.last_ts),
      durationS: finite(capture.duration_s),
      linkType: text(capture.link_type),
    },
    hierarchy: list(capture?.protocol_hierarchy, protocolStat),
    topSources: list(capture?.top_sources, hostStat),
    topDestinations: list(capture?.top_destinations, hostStat),
    topPorts: list(capture?.top_ports, portStat),
    counts: COUNT_KINDS.filter(([key]) => key in stored).map(([key, label]) => ({ key, label, stored: stored[key] })),
    engineErrors: Array.isArray(s.engine_errors)
      ? s.engine_errors.filter((code): code is string => typeof code === "string" && code !== "")
      : [],
    truncated: isRecord(s.truncated)
      ? Object.entries(s.truncated)
          .filter(([, flag]) => flag === true)
          .map(([key]) => key)
      : [],
    toolVersions: toolVersions(s),
  };
}

/** Stored finding count from a job summary; null when the summary has none (not ingested). */
export function findingCount(summary: unknown): number | null {
  if (!isRecord(summary) || !isRecord(summary.counts)) return null;
  return finite(summary.counts.findings);
}

export type ProtocolNode = ProtocolStat & { label: string; depth: number; share: number };

/**
 * Protocol hierarchy ("eth", "eth:ip", "eth:ip:tcp", ...) as a depth-first list for indented
 * bars: children sorted by bytes, `share` relative to the largest node. A path whose parent is
 * missing hangs under its nearest listed ancestor (or becomes a root); duplicates are dropped.
 */
export function protocolTree(stats: readonly ProtocolStat[]): ProtocolNode[] {
  const byPath = new Map<string, ProtocolStat>();
  for (const stat of stats) if (!byPath.has(stat.path)) byPath.set(stat.path, stat);

  const parentOf = (path: string): string | null => {
    const parts = path.split(":");
    for (let n = parts.length - 1; n > 0; n -= 1) {
      const candidate = parts.slice(0, n).join(":");
      if (byPath.has(candidate)) return candidate;
    }
    return null;
  };
  const children = new Map<string | null, ProtocolStat[]>();
  for (const stat of byPath.values()) {
    const parent = parentOf(stat.path);
    children.set(parent, [...(children.get(parent) ?? []), stat]);
  }
  const max = Math.max(0, ...[...byPath.values()].map((stat) => stat.bytes));

  const out: ProtocolNode[] = [];
  const visit = (parent: string | null, depth: number) => {
    const kids = [...(children.get(parent) ?? [])].sort((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path));
    for (const stat of kids) {
      const label = stat.path.split(":").at(-1) || stat.path;
      out.push({ ...stat, label, depth, share: max > 0 ? stat.bytes / max : 0 });
      visit(stat.path, depth + 1);
    }
  };
  visit(null, 0);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Record details (network_records.details, one shape per kind)

export type DetailField = { key: string; label: string; value: string; format?: "date" | "mono" };

export function detailText(details: unknown, key: string): string | null {
  if (!isRecord(details)) return null;
  const value = details[key];
  if (typeof value === "string") return value === "" ? null : value;
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : null;
  return null;
}

export function detailList(details: unknown, key: string): string[] {
  if (!isRecord(details) || !Array.isArray(details[key])) return [];
  return (details[key] as unknown[]).flatMap((item) =>
    typeof item === "string" ? [item] : typeof item === "number" && Number.isFinite(item) ? [String(item)] : [],
  );
}

export function detailFlag(details: unknown, key: string): boolean | null {
  if (!isRecord(details)) return null;
  const value = details[key];
  return typeof value === "boolean" ? value : null;
}

type FieldSpec = [key: string, label: string, kind?: "list" | "flag" | "date" | "mono" | "bytes"];

const RECORD_FIELDS: Record<RecordKind, FieldSpec[]> = {
  dns: [
    ["query", "Query"],
    ["qtype", "Type"],
    ["rcode", "Response code"],
    ["answers", "Answers", "list"],
    ["ttls", "TTLs (s)", "list"],
  ],
  http: [
    ["method", "Method"],
    ["host", "Host"],
    ["uri", "URI"],
    ["status_code", "Status"],
    ["user_agent", "User agent"],
    ["referrer", "Referrer"],
    ["resp_mime_types", "Response MIME types", "list"],
    ["request_body_len", "Request body", "bytes"],
    ["response_body_len", "Response body", "bytes"],
  ],
  tls: [
    ["version", "Version"],
    ["server_name", "Server name (SNI)"],
    ["cipher", "Cipher"],
    ["established", "Established", "flag"],
    ["ja3", "JA3", "mono"],
    ["ja3s", "JA3S", "mono"],
    ["cert_subject", "Certificate subject"],
    ["cert_issuer", "Certificate issuer"],
    ["cert_not_before", "Valid from", "date"],
    ["cert_not_after", "Valid until", "date"],
    ["cert_sha256", "Certificate SHA-256", "mono"],
    ["validation_status", "Validation"],
    ["self_signed", "Self-signed", "flag"],
  ],
};

/** The known fields of a record's details, in a fixed order, skipping absent values. */
export function recordFields(kind: RecordKind, details: unknown): DetailField[] {
  const specs = Object.hasOwn(RECORD_FIELDS, kind) ? RECORD_FIELDS[kind] : [];
  return specs.flatMap(([key, label, as]): DetailField[] => {
    if (as === "list") {
      const items = detailList(details, key);
      return items.length ? [{ key, label, value: items.join(", ") }] : [];
    }
    if (as === "flag") {
      const flag = detailFlag(details, key);
      return flag === null ? [] : [{ key, label, value: flag ? "yes" : "no" }];
    }
    const value = detailText(details, key);
    if (value === null) return [];
    if (as === "bytes") return [{ key, label, value: `${formatCount(Number(value))} B` }];
    if (as === "date" || as === "mono") return [{ key, label, value, format: as }];
    return [{ key, label, value }];
  });
}
