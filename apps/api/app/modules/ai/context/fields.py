"""Per-kind field allowlists and raw renderers (M5 phase 4, internal to the builder).

Every renderer is an allowlist: it reads named columns of one row and returns the raw
(untransformed) fields; nothing else of the row can reach the context. Never selected,
anywhere: Authorization / Cookie / Set-Cookie / basic-auth, NTLM or Kerberos user fields,
raw payload bytes, TI keys, analyst notes, provider permalinks, the HTTP referrer and every
URL query value (only the keys are kept).

The only open-ended input is a finding's `attributes` (written by the untrusted analyzers):
flattened into `attributes.<key>` fields when the key matches the RT4 grammar, is not
credential-like and keeps the field name within 64 characters; at most `MAX_ATTRIBUTES`
per finding. Everything else is dropped and counted (`context_stats.dropped_keys`).

The citation verifier does not import this module: a citation's `field` is valid iff it is a
key of the item's `fields` as sent.
"""

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from app.modules.ai.contracts import FieldValue, RefKind

ATTRIBUTE_KEY = re.compile(r"^[a-z0-9_]{1,32}(\.[a-z0-9_]{1,32}){0,2}$")
ATTRIBUTE_PREFIX = "attributes."
MAX_ATTRIBUTES = 16
MAX_FIELD_NAME = 64  # `CitationResult.field` max length
MAX_LIST_ITEMS = 10
# Attribute key segments that are never sent (credentials, payload bytes).
CREDENTIAL_MARKERS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "basic_auth",
    "ntlm",
    "kerberos",
    "krb5",
    "payload",
)

SEVERITY_BY_SURICATA = {1: "high", 2: "medium", 3: "low", 4: "info"}


@dataclass(frozen=True)
class HostList:
    """`name (count), …` aggregates: each name goes through the hostname pipeline."""

    entries: tuple[tuple[str, int], ...]


RawValue = FieldValue | HostList


@dataclass
class RawItem:
    """One selected row before the value transforms."""

    kind: RefKind
    ref_table: str
    ref_id: str
    job_id: Any  # uuid.UUID | None
    fields: dict[str, RawValue]
    host_fields: frozenset[str] = frozenset()
    url_fields: frozenset[str] = frozenset()  # URI-typed: query values and fragment dropped
    dropped_keys: int = 0
    capped: int = 0  # attributes over MAX_ATTRIBUTES (recorded as a truncated field)
    extra: dict[str, Any] = field(default_factory=dict)  # selection-only data, never sent


# Fixed field names per kind (attributes.* comes on top for findings). Credential-free by
# construction; `test_ai_context_fields.py` asserts it.
ALLOWED: dict[RefKind, frozenset[str]] = {
    RefKind.JOB: frozenset(
        {
            "analyzer",
            "profile",
            "created_at",
            "finished_at",
            "capture_format",
            "file_format",
            "results_truncated",
            "capture.packets",
            "capture.bytes",
            "capture.duration_s",
            "capture.first_ts",
            "capture.last_ts",
            "top.dns",
            "top.http_host",
            "top.sni",
        }
    ),
    RefKind.FINDING: frozenset(
        {
            "type",
            "title",
            "severity",
            "confidence",
            "detection_method",
            "summary",
            "ts",
            "last_seen",
            "src",
            "dst",
            "protocol",
            "evidence_refs",
        }
    ),
    RefKind.ALERT: frozenset(
        {"signature", "sid", "rev", "category", "severity", "proto", "src", "dst", "ts"}
        | {"count", "first_ts", "last_ts", "flow_ref"}
    ),
    RefKind.FLOW: frozenset(
        {
            "flow_ref",
            "ts",
            "src",
            "dst",
            "proto",
            "service",
            "duration_s",
            "orig_bytes",
            "resp_bytes",
            "total_bytes",
            "conn_state",
        }
    ),
    RefKind.RECORD: frozenset(
        {
            "kind",
            "ts",
            "src",
            "dst",
            "flow_ref",
            "qname",
            "qtype",
            "rcode",
            "answers",
            "host",
            "method",
            "uri_path",
            "uri_query_keys",
            "status",
            "user_agent",
            "sni",
            "cert_cn",
            "tls_version",
            "ja3",
        }
    ),
    RefKind.IOC: frozenset({"type", "value", "count", "first_seen", "last_seen", "source"}),
    RefKind.TI_RESULT: frozenset(
        {
            "provider",
            "ioc",
            "status",
            "found",
            "score",
            "score_scale",
            "tags",
            "families",
            "attack_ids",
            "fetched_at",
        }
    ),
    RefKind.SAMPLE: frozenset(
        {"size", "md5", "sha1", "sha256", "ssdeep", "file_type", "mime", "entropy", "file_format"}
    ),
    RefKind.PE_SUMMARY: frozenset(
        {
            "machine",
            "bits",
            "is_dll",
            "subsystem",
            "compile_timestamp",
            "entry_section",
            "imphash",
            "rich_header_hash",
            "tls_callbacks",
            "has_authenticode",
            "overlay_size",
            "characteristics",
            "dll_characteristics",
        }
    ),
    RefKind.SIGNATURE: frozenset({"engine", "name", "namespace", "tags"}),
    RefKind.CAPABILITY: frozenset({"name", "namespace", "attack_ids", "mbc", "matches"}),
    RefKind.STRING: frozenset({"value", "encoding", "offset"}),
    RefKind.TIMELINE: frozenset(
        {"ts", "ts_source", "event", "kind", "title", "severity", "src", "dst", "ref"}
    ),
    RefKind.EVIDENCE: frozenset(
        {
            "filename",
            "size",
            "mime",
            "type",
            "sha256",
            "uploaded_at",
            "status",
            "custody.last_verified",
        }
    ),
    RefKind.INVESTIGATION: frozenset(
        {"case_ref", "severity", "status", "created_at", "title", "description"}
    ),
    RefKind.DIGEST_CLAIM: frozenset(
        {"kind", "section", "text", "confidence", "citations", "untrusted", "flags"}
    ),
}
# Open-ended prefixes per kind (names under them are built from trusted enums or checked).
ALLOWED_PREFIXES: dict[RefKind, tuple[str, ...]] = {
    RefKind.JOB: ("count.",),
    RefKind.FINDING: (ATTRIBUTE_PREFIX,),
    RefKind.EVIDENCE: ("custody.",),
}
# Hostname-typed fields: a single-label name there is internal (pseudonymized).
HOST_FIELDS: dict[RefKind, frozenset[str]] = {
    RefKind.RECORD: frozenset({"qname", "host", "sni", "cert_cn"}),
}


# Structural / enum-like fields (types, enums, detection methods, ids, hashes, ATT&CK ids,
# timestamps, counts): sanitized, neutralized, defanged and truncated, never pseudonymized.
# Free-text and value fields (titles, summaries, endpoints, names, paths, URLs, rule
# messages, attributes) can carry internal identities and are pseudonymized.
STRUCTURAL: dict[RefKind, frozenset[str]] = {
    RefKind.JOB: ALLOWED[RefKind.JOB] - {"top.dns", "top.http_host", "top.sni"},
    RefKind.FINDING: frozenset(
        {"type", "severity", "confidence", "detection_method", "ts", "last_seen", "protocol"}
    ),
    RefKind.ALERT: frozenset(
        {"sid", "rev", "severity", "proto", "ts", "count", "first_ts", "last_ts", "flow_ref"}
    ),
    RefKind.FLOW: ALLOWED[RefKind.FLOW] - {"src", "dst"},
    RefKind.RECORD: frozenset(
        {"kind", "ts", "flow_ref", "qtype", "rcode", "method", "status", "tls_version", "ja3"}
    ),
    RefKind.IOC: frozenset({"type", "count", "first_seen", "last_seen", "source"}),
    RefKind.TI_RESULT: ALLOWED[RefKind.TI_RESULT],
    RefKind.SAMPLE: ALLOWED[RefKind.SAMPLE],
    RefKind.PE_SUMMARY: ALLOWED[RefKind.PE_SUMMARY],
    RefKind.SIGNATURE: frozenset({"engine", "namespace", "tags"}),
    RefKind.CAPABILITY: frozenset({"namespace", "attack_ids", "mbc", "matches"}),
    RefKind.STRING: frozenset({"encoding", "offset"}),
    RefKind.TIMELINE: frozenset({"ts", "ts_source", "event", "kind", "severity", "ref"}),
    RefKind.EVIDENCE: frozenset({"size", "mime", "sha256", "uploaded_at", "status"}),
    RefKind.INVESTIGATION: frozenset({"case_ref", "severity", "status", "created_at"}),
    RefKind.DIGEST_CLAIM: ALLOWED[RefKind.DIGEST_CLAIM],
}
STRUCTURAL_PREFIXES: dict[RefKind, tuple[str, ...]] = {
    RefKind.JOB: ("count.",),
    RefKind.EVIDENCE: ("custody.",),
}


def is_structural(kind: RefKind, name: str) -> bool:
    if name in STRUCTURAL.get(kind, frozenset()):
        return True
    return any(name.startswith(p) for p in STRUCTURAL_PREFIXES.get(kind, ()))


# Attribute keys (last segment) whose value is a hostname or a URI: a single-label name there
# is internal; a URI loses its query values and fragment even without `key=`.
ATTRIBUTE_HOST_KEYS = frozenset({"host", "hostname", "server_name", "sni", "qname"})
ATTRIBUTE_URL_KEYS = frozenset(
    {"uri", "url", "path", "request", "referrer", "referer", "location", "uri_path"}
)


def attribute_roles(names: Iterable[str]) -> tuple[frozenset[str], frozenset[str]]:
    """`(host_fields, url_fields)` among the given `attributes.*` field names."""
    hosts: set[str] = set()
    urls: set[str] = set()
    for name in names:
        if not name.startswith(ATTRIBUTE_PREFIX):
            continue
        last = name.rsplit(".", 1)[-1]
        if last in ATTRIBUTE_HOST_KEYS:
            hosts.add(name)
        elif last in ATTRIBUTE_URL_KEYS:
            urls.add(name)
    return frozenset(hosts), frozenset(urls)


def is_allowed(kind: RefKind, name: str) -> bool:
    if name in ALLOWED.get(kind, frozenset()):
        return True
    return any(name.startswith(p) for p in ALLOWED_PREFIXES.get(kind, ()))


# --- value helpers -------------------------------------------------------------------------


def ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def endpoint(ip: object, port: int | None) -> str | None:
    if ip is None:
        return None
    text = str(ip)
    if port is None:
        return text
    return f"[{text}]:{port}" if ":" in text else f"{text}:{port}"


def scalar(value: object) -> FieldValue:
    """A JSON-safe scalar: non-finite floats and decimals become text."""
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else str(value)
    return str(value)


def joined(values: Iterable[object], limit: int = MAX_LIST_ITEMS) -> str | None:
    items = [str(v) for v in values if v is not None and not isinstance(v, dict | list)]
    if not items:
        return None
    head = items[:limit]
    more = len(items) - len(head)
    return ", ".join(head) + (f" (+{more} more)" if more > 0 else "")


def _clean(fields: dict[str, RawValue]) -> dict[str, RawValue]:
    """Drop empty values (an absent field is never citable)."""
    return {k: v for k, v in fields.items() if v is not None and v != ""}


def _credential_like(key: str) -> bool:
    return any(marker in key for marker in CREDENTIAL_MARKERS)


def flatten_attributes(attributes: object) -> tuple[dict[str, FieldValue], int, int]:
    """`({"attributes.<key>": value}, dropped, capped)`. Nested objects are flattened with
    dots (at most three segments in total); lists of scalars are joined."""
    flat: list[tuple[str, FieldValue]] = []
    dropped = 0

    def walk(prefix: str, value: object, depth: int) -> None:
        nonlocal dropped
        if isinstance(value, Mapping):
            if depth >= 3:
                dropped += 1
                return
            for key, inner in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                walk(name, inner, depth + 1)
            return
        if not ATTRIBUTE_KEY.fullmatch(prefix) or _credential_like(prefix):
            dropped += 1
            return
        if len(ATTRIBUTE_PREFIX) + len(prefix) > MAX_FIELD_NAME:
            dropped += 1
            return
        if isinstance(value, list | tuple):
            flat.append((prefix, joined(value)))
        elif isinstance(value, bool | int | float | str | Decimal) or value is None:
            flat.append((prefix, scalar(value)))
        else:
            dropped += 1

    if isinstance(attributes, Mapping):
        walk("", attributes, 0)
    flat = [(k, v) for k, v in flat if v is not None and v != ""]
    flat.sort(key=lambda kv: kv[0])
    kept = flat[:MAX_ATTRIBUTES]
    capped = len(flat) - len(kept)
    return {ATTRIBUTE_PREFIX + k: v for k, v in kept}, dropped, capped


# --- renderers -----------------------------------------------------------------------------


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def job_fields(job: Any, aggregates: Mapping[str, HostList] | None = None) -> dict[str, RawValue]:
    summary: Mapping[str, Any] = job.summary if isinstance(job.summary, Mapping) else {}
    capture = summary.get("capture")
    capture = capture if isinstance(capture, Mapping) else {}
    fields: dict[str, RawValue] = {
        "analyzer": str(job.analyzer),
        "profile": str(job.profile) if job.profile is not None else None,
        "created_at": ts(job.created_at),
        "finished_at": ts(job.finished_at),
        "capture_format": scalar(summary.get("capture_format")),
        "file_format": scalar(summary.get("file_format")),
        "results_truncated": summary.get("truncated")
        if isinstance(summary.get("truncated"), bool)
        else None,
        "capture.packets": _int(capture.get("packets")),
        "capture.bytes": _int(capture.get("bytes")),
        "capture.duration_s": scalar(capture.get("duration_s")),
        "capture.first_ts": scalar(capture.get("first_ts")),
        "capture.last_ts": scalar(capture.get("last_ts")),
    }
    counts = summary.get("counts")
    if isinstance(counts, Mapping):
        for name in sorted(counts):
            value = counts[name]
            if isinstance(name, str) and re.fullmatch(r"[a-z0-9_]{1,32}", name):
                fields[f"count.{name}"] = _int(value)
    for name, entries in (aggregates or {}).items():
        if entries.entries:
            fields[name] = entries
    return _clean(fields)


def finding_fields(row: Any) -> tuple[dict[str, RawValue], int, int]:
    fields: dict[str, RawValue] = {
        "type": row.type,
        "title": row.title,
        "severity": row.severity,
        "confidence": scalar(row.confidence),
        "detection_method": row.detection_method,
        "summary": row.description,
        "ts": ts(row.ts),
        "last_seen": ts(row.last_seen),
        "src": endpoint(row.src_ip, row.src_port),
        "dst": endpoint(row.dst_ip, row.dst_port),
        "protocol": row.protocol,
        "evidence_refs": joined(row.evidence_refs or ()),
    }
    attributes, dropped, capped = flatten_attributes(row.attributes)
    return _clean({**fields, **attributes}), dropped, capped


def alert_fields(
    row: Any,
    *,
    count: int | None = None,
    first: datetime | None = None,
    last: datetime | None = None,
) -> dict[str, RawValue]:
    return _clean(
        {
            "signature": row.signature,
            "sid": row.signature_id,
            "rev": row.rev,
            "category": row.category,
            "severity": SEVERITY_BY_SURICATA.get(row.severity, str(row.severity)),
            "proto": row.proto,
            "src": endpoint(row.src_ip, row.src_port),
            "dst": endpoint(row.dst_ip, row.dst_port),
            "ts": ts(row.ts),
            "flow_ref": row.flow_ref,
            "count": count,
            "first_ts": ts(first) if count is not None and count > 1 else None,
            "last_ts": ts(last) if count is not None and count > 1 else None,
        }
    )


def flow_fields(row: Any) -> dict[str, RawValue]:
    return _clean(
        {
            "flow_ref": row.flow_ref,
            "ts": ts(row.ts),
            "src": endpoint(row.src_ip, row.src_port),
            "dst": endpoint(row.dst_ip, row.dst_port),
            "proto": row.proto,
            "service": row.service,
            "duration_s": scalar(row.duration_s),
            "orig_bytes": row.orig_bytes,
            "resp_bytes": row.resp_bytes,
            "total_bytes": row.total_bytes,
            "conn_state": row.conn_state,
        }
    )


_CN = re.compile(r"(?:^|[,/]\s*)CN\s*=\s*([^,/]+)", re.IGNORECASE)


def split_uri(uri: object) -> tuple[str | None, str | None]:
    """`/a/b?x=1&y=2#frag` -> (`/a/b`, `x, y`): query values and fragments never leave."""
    if not isinstance(uri, str) or not uri:
        return None, None
    path, _, rest = uri.partition("?")
    path = path.partition("#")[0]
    query = rest.partition("#")[0]
    keys = [part.partition("=")[0] for part in query.split("&") if part]
    keys = [k for k in keys if k]
    return path or None, joined(dict.fromkeys(keys), limit=20)


def record_fields(row: Any) -> dict[str, RawValue]:
    d: Mapping[str, Any] = row.details if isinstance(row.details, Mapping) else {}
    common: dict[str, RawValue] = {
        "kind": row.kind,
        "ts": ts(row.ts),
        "src": endpoint(row.src_ip, row.src_port),
        "dst": endpoint(row.dst_ip, row.dst_port),
        "flow_ref": row.flow_ref,
    }
    if row.kind == "dns":
        answers = d.get("answers")
        specific: dict[str, RawValue] = {
            "qname": scalar(d.get("query")),
            "qtype": scalar(d.get("qtype")),
            "rcode": scalar(d.get("rcode")),
            "answers": joined(answers) if isinstance(answers, list) else None,
        }
    elif row.kind == "http":
        path, keys = split_uri(d.get("uri"))
        specific = {
            "host": scalar(d.get("host")),
            "method": scalar(d.get("method")),
            "uri_path": path,
            "uri_query_keys": keys,
            "status": _int(d.get("status_code")),
            "user_agent": scalar(d.get("user_agent")),
        }
    else:
        subject = d.get("cert_subject")
        match = _CN.search(subject) if isinstance(subject, str) else None
        specific = {
            "sni": scalar(d.get("server_name")),
            "cert_cn": match.group(1).strip() if match else None,
            "tls_version": scalar(d.get("version")),
            "ja3": scalar(d.get("ja3")),
        }
    return _clean({**common, **specific})


def ioc_fields(row: Any) -> dict[str, RawValue]:
    return _clean(
        {
            "type": row.type,
            "value": row.value,
            "count": row.count,
            "first_seen": ts(row.first_seen),
            "last_seen": ts(row.last_seen),
            "source": row.source,
        }
    )


def ti_fields(row: Any, ioc_label: str) -> dict[str, RawValue]:
    def strings(value: object) -> str | None:
        return joined(v for v in value if isinstance(v, str)) if isinstance(value, list) else None

    return _clean(
        {
            "provider": row.provider,
            "ioc": ioc_label,
            "status": row.status,
            "found": row.found,
            "score": scalar(row.score),
            "score_scale": row.score_scale,
            "tags": strings(row.tags),
            "families": strings(row.families),
            "attack_ids": strings(row.attack_ids),
            "fetched_at": ts(row.fetched_at),
        }
    )


def sample_fields(row: Any) -> dict[str, RawValue]:
    return _clean(
        {
            "size": row.size,
            "md5": row.md5,
            "sha1": row.sha1,
            "sha256": row.sha256,
            "ssdeep": row.ssdeep,
            "file_type": row.file_type,
            "mime": row.mime,
            "entropy": scalar(row.entropy),
            "file_format": row.file_format,
        }
    )


def pe_fields(pe: Mapping[str, Any]) -> dict[str, RawValue]:
    fields: dict[str, RawValue] = {}
    for name in sorted(ALLOWED[RefKind.PE_SUMMARY]):
        value = pe.get(name)
        fields[name] = joined(value, limit=32) if isinstance(value, list) else scalar(value)
    return _clean(fields)


def signature_fields(row: Any) -> dict[str, RawValue]:
    tags = row.tags if isinstance(row.tags, list) else []
    return _clean(
        {"engine": row.engine, "name": row.name, "namespace": row.namespace, "tags": joined(tags)}
    )


def capability_fields(row: Any) -> dict[str, RawValue]:
    attack = row.attack if isinstance(row.attack, list) else []
    mbc = row.mbc if isinstance(row.mbc, list) else []
    return _clean(
        {
            "name": row.name,
            "namespace": row.namespace,
            "attack_ids": joined(attack, limit=20),
            "mbc": joined(mbc, limit=20),
            "matches": row.matches,
        }
    )


def string_fields(row: Any) -> dict[str, RawValue]:
    return _clean({"value": row.value, "encoding": row.encoding, "offset": row.offset})


def job_timeline_fields(row: Any) -> dict[str, RawValue]:
    return _clean(
        {
            "ts": ts(row.ts),
            "event": row.event,
            "title": row.title,
            "severity": row.severity,
            "src": str(row.src_ip) if row.src_ip is not None else None,
            "dst": str(row.dst_ip) if row.dst_ip is not None else None,
            "ref": row.ref,
        }
    )


def merged_timeline_fields(entry: Any) -> dict[str, RawValue]:
    return _clean(
        {
            "ts": ts(entry.ts),
            "ts_source": entry.ts_source,
            "kind": entry.kind,
            "title": entry.title,
            "severity": entry.severity,
        }
    )


def evidence_fields(
    evidence: Any, sha256: str | None, custody: Mapping[str, int], last_verified: datetime | None
) -> dict[str, RawValue]:
    fields: dict[str, RawValue] = {
        "filename": evidence.original_filename,
        "size": evidence.size_bytes,
        "mime": evidence.detected_mime,
        "type": evidence.detected_description,
        "sha256": sha256,
        "uploaded_at": ts(evidence.uploaded_at),
        "status": str(evidence.status),
        "custody.last_verified": ts(last_verified),
    }
    for action in sorted(custody):
        fields[f"custody.{action}"] = custody[action]
    return _clean(fields)


def investigation_fields(
    investigation: Any, case_ref: str, *, include_text: bool
) -> dict[str, RawValue]:
    fields: dict[str, RawValue] = {
        "case_ref": case_ref,
        "severity": str(investigation.severity),
        "status": str(investigation.status),
        "created_at": ts(investigation.created_at),
    }
    if include_text:
        fields["title"] = investigation.title
        fields["description"] = investigation.description
    return _clean(fields)


def digest_fields(
    *,
    section: str,
    text: str,
    confidence: str,
    citations: Sequence[str],
    flags: Sequence[str],
) -> dict[str, RawValue]:
    """A `D` item: an earlier AI claim, never evidence (RT23 carries the child's flags)."""
    return {
        "kind": "digest_claim",
        "section": section,
        "text": text,
        "confidence": confidence,
        "citations": ", ".join(citations),
        "untrusted": "model_output",
        "flags": ", ".join(flags),
    }
