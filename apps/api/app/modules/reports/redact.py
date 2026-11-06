"""Redaction profiles of the report snapshot (M6 phase 3; RT2, RT8, RT29).

Both profiles: each AI run's pseudonyms were already reversed with that run's own map by the
builder (separate run trees number independently, RT2).

- `internal`: real values; nothing else changes.
- `external`: **one report-level map**. A single M5 `Pseudonymizer` (org CIDRs / suffixes or
  the defaults) covers the whole snapshot, so a pseudonym means the same value in every
  section and every AI run:
  1. seeded first from structured fields: hostname-typed fields of the case's pcap results
     (DNS query, HTTP host, TLS SNI / certificate CN), the user paths in its static strings,
     the org members' names (custody actors, authors), then every original value of the
     included AI runs' own pseudonym maps (reversed by the builder, RT2: a single-label host
     an analyzer put in a finding attribute reaches the claim text that way);
  2. every string field is walked except an explicit allow-list of enum, hash, UUID, count
     and timestamp fields (`EXEMPT`); planted pseudonym-shaped text is neutralized first;
  3. a whole-token second pass replaces every original value already in the map wherever
     it occurs (single-label hosts such as `FIN-SRV-01`, bare usernames in free text);
  4. notes (their section, the timeline's `note` entries and any citation of an
     `analyst_notes` row, which the builder already refuses to resolve), custody `ip` /
     `user_agent`, deep links and `base_url` are dropped, and actors and authors become role
     labels;
  5. `ioc_key` (an unsalted sha256 of type and value, so an internal value could be
     recovered by brute force) becomes HMAC-SHA256 under a random per-build key that is never
     stored: the IOC and TI sections still join on it inside the version, nothing outside it.
  The map is never stored (RT29). Pattern-based redaction stays a residual (RT8).
"""

import hashlib
import hmac
import ipaddress
import re
import secrets
import uuid
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from cyberlab_jobs.report import ANALYST_TEXT_CHARS, ReportSnapshot, truncate_text
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai import postprocess
from app.modules.ai import text as ai_text
from app.modules.ai.context.pseudonymize import Pseudonymizer, neutralize
from app.modules.ai.models import AiOrgSettings
from app.modules.memory_analysis.models import MemoryProcess
from app.modules.organizations.models import OrganizationMember
from app.modules.pcap_analysis.models import NetworkRecord
from app.modules.reports.citations import CaseScope, fields_sha256
from app.modules.static_analysis.models import MalwareString
from app.modules.users.models import User

# Field names (at any depth) that hold enums, hashes, UUIDs, counts or timestamps: never
# pseudonymized. Every other string is walked.
EXEMPT = frozenset(
    {
        "schema_version",
        "report_id",
        "version",
        "template",
        "tlp",
        "profile",
        "finalized_at",
        "investigation_id",
        "case_ref",
        "status",
        "severity",
        "created_at",
        "updated_at",
        "from_status",
        "to_status",
        "occurred_at",
        "evidence_id",
        "size_bytes",
        "sha256",
        "sha1",
        "md5",
        "uploaded_at",
        "verification",
        "last_verified_at",
        "action",
        "job_id",
        "job_ids",
        "analyzer",
        "finished_at",
        "tool_versions",
        "finding_id",
        "category",
        "attack_ids",
        "score",
        "alert_id",
        "ts",
        "signature_id",
        "proto",
        "count",
        "ioc_type",
        "ioc_key",
        "count_jobs",
        "first_seen",
        "last_seen",
        "provider",
        "found",
        "score_scale",
        "fetched_at",
        "technique_id",
        "tactics",
        "revoked",
        "ts_source",
        "kind",
        "ref_kind",
        "ref_id",
        "ref_table",
        "note_id",
        "claim_id",
        "section",
        "confidence",
        "flags",
        "run_id",
        "task",
        "model",
        "prompt_version",
        "context_sha256",
        "overall_confidence",
        "omitted_unsupported",
        "omitted_flagged",
        "total",
        "fields_sha256",
        "source",
        "snapshot_sha256_short",
        "status_history_total",
        "dropped_out_of_scope",
        "cite_no",
        "cite_nos",
        "disclaimer",
    }
)
# Hostname-typed values (citation field copies, attributes): a single-label name is a host.
HOST_FIELDS = frozenset({"qname", "host", "sni", "cert_cn", "hostname", "server_name"})
HOST_IOC_TYPES = frozenset({"domain", "hostname", "host", "fqdn"})
ROLE_LABELS = {
    "owner": "Owner",
    "admin": "Administrator",
    "analyst": "Analyst",
    "viewer": "Viewer",
}
FORMER_MEMBER = "Former member"
MIN_TOKEN = 3
SEED_ROWS = 5_000
# Whole-token edges: an original never matches inside a longer word or a pseudonym.
_EDGE = r"(?<![A-Za-z0-9_])({})(?![A-Za-z0-9_])"


async def _org_settings(session: AsyncSession, org_id: uuid.UUID) -> tuple[list[Any], list[Any]]:
    row = await session.scalar(select(AiOrgSettings).where(AiOrgSettings.organization_id == org_id))
    if row is None:
        return [], []
    return list(row.internal_cidrs or []), list(row.internal_suffixes or [])


async def _members(session: AsyncSession, org_id: uuid.UUID) -> list[tuple[str, str, str]]:
    """(display name, email, role) of every member of the org."""
    rows = await session.execute(
        select(User.display_name, User.email, OrganizationMember.role)
        .select_from(OrganizationMember)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == org_id)
        .order_by(User.display_name, User.email)
    )
    return [(name or "", str(email or ""), str(getattr(r, "value", r))) for name, email, r in rows]


def _seed_user(p: Pseudonymizer, name: str) -> None:
    clean = name.strip()
    if len(clean) >= MIN_TOKEN:
        p._name("user", clean.lower(), clean)


async def seed(
    session: AsyncSession, scope: CaseScope, p: Pseudonymizer, members: Iterable[tuple[str, str]]
) -> None:
    """Register the structured internal values first (RT8), in a fixed order."""
    for name, email in members:
        _seed_user(p, name)
        local = email.partition("@")[0]
        _seed_user(p, local)
    pcap_jobs = sorted(j for j, a in scope.jobs.items() if a == "pcap")
    if pcap_jobs:
        records = await session.scalars(
            select(NetworkRecord)
            .where(
                NetworkRecord.organization_id == scope.org_id, NetworkRecord.job_id.in_(pcap_jobs)
            )
            .order_by(NetworkRecord.ts, NetworkRecord.id)
            .limit(SEED_ROWS)
        )
        for record in records:
            details = record.details if isinstance(record.details, Mapping) else {}
            for key in ("query", "host", "server_name"):
                value = details.get(key)
                if isinstance(value, str) and value:
                    p.host_field(value)
    static_jobs = sorted(j for j, a in scope.jobs.items() if a == "static")
    if static_jobs:
        strings = await session.scalars(
            select(MalwareString.value)
            .where(
                MalwareString.organization_id == scope.org_id,
                MalwareString.job_id.in_(static_jobs),
            )
            .order_by(MalwareString.id)
            .limit(SEED_ROWS)
        )
        for value in strings:
            if isinstance(value, str) and value:
                p.text(value)
    # M8 (RT1): memory jobs seed from their process command lines, like static strings (the
    # internal hosts and users they name); bounded the same way.
    memory_jobs = sorted(j for j, a in scope.jobs.items() if a == "memory")
    if memory_jobs:
        cmdlines = await session.scalars(
            select(MemoryProcess.cmdline)
            .where(
                MemoryProcess.organization_id == scope.org_id,
                MemoryProcess.job_id.in_(memory_jobs),
                MemoryProcess.cmdline.is_not(None),
            )
            .order_by(MemoryProcess.id)
            .limit(SEED_ROWS)
        )
        for value in cmdlines:
            if isinstance(value, str) and value:
                p.text(value)


def seed_run_maps(p: Pseudonymizer, originals: Iterable[tuple[str, str]]) -> None:
    """Register every original value of the included AI runs' pseudonym maps, in its own
    category: the run already decided it was internal (a single-label host from a finding
    attribute, a bare username), so the report map must cover it too (RT2)."""
    for pseudonym, original in originals:
        clean = original.strip()
        if not clean:
            continue
        prefix = pseudonym.rsplit("_", 1)[0]
        if prefix == "INT_HOST":
            p._name("host", clean.rstrip(".").lower(), clean)
        elif prefix == "USER":
            _seed_user(p, clean)
        elif prefix == "INT_IP":
            try:
                address = ipaddress.ip_address(clean.strip("[]"))
            except ValueError:
                p.text(clean)
                continue
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            p._name("ip", str(address), clean)


def _opaque_ioc_keys(data: dict[str, Any]) -> None:
    """`ioc_key` -> HMAC-SHA256 under a key that lives only for this build (never stored):
    consistent across the IOC and TI sections of the version, unlinkable outside it."""
    key = secrets.token_bytes(32)
    mapped: dict[str, str] = {}

    def opaque(value: str) -> str:
        found = mapped.get(value)
        if found is None:
            found = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()
            mapped[value] = found
        return found

    for name in ("iocs", "ti"):
        for item in data[name]["items"]:
            item["ioc_key"] = opaque(item["ioc_key"])
    for item in data["citations"]["items"]:
        if "ioc_key" in item["fields"]:
            item["fields"]["ioc_key"] = opaque(item["fields"]["ioc_key"])


class _Redactor:
    def __init__(self, p: Pseudonymizer) -> None:
        self.p = p
        self.second: Callable[[str], str] = lambda text: text

    def first(self, value: str, *, host: bool) -> str:
        """Refang, pseudonymize, and defang again when the value was defanged by the builder
        (analyst text is not defanged, so for it the refang is a no-op)."""
        value, _ = neutralize(value)
        plain = ai_text.refang(value)
        out = self.p.host_field(plain) if host else self.p.text(plain)
        if out == plain:
            return value
        return postprocess.defang_all(out) if plain != value else out

    @staticmethod
    def _is_host(key: str | None, parent: str | None) -> bool:
        if key == "_host":
            return True
        return parent == "fields" and key is not None and key.rsplit(".", 1)[-1] in HOST_FIELDS

    def walk(self, node: Any, key: str | None = None, parent: str | None = None) -> Any:
        if isinstance(node, dict):
            host_ioc = parent == "iocs_item" and str(node.get("ioc_type", "")).lower() in (
                HOST_IOC_TYPES
            )
            out: dict[str, Any] = {}
            for k, v in node.items():
                if k in EXEMPT and key != "fields":
                    out[k] = v
                elif host_ioc and k == "value":
                    out[k] = self.walk(v, "_host", None)
                else:
                    out[k] = self.walk(v, k, key)
            return out
        if isinstance(node, list):
            child = "iocs_item" if key == "items" and parent == "iocs" else parent
            return [self.walk(v, key, child) for v in node]
        if isinstance(node, str):
            return self.first(node, host=self._is_host(key, parent))
        return node

    def finish(self, node: Any, key: str | None = None) -> Any:
        """The second pass, over the same strings as the walk."""
        if isinstance(node, dict):
            return {
                k: (v if k in EXEMPT and key != "fields" else self.finish(v, k))
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [self.finish(v, key) for v in node]
        if isinstance(node, str):
            return self.second(node)
        return node

    def build_second(self) -> None:
        originals: dict[str, str] = {}
        for pseudonym, original in self.p.mapping.items():
            for variant in {original, original.rstrip("."), ai_text.defang(original)}:
                if len(variant) >= MIN_TOKEN and variant.lower() not in originals:
                    originals[variant.lower()] = pseudonym
        if not originals:
            return
        ordered = sorted(originals, key=len, reverse=True)
        pattern = re.compile(_EDGE.format("|".join(re.escape(o) for o in ordered)), re.IGNORECASE)
        self.second = lambda text: pattern.sub(lambda m: originals[m.group(1).lower()], text)


def _fit(data: dict[str, Any]) -> None:
    """Pseudonyms can be longer than the values they replace: keep every field in its cap
    (only reached by pathological input; analyst text is otherwise never cut)."""
    report, case = data["report"], data["case"]
    report["title"] = report["title"][:200] or "Report"
    if report.get("distribution"):
        report["distribution"] = report["distribution"][:500]
    if report.get("change_note"):
        report["change_note"] = report["change_note"][:500]
    case["title"] = case["title"][:200] or "Case"
    case["description"] = case["description"][:ANALYST_TEXT_CHARS]
    for event in case["status_history"]:
        if event.get("reason"):
            event["reason"] = event["reason"][:500]
    for name in data["sections"]:
        data["sections"][name] = data["sections"][name][:ANALYST_TEXT_CHARS]
    for item in data["attack"]["items"]:
        item["rationale"] = item["rationale"][:ANALYST_TEXT_CHARS]
    for item in data["iocs"]["items"]:
        item["collections"] = [c[:200] for c in item["collections"]]
    for item in data["citations"]["items"]:
        item["fields"] = {k: truncate_text(v) for k, v in item["fields"].items()}


def _role(name: str, roles: Mapping[str, str]) -> str:
    return ROLE_LABELS.get(roles.get(name, ""), FORMER_MEMBER)


async def redact(
    session: AsyncSession,
    scope: CaseScope,
    snapshot: ReportSnapshot,
    run_originals: Iterable[tuple[str, str]] = (),
) -> ReportSnapshot:
    """The snapshot as signed for its profile (`snapshot.report.profile`).
    `run_originals`: the (pseudonym, original) pairs of the AI run maps the builder
    reversed (`BuiltSnapshot.run_originals`)."""
    if snapshot.report.profile != "external":
        return snapshot
    cidrs, suffixes = await _org_settings(session, scope.org_id)
    p = Pseudonymizer(enabled=True, internal_cidrs=cidrs, internal_suffixes=suffixes)
    members = await _members(session, scope.org_id)
    roles: dict[str, str] = {}
    for name, _, role in members:
        roles.setdefault(name.strip(), role)
    await seed(session, scope, p, [(n, e) for n, e, _ in members])
    seed_run_maps(p, run_originals)

    data = snapshot.model_dump(mode="json")
    # Actors and authors become role labels (before the walk: they are not free text).
    data["report"]["generated_by"] = _role(data["report"]["generated_by"], roles)
    data["report"]["base_url"] = None
    for event in data["case"]["status_history"]:
        event["actor"] = _role(event["actor"], roles)
    for item in data["evidence"]["items"]:
        item["uploaded_by"] = _role(item["uploaded_by"], roles)
    for item in data["custody"]["items"]:
        item["actor"] = _role(item["actor"], roles)
        item["ip"] = None
        item["user_agent"] = None
    data["notes"] = {"items": [], "total": 0}
    # Notes leave the external profile everywhere, not only their section: the timeline's
    # `note` entries carry the body as their title, and a cited note copies its fields.
    timeline = data["timeline"]
    kept = [item for item in timeline["items"] if item["kind"] != "note"]
    timeline["total"] = max(0, timeline["total"] - (len(timeline["items"]) - len(kept)))
    timeline["items"] = kept
    for item in data["citations"]["items"]:
        item["path"] = None
        if item["kind"] == "note" or item["ref_table"] == "analyst_notes":
            item["fields"] = {}
    labels = set(ROLE_LABELS.values()) | {FORMER_MEMBER}

    r = _Redactor(p)
    walked = r.walk(data)
    r.build_second()
    final: dict[str, Any] = r.finish(walked)
    # Role labels stay as written (a member could be named "Analyst").
    final["report"]["generated_by"] = data["report"]["generated_by"]
    for src, dst in zip(
        data["case"]["status_history"], final["case"]["status_history"], strict=True
    ):
        dst["actor"] = src["actor"] if src["actor"] in labels else dst["actor"]
    for name in ("evidence", "custody"):
        key = "uploaded_by" if name == "evidence" else "actor"
        for src, dst in zip(data[name]["items"], final[name]["items"], strict=True):
            dst[key] = src[key]
    _fit(final)
    _opaque_ioc_keys(final)
    for item in final["citations"]["items"]:
        item["fields_sha256"] = fields_sha256(item["fields"])
    return ReportSnapshot.model_validate(final)
