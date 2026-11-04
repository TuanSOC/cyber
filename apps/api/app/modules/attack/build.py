"""Pure builder of the compact Enterprise ATT&CK index (stdlib only).

`scripts/build_attack_index.py` downloads a pinned `mitre-attack/attack-stix-data` bundle on a
maintainer's host and calls `build_from_bytes`. Nothing here touches the network, so the same
code is tested in `api-test` against a tiny committed STIX fixture.

Tactics come only from the bundle (`x-mitre-tactic` objects and the `mitre-attack`
`kill_chain_phases` of each technique), never from capa strings: since ATT&CK v19, Defense
Evasion (TA0005) is split into "Stealth" (TA0005, shortname `stealth`) and "Defense Impairment"
(TA0112, shortname `defense-impairment`), so hard-coded tactic names would go stale.
"""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

KILL_CHAIN = "mitre-attack"
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^\d{1,3}\.\d{1,3}$")


class BuildError(Exception):
    """The bundle is not what the pin says, or not a usable Enterprise ATT&CK bundle."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected: str) -> str:
    expected = expected.strip().lower()
    if not SHA256_HEX.fullmatch(expected):
        raise BuildError("expected sha256 must be 64 hex characters")
    actual = sha256_hex(data)
    if actual != expected:
        raise BuildError(f"sha256 mismatch: expected {expected}, got {actual}")
    return actual


def _mitre_ref(obj: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for ref in obj.get("external_references") or ():
        if isinstance(ref, Mapping) and ref.get("source_name") == KILL_CHAIN:
            return ref
    return None


def _objects(bundle: Mapping[str, Any], kind: str) -> Iterable[Mapping[str, Any]]:
    return (o for o in bundle["objects"] if isinstance(o, Mapping) and o.get("type") == kind)


def _collection(bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    collections = list(_objects(bundle, "x-mitre-collection"))
    if len(collections) != 1:
        raise BuildError(f"expected one x-mitre-collection, found {len(collections)}")
    return collections[0]


def _tactics(bundle: Mapping[str, Any]) -> dict[str, str]:
    tactics: dict[str, str] = {}
    for tactic in _objects(bundle, "x-mitre-tactic"):
        if tactic.get("revoked") or tactic.get("x_mitre_deprecated"):
            continue
        shortname, name = tactic.get("x_mitre_shortname"), tactic.get("name")
        if not isinstance(shortname, str) or not isinstance(name, str):
            raise BuildError(f"tactic {tactic.get('id')!r} lacks a shortname or name")
        tactics[shortname] = name
    if not tactics:
        raise BuildError("bundle has no tactics")
    return tactics


def _better(new: Mapping[str, Any], old: Mapping[str, Any]) -> bool:
    """Two STIX objects with one T-id: prefer the live one, then the most recently modified."""

    def rank(o: Mapping[str, Any]) -> tuple[bool, bool, str]:
        return (
            not o.get("revoked"),
            not o.get("x_mitre_deprecated"),
            str(o.get("modified", "")),
        )

    return rank(new) > rank(old)


def build_index(
    bundle: Mapping[str, Any], *, version: str, source_url: str, source_sha256: str
) -> dict[str, Any]:
    if not isinstance(bundle, Mapping) or not isinstance(bundle.get("objects"), list):
        raise BuildError("not a STIX bundle")
    output_name(version)  # validates the version format
    collection = _collection(bundle)
    bundle_version = collection.get("x_mitre_version")
    if bundle_version != version:
        raise BuildError(f"bundle is ATT&CK {bundle_version!r}, pinned version is {version!r}")
    tactics = _tactics(bundle)

    # T-id per STIX id, keeping one object per T-id.
    by_tid: dict[str, Mapping[str, Any]] = {}
    for obj in _objects(bundle, "attack-pattern"):
        ref = _mitre_ref(obj)
        tid = ref.get("external_id") if ref else None
        if not isinstance(tid, str) or not TECHNIQUE_ID.fullmatch(tid):
            continue
        if tid not in by_tid or _better(obj, by_tid[tid]):
            by_tid[tid] = obj
    if not by_tid:
        raise BuildError("bundle has no techniques")
    tid_of = {obj["id"]: tid for tid, obj in by_tid.items()}

    parent_of: dict[str, str] = {}
    revoked_by: dict[str, str] = {}
    for rel in _objects(bundle, "relationship"):
        if rel.get("revoked") or rel.get("x_mitre_deprecated"):
            continue
        source, target = tid_of.get(rel.get("source_ref")), tid_of.get(rel.get("target_ref"))
        if source is None or target is None or source == target:
            continue
        if rel.get("relationship_type") == "subtechnique-of":
            parent_of[source] = target
        elif rel.get("relationship_type") == "revoked-by":
            revoked_by[source] = target

    techniques: dict[str, dict[str, Any]] = {}
    for tid, obj in by_tid.items():
        name = obj.get("name")
        if not isinstance(name, str) or not name:
            raise BuildError(f"{tid} has no name")
        technique_tactics: list[str] = []
        for phase in obj.get("kill_chain_phases") or ():
            if not isinstance(phase, Mapping) or phase.get("kill_chain_name") != KILL_CHAIN:
                continue
            shortname = phase.get("phase_name")
            if shortname in technique_tactics:
                continue
            if shortname not in tactics:
                raise BuildError(f"{tid} uses unknown tactic {shortname!r}")
            technique_tactics.append(shortname)
        is_sub = bool(obj.get("x_mitre_is_subtechnique")) or "." in tid
        parent = parent_of.get(tid) or (tid.split(".")[0] if is_sub else None)
        if parent is not None and parent not in by_tid:
            parent = None
        ref = _mitre_ref(obj)
        url = ref.get("url") if ref else None
        techniques[tid] = {
            "name": name,
            "tactics": technique_tactics,
            "is_subtechnique": is_sub,
            "parent": parent,
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "revoked_by": revoked_by.get(tid) if obj.get("revoked") else None,
            "url": url if isinstance(url, str) else "",
        }

    return {
        "meta": {
            "version": version,
            "source_url": source_url,
            "source_sha256": source_sha256,
            # The bundle's release timestamp, not the wall clock: the same input always gives
            # byte-identical output, so the committed index is reproducible.
            "built_at": str(collection.get("modified", "")),
            "attack_spec": str(collection.get("x_mitre_attack_spec_version", "")),
        },
        "techniques": techniques,
        "tactics": tactics,
    }


def render(index: Mapping[str, Any]) -> bytes:
    """Compact, key-sorted, ASCII JSON with a trailing LF: stable bytes for a stable input."""
    text = json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return (text + "\n").encode("ascii")


def build_from_bytes(data: bytes, *, version: str, source_url: str, expected_sha256: str) -> bytes:
    """Hash-check the downloaded bundle, then build and render the index (aborts on mismatch)."""
    digest = verify_sha256(data, expected_sha256)
    try:
        bundle = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BuildError(f"bundle is not UTF-8 JSON: {exc}") from exc
    return render(build_index(bundle, version=version, source_url=source_url, source_sha256=digest))


def output_name(version: str) -> str:
    if not VERSION.fullmatch(version):
        raise BuildError(f"version must look like 20.0, got {version!r}")
    return f"attack_enterprise_v{version}.json"
