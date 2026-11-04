import json
from pathlib import Path
from typing import Any

import pytest

from app.modules.attack.build import (
    BuildError,
    build_from_bytes,
    build_index,
    output_name,
    sha256_hex,
)
from app.modules.attack.schemas import AttackIndexFile

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "attack" / "enterprise-attack-mini.json"
)
URL = "https://example.test/enterprise-attack-99.0.json"


def _build(data: bytes, **overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "version": "99.0",
        "source_url": URL,
        "expected_sha256": sha256_hex(data),
    }
    kwargs.update(overrides)
    result: dict[str, Any] = json.loads(build_from_bytes(data, **kwargs))
    return result


def _technique(
    name: str,
    tactics: list[str],
    *,
    parent: str | None = None,
    deprecated: bool = False,
    revoked_by: str | None = None,
    url: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "tactics": tactics,
        "is_subtechnique": parent is not None,
        "parent": parent,
        "deprecated": deprecated,
        "revoked_by": revoked_by,
        "url": url,
    }


def test_fixture_bundle_gives_expected_index() -> None:
    data = FIXTURE.read_bytes()
    base = "https://attack.mitre.org/techniques/"
    assert _build(data) == {
        "meta": {
            "version": "99.0",
            "source_url": URL,
            "source_sha256": sha256_hex(data),
            "built_at": "2026-10-13T17:53:10.145Z",
            "attack_spec": "3.3.0",
        },
        "techniques": {
            # Several tactics, in bundle order; the non-mitre kill chain is ignored.
            "T1055": _technique(
                "Process Injection", ["stealth", "privilege-escalation"], url=base + "T1055"
            ),
            "T1055.011": _technique(
                "Extra Window Memory Injection",
                ["stealth", "privilege-escalation"],
                parent="T1055",
                url=base + "T1055/011",
            ),
            "T1059": _technique(
                "Command and Scripting Interpreter", ["execution"], url=base + "T1059"
            ),
            "T1059.001": _technique(
                "PowerShell", ["execution"], parent="T1059", url=base + "T1059/001"
            ),
            "T1562": _technique("Impair Defenses", ["defense-impairment"], url=base + "T1562"),
            "T1064": _technique("Scripting", ["execution"], deprecated=True, url=base + "T1064"),
            "T1086": _technique("PowerShell", [], revoked_by="T1059.001", url=base + "T1086"),
            "T1000": _technique("Old Shell Technique", [], revoked_by="T1086", url=base + "T1000"),
        },
        # The deprecated Defense Evasion tactic is dropped (v19 split it).
        "tactics": {
            "execution": "Execution",
            "privilege-escalation": "Privilege Escalation",
            "stealth": "Stealth",
            "defense-impairment": "Defense Impairment",
        },
    }


def test_output_is_compact_sorted_and_reproducible() -> None:
    data = FIXTURE.read_bytes()
    first = build_from_bytes(data, version="99.0", source_url=URL, expected_sha256=sha256_hex(data))
    second = build_from_bytes(
        data, version="99.0", source_url=URL, expected_sha256=sha256_hex(data).upper()
    )
    assert first == second
    assert first.endswith(b"}\n") and b"\r" not in first and b", " not in first
    assert (
        first
        == (json.dumps(json.loads(first), sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    AttackIndexFile.model_validate_json(first)


def test_sha256_mismatch_aborts() -> None:
    data = FIXTURE.read_bytes()
    with pytest.raises(BuildError, match="sha256 mismatch"):
        _build(data, expected_sha256=sha256_hex(data + b" "))
    with pytest.raises(BuildError, match="64 hex"):
        _build(data, expected_sha256="abc")


def test_version_must_match_the_bundle() -> None:
    with pytest.raises(BuildError, match="pinned version"):
        _build(FIXTURE.read_bytes(), version="20.0")


def test_rejects_non_bundles_and_unknown_tactics() -> None:
    with pytest.raises(BuildError, match="not UTF-8 JSON"):
        _build(b"\xff\xfe")
    bundle = json.loads(FIXTURE.read_bytes())
    with pytest.raises(BuildError, match="not a STIX bundle"):
        build_index({"type": "bundle"}, version="99.0", source_url=URL, source_sha256="0" * 64)
    for obj in bundle["objects"]:
        if obj.get("name") == "Impair Defenses":
            obj["kill_chain_phases"] = [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ]
    with pytest.raises(BuildError, match="unknown tactic 'defense-evasion'"):
        build_index(bundle, version="99.0", source_url=URL, source_sha256="0" * 64)


@pytest.mark.parametrize("version", ["20", "../20.0", "20.0/x", ""])
def test_output_name_rejects_odd_versions(version: str) -> None:
    with pytest.raises(BuildError):
        output_name(version)
    assert output_name("20.0") == "attack_enterprise_v20.0.json"
