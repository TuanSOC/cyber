from pathlib import Path

import pytest

from app.modules.attack import index
from app.modules.attack.build import build_from_bytes, sha256_hex
from app.modules.attack.schemas import MITRE_NOTICE, AttackIndexFile
from app.modules.attack.service import (
    MAX_IDS,
    InvalidAttackIds,
    lookup_techniques,
    parse_ids,
    techniques_response,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "attack" / "enterprise-attack-mini.json"
)


@pytest.fixture(scope="module")
def mini_index(tmp_path_factory: pytest.TempPathFactory) -> AttackIndexFile:
    data = FIXTURE.read_bytes()
    path = tmp_path_factory.mktemp("attack") / "mini.json"
    path.write_bytes(
        build_from_bytes(
            data,
            version="99.0",
            source_url="https://x.test/b.json",
            expected_sha256=sha256_hex(data),
        )
    )
    return index.load_index(path)


def test_committed_index_is_valid_and_pinned() -> None:
    idx = index.get_index()
    assert index.INDEX_PATH.is_file()
    assert idx.meta.version == index.INDEX_VERSION
    assert idx.meta.source_url.endswith(f"enterprise-attack-{index.INDEX_VERSION}.json")
    assert len(idx.meta.source_sha256) == 64 and idx.meta.attack_spec
    assert len(idx.techniques) > 500
    # v19+ tactics: Defense Evasion is gone, split into Stealth and Defense Impairment.
    assert {"stealth", "defense-impairment"} <= idx.tactics.keys()
    assert "defense-evasion" not in idx.tactics
    assert index.get_index() is idx  # loaded once


def test_committed_index_labels_capa_ids() -> None:
    injection = index.label("T1055")
    assert injection is not None
    assert injection.name == "Process Injection" and not injection.is_subtechnique
    assert injection.tactics and all(t.name for t in injection.tactics)
    assert injection.url == "https://attack.mitre.org/techniques/T1055"

    powershell = index.label("T1059.001")
    assert powershell is not None
    assert (powershell.name, powershell.parent) == ("PowerShell", "T1059")
    assert powershell.parent_name == "Command and Scripting Interpreter"
    assert [t.shortname for t in powershell.tactics] == ["execution"]


def test_committed_index_resolves_revoked_ids() -> None:
    old = index.label("T1086")
    assert old is not None
    assert (old.id, old.technique_id, old.revoked) == ("T1086", "T1059.001", True)
    assert index.label("T9999") is None


def test_label_follows_revocation_chains_and_flags_deprecated(
    mini_index: AttackIndexFile,
) -> None:
    chained = index.label("T1000", mini_index)
    assert chained is not None
    assert (chained.technique_id, chained.name, chained.revoked) == (
        "T1059.001",
        "PowerShell",
        True,
    )
    assert chained.parent_name == "Command and Scripting Interpreter"

    deprecated = index.label("T1064", mini_index)
    assert deprecated is not None
    assert (deprecated.deprecated, deprecated.revoked) == (True, False)

    multi = index.label("T1055.011", mini_index)
    assert multi is not None
    assert [(t.shortname, t.name) for t in multi.tactics] == [
        ("stealth", "Stealth"),
        ("privilege-escalation", "Privilege Escalation"),
    ]


def test_index_file_with_dangling_reference_is_rejected(tmp_path: Path) -> None:
    raw = index.INDEX_PATH.read_text().replace(
        '"revoked_by":"T1059.001"', '"revoked_by":"T0000"', 1
    )
    path = tmp_path / "broken.json"
    path.write_text(raw)
    with pytest.raises(ValueError, match="unknown technique T0000"):
        index.load_index(path)


def test_parse_ids() -> None:
    assert parse_ids(None) == []
    assert parse_ids("") == []
    assert parse_ids(" t1055 , T1059.001,T1055,, ") == ["T1055", "T1059.001"]
    assert len(parse_ids(",".join(f"T{1000 + i}" for i in range(MAX_IDS)))) == MAX_IDS


@pytest.mark.parametrize(
    "raw",
    [
        "T105",
        "T1055.1",
        "TA0002",
        "T1055;DROP",
        "S0001",
        ",".join(f"T{1000 + i}" for i in range(MAX_IDS + 1)),
        "T1055," * 400,
    ],
)
def test_parse_ids_rejects(raw: str) -> None:
    with pytest.raises(InvalidAttackIds) as exc:
        parse_ids(raw)
    assert exc.value.status_code == 422


def test_response_carries_meta_and_notice() -> None:
    empty = techniques_response("")
    assert empty.techniques == [] and empty.unknown == []
    assert empty.meta.version == index.INDEX_VERSION
    assert empty.meta.notice == MITRE_NOTICE
    assert "The MITRE Corporation" in empty.meta.notice

    out = lookup_techniques(["T1055", "T9999", "T1059.001"])
    assert [t.id for t in out.techniques] == ["T1055", "T1059.001"]
    assert out.unknown == ["T9999"]
    body = out.model_dump(mode="json")
    assert body["meta"]["notice"] == MITRE_NOTICE
