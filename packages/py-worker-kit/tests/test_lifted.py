"""The helpers M9 phase 1 lifted into the kit (RT8): the M8 masker and the M3 YARA rule files
and severity allow-list. Their full behaviour is tested where they came from (the memory
worker's test_mask.py, the static worker's test_detections.py, through the shims); this pins
the kit API and the shims' identity."""

import hashlib
from pathlib import Path

import pytest

from cyberlab_worker import apisets, mask, yara_rules

REPO = Path(__file__).resolve().parents[3]
BASELINE = REPO / "apps" / "workers" / "static" / "rules" / "yara" / "cyberlab_baseline.yar"


def test_masker_keeps_two_characters_and_the_length() -> None:
    assert mask.mask_value("P@ssw0rd12") == "P@********(10)"
    assert mask.mask_value("abcd") == "****(4)"
    masked = mask.mask(r"net use \\srv\c$ /user:corp\bob Secr3tPass!")
    assert "Secr3tPass!" not in masked
    assert mask.mask(None) == ""


def test_yara_severity_needs_the_allow_list() -> None:
    class Match:
        def __init__(self, name: str, namespace: str, severity: str | None) -> None:
            self.name, self.namespace = name, namespace
            self.meta = {} if severity is None else {"severity": severity}

    rule = "CyberLab_Embedded_PE_In_Overlay"
    ns = "image.cyberlab_baseline"
    assert yara_rules.yara_severity(Match(rule, ns, "high")) == "low"
    ceilings = yara_rules.yara_ceilings({ns: yara_rules.BASELINE_SHA256}, test_rules=False)
    assert yara_rules.yara_severity(Match(rule, ns, "high"), ceilings) == "medium"
    assert yara_rules.yara_severity(Match(rule, ns, "bogus"), ceilings) == "low"
    test_ceilings = yara_rules.yara_ceilings(
        {"test.cyberlab_test": yara_rules.TEST_RULES_SHA256}, test_rules=False
    )
    assert test_ceilings == {}


def test_rule_files_and_hashes(tmp_path: Path) -> None:
    image, test = tmp_path / "image", tmp_path / "test"
    image.mkdir()
    test.mkdir()
    (image / "b.yar").write_bytes(b"rule b { condition: false }")
    (image / "a.yara").write_bytes(b"rule a { condition: false }")
    (test / "t.yar").write_bytes(b"rule t { condition: false }")
    files = yara_rules.rule_files([image, test])
    assert list(files) == ["image.a", "image.b", "test.t"]
    hashes = yara_rules.rule_hashes([image, tmp_path / "missing"])
    assert hashes["image.b"] == hashlib.sha256(b"rule b { condition: false }").hexdigest()


@pytest.mark.skipif(not BASELINE.is_file(), reason="repository rule sources not mounted")
def test_the_baseline_hash_matches_the_rule_file() -> None:
    assert hashlib.sha256(BASELINE.read_bytes()).hexdigest() == yara_rules.BASELINE_SHA256


def test_api_sets_are_the_m3_data() -> None:
    """M10 phase 1 (RT7): the data only; `detect()` stays in the static worker (its tests
    cover the behaviour through the re-export)."""
    by_type = {s.type: s for s in apisets.API_SETS}
    assert set(by_type) == {
        "api_injection",
        "api_keylogging",
        "api_anti_debug",
        "api_credential_access",
        "api_persistence",
        "api_downloader",
    }
    for api_set in apisets.API_SETS:
        assert api_set.any_of, api_set.type
        for combo in api_set.any_of:
            assert combo <= set(api_set.groups), api_set.type
    assert apisets.RUN_KEY_FLAG in by_type["api_persistence"].groups["run_key"]
    assert {"SetWindowsHookExA", "SetWindowsHookExW"} <= by_type["api_keylogging"].groups["hook"]
    names = apisets.api_names()
    assert "WriteProcessMemory" in names and apisets.RUN_KEY_FLAG not in names
