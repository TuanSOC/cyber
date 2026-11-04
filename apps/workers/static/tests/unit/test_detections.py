"""Detector logic on hand-made facts (no engines): combinations, severity policy, wording."""

import hashlib
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cyberlab_jobs.static import CapabilityRecord, PeInfo, ResourceRecord, SectionRecord
from cyberlab_jobs.static import SignatureMatch as Match

from static_worker.detections import apis
from static_worker.detections.base import SEVERITY_RANK, TEMPLATES, Finding
from static_worker.detections.run import Detection
from static_worker.detections.signatures import (
    BASELINE_SHA256,
    TEST_RULES_SHA256,
    YARA_SEVERITY_ALLOWLIST,
    YARA_TEST_ALLOWLIST,
    capability_findings,
    clamav_severity,
    signature_findings,
    yara_ceilings,
    yara_severity,
)
from static_worker.detections.structure import Structure, anomalies, packer

NOW = datetime(2026, 11, 5, tzinfo=UTC)
VERDICT = re.compile(r"malicious|is malware|malware detected|\bvirus\b|infected", re.I)
METHOD = re.compile(r"^[a-z_]{1,32}:[a-z0-9_.\-]{1,64}@\d{1,4}$")


def pe_info(**kw: object) -> PeInfo:
    base: dict[str, object] = {
        "machine": "i386", "bits": 32, "is_dll": False, "entry_point": 0x1000,
        "entry_section": ".text", "image_base": 0x400000, "compile_timestamp": 1_600_000_000,
    }  # fmt: skip
    return PeInfo.model_validate(base | kw)


def section(
    name: str, entropy: float = 5.0, flags: tuple[str, ...] = ("read",), **kw: int
) -> SectionRecord:
    values = {"index": 0, "virtual_address": 0x1000, "virtual_size": 0x1000, "raw_size": 0x1000}
    return SectionRecord(name=name, entropy=entropy, flags=list(flags), **(values | kw))


def test_templates_never_use_verdict_words() -> None:
    for kind, (title, description) in TEMPLATES.items():
        assert not VERDICT.search(title), kind
        assert not VERDICT.search(description), kind
        assert re.fullmatch(r"[a-z][a-z0-9_]{0,63}", kind)


@pytest.mark.parametrize(
    "api", sorted({a for s in apis.API_SETS for g in s.groups.values() for a in g})
)
def test_a_single_api_never_yields_a_finding(api: str) -> None:
    assert apis.detect({api}) == []


def test_api_sets_need_combinations() -> None:
    assert apis.detect({"OpenProcess", "VirtualAllocEx", "WriteProcessMemory"}) == []
    [injection] = apis.detect({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"})
    assert injection.type == "api_injection" and injection.severity == "medium"
    assert injection.refs == [
        "import:VirtualAllocEx", "import:WriteProcessMemory", "import:CreateRemoteThread",
    ] or set(injection.refs) == {
        "import:VirtualAllocEx", "import:WriteProcessMemory", "import:CreateRemoteThread",
    }  # fmt: skip
    # Registry writes alone are ordinary; with a Run-key path in the strings they are not.
    assert apis.detect({"RegSetValueExA", "RegCreateKeyExA"}) == []
    [persistence] = apis.detect({"RegSetValueExA", apis.RUN_KEY_FLAG})
    assert persistence.type == "api_persistence"
    # MSVC runtimes import IsDebuggerPresent + OutputDebugString: not anti-debugging.
    assert apis.detect({"IsDebuggerPresent", "OutputDebugStringW", "QueryPerformanceCounter"}) == []


def test_import_and_structure_findings_never_exceed_medium() -> None:
    every_api = {a for s in apis.API_SETS for g in s.groups.values() for a in g}
    raw = apis.detect(every_api)
    assert {f.type for f in raw} == {s.type for s in apis.API_SETS}
    s = Structure(
        "pe", 100_000, 7.9, pe=pe_info(entry_section="UPX1", compile_timestamp=1, tls_callbacks=3,
                                       overlay_size=90_000),
        sections=[section("UPX0", 0.0, ("execute",), raw_size=0, virtual_size=0x40000),
                  section("UPX1", 7.99, ("execute",))],
        resources=[ResourceRecord(type="RT_RCDATA", size=50_000, entropy=7.99)],
        imports={"LoadLibraryA", "GetProcAddress"}, import_count=2,
    )  # fmt: skip
    raw += packer(s) + anomalies(s, NOW.timestamp())
    assert raw and all(SEVERITY_RANK[f.severity] <= SEVERITY_RANK["medium"] for f in raw)
    assert all(f.method.startswith("heuristic:") for f in raw)


def test_packer_needs_two_indicators() -> None:
    one = Structure("pe", 10_000, 6.0, pe=pe_info(), sections=[section("UPX0")], import_count=40)
    assert packer(one) == []
    two = Structure("pe", 10_000, 6.0, pe=pe_info(entry_section="UPX0"), sections=[section("UPX0")],
                    import_count=40)  # fmt: skip
    [finding] = packer(two)
    assert finding.severity == "low" and finding.attributes["indicator_count"] == 2


def test_anomaly_rules() -> None:
    zero = Structure("pe", 10_000, 5.0, pe=pe_info(compile_timestamp=0))
    assert anomalies(zero, NOW.timestamp()) == []  # reproducible builds zero the timestamp
    old = anomalies(
        Structure("pe", 1, 5.0, pe=pe_info(compile_timestamp=708_992_537)), NOW.timestamp()
    )
    assert [f.type for f in old] == ["timestamp_anomaly"]
    icon = ResourceRecord(type="RT_ICON", size=90_000, entropy=7.9)
    icons = Structure("pe", 1, 5.0, pe=pe_info(), resources=[icon])
    assert anomalies(icons, NOW.timestamp()) == []  # compressed images are expected
    small = anomalies(Structure("pe", 1, 5.0, pe=pe_info(overlay_size=100)), NOW.timestamp())
    assert [(f.type, f.severity) for f in small] == [("overlay", "info")]


def test_clamav_and_yara_severity_policy() -> None:
    assert clamav_severity("PUA.Win.Packer.Upx-1") == "medium"
    assert clamav_severity("Heuristics.Encrypted.Zip") == "info"
    assert clamav_severity("Win.Test.EICAR_HDB-1") == "high"

    def yara(name: str, ns: str, severity: str | None) -> Match:
        meta = {"severity": severity} if severity is not None else {}
        return Match(engine="yara", name=name, namespace=ns, meta=meta)

    assert yara_severity(yara("Anything", "image.x", None)) == "low"
    assert yara_severity(yara("Anything", "image.x", "high")) == "low"  # not allowlisted
    assert yara_severity(yara("Anything", "image.x", "info")) == "info"  # lowering is fine
    assert yara_severity(yara("Anything", "image.x", "bogus")) == "low"
    name, ns = "CyberLab_Embedded_PE_In_Overlay", "image.cyberlab_baseline"
    assert YARA_SEVERITY_ALLOWLIST[(BASELINE_SHA256, name)] == "medium"
    ceilings = yara_ceilings({ns: BASELINE_SHA256}, test_rules=False)
    assert yara_severity(yara(name, ns, "high"), ceilings) == "medium"  # capped at the ceiling
    assert yara_severity(yara(name, ns, "high")) == "low"  # no ceilings: nothing is raised
    # Only signature engines may reach `high`.
    [hit] = signature_findings([Match(engine="clamav", name="Win.Test.EICAR_HDB-1")])
    assert hit.severity == "high" and hit.method == "signature:clamav@1"


def test_capa_findings_need_attack_ids_in_high_risk_namespaces() -> None:
    inject = "host-interaction/process/inject"
    caps = [
        CapabilityRecord(name="allocate or change RWX memory", namespace=inject),
        CapabilityRecord(name="inject thread", namespace=inject, attack=["T1055.003", "T1620"]),
        CapabilityRecord(name="parse PE header", namespace="load-code/pe", attack=["T1129"]),
        CapabilityRecord(
            name="packed with UPX", namespace="anti-analysis/packer/upx", attack=["T1027.002"]
        ),
    ]
    found = {f.type: f for f in capability_findings(caps)}
    assert set(found) == {"capability_injection", "capability_anti_analysis"}
    assert found["capability_injection"].attributes["rules"] == "inject thread"
    assert found["capability_injection"].attributes["attack"] == "T1055.003, T1620"
    assert found["capability_anti_analysis"].severity == "low"


def test_finding_records_are_contract_valid_and_stable() -> None:
    job = uuid.uuid4()
    structure = Structure("pe", 1, 5.0, pe=pe_info(tls_callbacks=1), imports={
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"})  # fmt: skip
    detection = Detection(job, NOW, structure, ioc_limit=10)
    detection.string("see http://evil.example.com/a — no verdict here", "strings")
    sigs = [
        Match(engine="yara", name="R" * 255, namespace="test.x", meta={"description": "d" * 255})
    ]
    first, capped = detection.findings(sigs, [], limit=10)
    second, _ = detection.findings(sigs, [], limit=10)
    assert not capped and [f.finding_id for f in first] == [f.finding_id for f in second]
    assert [f.severity for f in first] == sorted(
        (f.severity for f in first), key=lambda s: -SEVERITY_RANK[s]
    )
    for f in first:
        assert METHOD.match(f.detection_method) and f.ts == NOW
        assert len(f.title) <= 255 and len(f.description) <= 2048
    limited, capped = detection.findings(sigs, [], limit=1)
    assert len(limited) == 1 and capped
    [url, domain] = sorted(detection.ioc_records(), key=lambda r: r.type, reverse=True)
    assert (url.type, domain.type, domain.value) == ("url", "domain", "evil.example.com")


def test_engine_names_are_placeholders_not_templates() -> None:
    """A signature named 'malicious' is shown verbatim; our own words stay neutral."""
    [f] = signature_findings([Match(engine="clamav", name="Totally.Malicious.Thing")])
    assert isinstance(f, Finding)
    template_text = TEMPLATES[f.type][0] + TEMPLATES[f.type][1]
    assert "{name}" in template_text and not VERDICT.search(template_text)
    assert "Totally.Malicious.Thing" in f.title


def test_yara_allowlist_is_keyed_on_the_rule_file_hash() -> None:
    """A mounted file named like the baseline (or reusing its rule names) inherits nothing."""
    name = "CyberLab_Embedded_PE_In_Overlay"
    match = Match(engine="yara", name=name, namespace="image.cyberlab_baseline",
                  meta={"severity": "high"})  # fmt: skip
    impostor = yara_ceilings({"image.cyberlab_baseline": "f" * 64}, test_rules=True)
    assert impostor == {} and yara_severity(match, impostor) == "low"
    # The same file under another name / namespace keeps its ceilings (content, not name).
    moved = yara_ceilings({"image.renamed": BASELINE_SHA256}, test_rules=False)
    assert moved[f"image.renamed:{name}"] == "medium"


def test_test_rule_ceilings_only_with_test_rules() -> None:
    marker = Match(engine="yara", name="CyberLab_Test_Marker", namespace="test.cyberlab_test",
                   meta={"severity": "medium"})  # fmt: skip
    hashes = {"test.cyberlab_test": TEST_RULES_SHA256}
    assert all(sha != TEST_RULES_SHA256 for sha, _ in YARA_SEVERITY_ALLOWLIST)
    assert yara_severity(marker, yara_ceilings(hashes, test_rules=False)) == "low"
    assert yara_severity(marker, yara_ceilings(hashes, test_rules=True)) == "medium"


def test_allowlist_hashes_match_the_rule_files() -> None:
    """Editing a rule file must update its pinned hash (or its rules lose their ceiling)."""
    root = Path(__file__).parents[2]
    baseline = root / "rules" / "yara" / "cyberlab_baseline.yar"
    if not baseline.exists():  # the test image bakes the rules to /opt/yara/rules
        baseline = Path("/opt/yara/rules/cyberlab_baseline.yar")
    assert hashlib.sha256(baseline.read_bytes()).hexdigest() == BASELINE_SHA256
    test_rules = root / "tests" / "rules" / "yara" / "cyberlab_test.yar"
    assert hashlib.sha256(test_rules.read_bytes()).hexdigest() == TEST_RULES_SHA256
    assert set(YARA_TEST_ALLOWLIST) == {(TEST_RULES_SHA256, "CyberLab_Test_Marker")}
