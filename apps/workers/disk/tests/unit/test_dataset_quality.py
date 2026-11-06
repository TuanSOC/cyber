# ruff: noqa: E501 - test data tables
"""The labelled disk scenario set (phase 6 success criteria): every rule has >= 10 labelled
positives and is exercised, baselines and hard negatives produce nothing, precision and recall
are 1.0 on the set (with the caveat), IOC recall is 1.0, no heuristic exceeds `medium`, no
unmasked secret reaches a shared surface, and the set itself is well formed and synthetic."""

import ipaddress
import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

import pytest

from dataset import evaluate, generate, records
from dataset.baselines import BASELINES, WEEK_START
from dataset.scenarios import SCENARIOS, draft, ioc_labels
from disk_worker.detections.base import METHOD_MAX, SEVERITY_RANK, TEMPLATES

MIN_POSITIVES = 10
HARD_NEGATIVES = {
    "Defender updates": ("win_defender_update", "windows10_workstation"),
    "OneDrive": ("win_onedrive_teams", "windows10_workstation"),
    "Zone.Identifier streams": ("win_ads_executable", "windows10_workstation"),
    "FAT 2-second times": ("windows11_workstation",),
    "legitimate service install by an installer path": (
        "win_installer_service",
        "windows10_workstation",
    ),
    "sudo usage": ("linux_admin_week", "debian_server"),
}


@pytest.fixture(scope="module")
def report() -> evaluate.Report:
    return evaluate.evaluate()


def test_scenario_ids_are_unique_and_kinds_known() -> None:
    names = [s.name for s in SCENARIOS.values()]
    assert len(names) == len(set(names)) == len(SCENARIOS)
    for scenario in SCENARIOS.values():
        assert scenario.kind in {"baseline", "positive", "hard_negative"}, scenario.name
        assert scenario.baseline in BASELINES
        if scenario.kind == "positive":
            assert scenario.expect, scenario.name
        else:
            assert scenario.expect == [] and scenario.iocs == [], scenario.name
        for label in scenario.expect:
            assert label.type in TEMPLATES and label.method in METHOD_MAX, label
            assert (
                label.severity is None
                or SEVERITY_RANK[label.severity] <= SEVERITY_RANK[METHOD_MAX[label.method]]
            )


def test_every_method_has_at_least_ten_labelled_positives() -> None:
    counts = Counter(label.method for s in SCENARIOS.values() for label in s.expect)
    for method in METHOD_MAX:
        assert counts[method] >= MIN_POSITIVES, (method, counts[method])


def test_named_hard_negatives_are_in_the_set() -> None:
    for what, names in HARD_NEGATIVES.items():
        assert all(n in SCENARIOS for n in names), what
    assert {s.name for s in SCENARIOS.values() if s.kind == "baseline"} == set(BASELINES)
    fat = [
        f
        for f in draft("windows11_workstation").files
        if f.partition_index == records.FAT_PARTITION
    ]
    assert fat and all(
        f.time_basis == "local_unknown" and f.mtime is not None and f.mtime.second % 2 == 0
        for f in fat
    )
    zone = [f for f in draft("windows10_workstation").files if f.stream == "Zone.Identifier"]
    assert len(zone) >= 10


def test_every_method_is_exercised(report: evaluate.Report) -> None:
    for method in METHOD_MAX:
        assert report.per_method[method].tp >= MIN_POSITIVES, method


def test_precision_and_recall_are_one(report: evaluate.Report) -> None:
    assert report.false_positives == []
    assert report.false_negatives == []
    for method, counts in report.per_method.items():
        assert counts.precision == 1.0 and counts.recall == 1.0, method
    assert report.ioc_recall == 1.0


def test_baselines_and_hard_negatives_have_no_finding(report: evaluate.Report) -> None:
    for name, scenario in SCENARIOS.items():
        if scenario.kind != "positive":
            assert report.outputs[name].findings == [], name


def test_no_heuristic_exceeds_medium(report: evaluate.Report) -> None:
    for out in report.outputs.values():
        for finding in out.findings:
            ceiling = METHOD_MAX[finding.detection_method]
            assert SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[ceiling]
            if finding.detection_method.startswith(("heuristic:", "known_file:")):
                assert SEVERITY_RANK[finding.severity] <= SEVERITY_RANK["medium"]
    assert any(f.severity == "high" for f in report.outputs["win_yara"].findings)  # only YARA


def test_no_secret_reaches_a_shared_surface(report: evaluate.Report) -> None:
    with_secrets = {name: s.secrets for name, s in SCENARIOS.items() if s.secrets}
    assert len(with_secrets) >= 2
    for name, secrets in with_secrets.items():
        out = report.outputs[name]
        surfaces = [f.title for f in out.findings] + [f.description for f in out.findings]
        surfaces += [str(v) for f in out.findings for v in f.attributes.values()]
        surfaces += [i.value for i in out.iocs] + [e.title for e in out.timeline]
        # the secrets really are in the raw records, so the check is not vacuous
        raw = json.dumps([e.model_dump(mode="json") for e in draft(name).events])
        for secret in secrets:
            assert secret in raw, (name, secret)
            for text in surfaces:
                assert secret not in text, (name, secret, text)


def test_secret_scenarios_quote_the_masked_value(report: evaluate.Report) -> None:
    text = " ".join(f.description for f in report.outputs["linux_dual_use"].findings)
    assert "Hu***********(13)" in text and "gh**********************(24)" in text
    text = " ".join(f.description for f in report.outputs["win_persistence"].findings)
    assert "Su***********(13)" in text


def test_baselines_are_realistic_in_size() -> None:
    for name in BASELINES:
        d = draft(name)
        assert 1_500 <= len(d.files) <= 5_000, (name, len(d.files))
        assert len({e.ordinal for e in d.events}) == len(d.events) == d.events[-1].ordinal + 1
        # a quiet week of activity (registry keys keep their older last-written times)
        week = [e for e in d.events if WEEK_START <= e.ts < WEEK_START + timedelta(days=7)]
        assert len(week) >= 300, name
        assert {e.ts.day for e in week} == set(range(1, 8)), name
    windows = draft("windows10_workstation")
    assert any(
        f.path.startswith("ProgramData/Microsoft/Windows Defender/Platform/") and f.magic == "pe"
        for f in windows.files
    )
    assert any(f.path.startswith("Program Files/") for f in windows.files)


def test_no_real_public_address_is_used() -> None:
    """External peers are RFC 5737 / RFC 3849 documentation addresses, never a real host."""
    for name in SCENARIOS:
        out_iocs = ioc_labels(name)
        for label in out_iocs:
            if label.type == "ip":
                assert not ipaddress.ip_address(label.value).is_global, (name, label)
    for ioc in evaluate.run_scenario("win_remote_logon").iocs:
        if ioc.type == "ip":
            assert not ipaddress.ip_address(ioc.value).is_global


def test_every_view_is_labelled_synthetic() -> None:
    for name in SCENARIOS:
        view = generate.build(name)
        assert all(
            records.HEADER_NOTE in (p.os_name or records.HEADER_NOTE) for p in view.partitions
        )
        header = generate.header(SCENARIOS[name], view)
        assert header.tool_versions["dataset"] == records.HEADER_NOTE
        assert header.timeline_engine == "replay"


def test_generator_writes_records_and_labels(tmp_path: Path) -> None:
    written = generate.write(tmp_path)
    assert len(written) == len(SCENARIOS) + 1
    lines = (tmp_path / "linux_dual_use.ndjson").read_text("utf-8").splitlines()
    first = json.loads(lines[0])
    assert first["kind"] == "header" and first["tool_versions"]["dataset"] == records.HEADER_NOTE
    assert {json.loads(x)["kind"] for x in lines[1:]} == {"partition", "file", "event"}
    labels = json.loads((tmp_path / "labels.json").read_text("utf-8"))
    assert set(labels["scenarios"]) == set(SCENARIOS) and labels["synthetic"] == records.HEADER_NOTE
    # deterministic
    again = generate.lines("linux_dual_use")
    assert [json.dumps(x, separators=(",", ":"), ensure_ascii=False) for x in again] == lines


def test_the_harness_reports_a_table(report: evaluate.Report) -> None:
    text = evaluate.table(report)
    total = report.total
    assert f"| **all** | {total.tp} | 0 | 0 | 1.00 | 1.00 |" in text
    assert "IOC recall:" in text and "(1.00)" in text and "real-world quality" in text


def test_harness_counts_a_missing_label_as_a_false_negative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataset.scenarios import Expect

    scenario = SCENARIOS["debian_server"]
    monkeypatch.setattr(scenario, "expect", [Expect("disk_exec_user_writable", "tmp/none", "low")])
    result = evaluate.evaluate(["debian_server"])
    assert result.per_method["heuristic:disk_exec_user_writable@1"].fn == 1
    assert result.false_negatives == ["debian_server: disk_exec_user_writable 'tmp/none'"]
