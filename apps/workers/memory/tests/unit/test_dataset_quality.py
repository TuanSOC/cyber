# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""The labelled scenario set (phase 3 success criteria): every positive yields its labelled
finding, baselines and near-misses nothing above `info` (precision and recall 1.0 on the set,
with the caveat), IOC recall 1.0, no heuristic above `medium`, no unmasked secret on a shared
surface, and the set itself is well formed."""

import pytest

from dataset import evaluate
from dataset.baselines import BASELINES
from dataset.scenarios import SCENARIOS, SECRETS, build, draft
from memory_worker.detections.base import METHOD_MAX, SEVERITY_RANK, TEMPLATES


@pytest.fixture(scope="module")
def report() -> evaluate.Report:
    return evaluate.evaluate()


def test_labels_cover_exactly_the_scenarios() -> None:
    labels = evaluate.load_labels()
    assert set(labels["scenarios"]) == set(SCENARIOS)
    assert "not their real-world quality" in labels["caveat"]
    for name, label in labels["scenarios"].items():
        assert label["kind"] in {"baseline", "positive", "near_miss"}, name
        if label["kind"] == "positive":
            assert label["findings"], name
        else:
            assert label["findings"] == [] and label["iocs"] == [], name
        for finding in label["findings"]:
            assert finding["method"] in METHOD_MAX, name
            assert TEMPLATES[finding["type"]][0] == finding["method"], name


def test_every_detector_is_exercised(report: evaluate.Report) -> None:
    for method in METHOD_MAX:
        assert report.per_method[method].tp >= 1, method


def test_precision_and_recall_are_one(report: evaluate.Report) -> None:
    assert report.false_positives == []
    assert report.false_negatives == []
    for method, counts in report.per_method.items():
        assert counts.precision == 1.0 and counts.recall == 1.0, method
    assert report.ioc_recall == 1.0


def test_baselines_and_near_misses_have_nothing_above_info(report: evaluate.Report) -> None:
    labels = evaluate.load_labels()["scenarios"]
    for name, label in labels.items():
        if label["kind"] != "positive":
            assert [f for f in report.outputs[name].findings if f.severity != "info"] == [], name


def test_no_heuristic_exceeds_its_ceiling(report: evaluate.Report) -> None:
    for out in report.outputs.values():
        for finding in out.findings:
            assert finding.detection_method.startswith("heuristic:")
            assert SEVERITY_RANK[finding.severity] <= SEVERITY_RANK["medium"]
            assert SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[METHOD_MAX[finding.detection_method]]


def test_no_secret_reaches_a_shared_surface(report: evaluate.Report) -> None:
    for name, secrets in SECRETS.items():
        out = report.outputs[name]
        surfaces = [f.title for f in out.findings] + [f.description for f in out.findings]
        surfaces += [str(v) for f in out.findings for v in f.attributes.values()]
        surfaces += [i.value for i in out.iocs] + [e.title for e in out.timeline]
        # The secrets really are in the raw records, so the check is not vacuous.
        raw = draft(name)
        raw_text = " ".join(
            [str(p.get("cmdline")) for p in raw.processes]
            + [str(a["attributes"].get("command")) for a in raw.artifacts]
        )
        for secret in secrets:
            assert secret in raw_text, (name, secret)
            for text in surfaces:
                assert secret not in text, (name, secret, text)


def test_password_scenarios_quote_the_masked_value(report: evaluate.Report) -> None:
    descriptions = " ".join(f.description for f in report.outputs["win_cmdline_password"].findings)
    assert "Wi***********(13)" in descriptions
    descriptions = " ".join(f.description for f in report.outputs["linux_bash_password"].findings)
    assert "Tr*********(11)" in descriptions


def test_baselines_are_realistic_in_size() -> None:
    workstation = build("windows_workstation")
    assert 100 <= len(workstation.processes) <= 150
    assert len({p.pid for p in workstation.processes}) == len(workstation.processes)
    server = build("windows_server")
    assert sum(a.type == "service" for a in server.artifacts) >= 50
    linux = build("linux_server")
    assert linux.os == "linux" and any(a.type == "bash" for a in linux.artifacts)
    assert set(BASELINES) == {"windows_workstation", "windows_server", "linux_server"}


def test_jit_hosts_hold_rwx_regions_in_the_baseline() -> None:
    view = build("windows_workstation")
    rwx = [r for r in view.injections if r.protection == "PAGE_EXECUTE_READWRITE"]
    assert {r.process for r in rwx} >= {"msedge.exe", "powershell.exe"}


def test_no_real_public_address_is_used() -> None:
    """External peers are RFC 5737 documentation addresses (never a real host)."""
    for name in SCENARIOS:
        for conn in build(name).connections:
            assert conn.remote_addr is None or not conn.remote_addr.is_global, (name, conn)


def test_the_harness_reports_a_table(report: evaluate.Report) -> None:
    text = evaluate.table(report)
    assert "| **all** | 19 | 0 | 0 | 1.00 | 1.00 |" in text
    assert "IOC recall: 8/8 (1.00)" in text and "real-world quality" in text


def test_harness_counts_a_missing_label_as_a_false_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    labels = evaluate.load_labels()
    labels["scenarios"]["windows_workstation"]["findings"] = [
        {"method": "heuristic:mem_hidden_process@1", "type": "mem_hidden_process", "pid": 1}
    ]
    monkeypatch.setattr(evaluate, "load_labels", lambda: labels)
    result = evaluate.evaluate()
    assert result.per_method["heuristic:mem_hidden_process@1"].fn == 1
    assert result.false_negatives == ["windows_workstation: mem_hidden_process pid 1"]
