"""The labelled RE scenario set (M10 phase 5 success criteria): every rule fires on its
positives and not on its near misses, precision and recall 1.0 on the set (with the
caveat), IOC recall 1.0 and no unexpected IOC, every priority-order check passes, the split
near miss is one M3's file-level rule would report; the table is written to
`dataset/quality.json` (or `$RE_QUALITY_DIR`; skipped on a read-only mount)."""

import json
import os
from pathlib import Path

import pytest

from dataset import evaluate
from dataset.generate import SCENARIOS
from re_worker.detections.base import METHOD_MAX, TEMPLATES

DATASET = Path(evaluate.__file__).parent


@pytest.fixture(scope="module")
def report() -> evaluate.Report:
    return evaluate.evaluate()


def test_labels_cover_exactly_the_scenarios() -> None:
    labels = evaluate.load_labels()
    assert set(labels["scenarios"]) == set(SCENARIOS)
    assert "not their real-world quality" in labels["caveat"]
    kinds = {label["kind"] for label in labels["scenarios"].values()}
    assert kinds == {"baseline", "positive", "near_miss", "priority"}
    for name, label in labels["scenarios"].items():
        if label["kind"] == "positive":
            assert label["findings"], name
        if label["kind"] == "near_miss":
            assert label["findings"] == [], name
        for finding in label["findings"]:
            assert finding["method"] in METHOD_MAX, name
            assert TEMPLATES[finding["type"]][0] == finding["method"], name


def test_every_rule_is_exercised(report: evaluate.Report) -> None:
    for method in METHOD_MAX:
        assert report.per_method[method].tp >= 3, method


def test_precision_and_recall_are_one(report: evaluate.Report) -> None:
    assert report.false_positives == []
    assert report.false_negatives == []
    for method, counts in report.per_method.items():
        assert counts.precision == 1.0 and counts.recall == 1.0, method
    assert report.ioc_recall == 1.0 and report.unexpected_iocs == []


def test_priority_checks_pass(report: evaluate.Report) -> None:
    assert report.priority_checks == 3 and report.priority_failures == []


def test_split_near_miss_is_what_m3_would_report(report: evaluate.Report) -> None:
    assert report.m3_file_level == {"nm_injection_split": ["api_injection"]}


def test_the_harness_reports_a_table_and_writes_quality_json(report: evaluate.Report) -> None:
    text = evaluate.table(report)
    assert "| **all** | 15 | 0 | 0 | 1.00 | 1.00 |" in text
    assert "Priority-order checks: 3/3" in text and "real-world quality" in text
    data = evaluate.as_json(report)
    target = Path(os.environ.get("RE_QUALITY_DIR", str(DATASET))) / "quality.json"
    try:
        text = json.dumps(data, indent=2, sort_keys=True) + "\n"
        target.write_text(text, encoding="utf-8", newline="\n")
    except OSError:
        pytest.skip(f"read-only {target.parent}: table not written")
    assert json.loads(target.read_text(encoding="utf-8"))["scenarios"] == len(SCENARIOS)


def test_harness_counts_a_missing_label_as_a_false_negative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    labels = evaluate.load_labels()
    labels["scenarios"]["baseline_gui"]["findings"] = [
        {"method": "heuristic:re_api_set_function@1", "type": "api_keylogging",
         "function": "window_loop", "severity": "medium"}
    ]  # fmt: skip
    monkeypatch.setattr(evaluate, "load_labels", lambda: labels)
    result = evaluate.evaluate()
    assert result.per_method["heuristic:re_api_set_function@1"].fn == 1
    assert result.false_negatives == ["baseline_gui: api_keylogging in window_loop"]
