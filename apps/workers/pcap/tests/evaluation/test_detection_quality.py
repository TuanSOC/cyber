"""Detector quality on the labeled synthetic dataset (requirement §14 metrics).

For every scenario, findings are matched against `labels.json`: a label is a true positive if
a finding of the same type with the same source (and destination / port / domain when the
label names one) exists; every other finding is a false positive. Numbers are per detector
over the individual scenarios. Set EVALUATION_OUT to also write the report as JSON.

These are synthetic-data numbers: they show the detectors behave as specified on controlled
traffic, not real-world precision.
"""

import json
import os
import shutil
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import JobLimits

from dataset.generate import generate
from pcap_worker import analyzer, sandbox
from tests.integration.test_engines import LIMITS, TEST_RULES, parse

FLOORS = {"precision": 0.9, "recall": 0.9}

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="runs inside the pcap-worker image")


def _matches(label: dict[str, Any], finding: Any) -> bool:
    if finding.type != label["type"] or str(finding.src_ip) != label["src"]:
        return False
    if "dst" in label and str(finding.dst_ip) != label["dst"]:
        return False
    if "dport" in label and finding.dst_port != label["dport"]:
        return False
    return "domain" not in label or finding.attributes.get("domain") == label["domain"]


def _detector(finding: Any) -> str:
    return str(finding.detection_method).split(":", 1)[1].split("@", 1)[0]


def evaluate(results: dict[str, dict[str, Any]], labels: dict[str, list[Any]]) -> dict[str, Any]:
    tally: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for scenario, out in results.items():
        findings = list(out.get("finding", []))
        matched: set[int] = set()
        for label in labels[scenario]:
            hit = next(
                (i for i, f in enumerate(findings) if i not in matched and _matches(label, f)),
                None,
            )
            if hit is None:
                tally[label["detector"]]["fn"] += 1
            else:
                matched.add(hit)
                tally[label["detector"]]["tp"] += 1
        for i, finding in enumerate(findings):
            if i not in matched:
                tally[_detector(finding)]["fp"] += 1
    report = {}
    for detector, t in sorted(tally.items()):
        predicted, actual = t["tp"] + t["fp"], t["tp"] + t["fn"]
        report[detector] = {
            **t,
            "precision": round(t["tp"] / predicted, 3) if predicted else 1.0,
            "recall": round(t["tp"] / actual, 3) if actual else 1.0,
        }
    return report


@pytest.fixture(scope="module")
def evaluation(dirs_factory: Any) -> dict[str, Any]:
    out_dir = Path("/tmp/evaluation-dataset")
    shutil.rmtree(out_dir, ignore_errors=True)
    paths = generate(out_dir)
    labels = json.loads((out_dir / "labels.json").read_text())
    results: dict[str, dict[str, Any]] = {}
    latency: dict[str, float] = {}
    parsed = 0
    for scenario, path in paths.items():
        dirs = dirs_factory()
        shutil.copyfile(path, dirs.capture)
        dirs.capture.chmod(0o444)
        started = time.monotonic()
        result = analyzer.analyze_file(dirs, uuid.uuid4(), LIMITS, analyzer.Budget(LIMITS))
        latency[scenario] = round(time.monotonic() - started, 2)
        results[scenario] = parse(result)
        parsed += not results[scenario]["header"].engine_errors
        sandbox.cleanup(dirs)
    individual = {k: v for k, v in results.items() if k != "mixed"}
    report = {
        "dataset": "synthetic (dataset/generate.py, seed 1337)",
        "rules": "tests/rules/local-test.rules",
        "parsing_success_rate": round(parsed / len(results), 3),
        "latency_s": latency,
        "detectors": evaluate(individual, labels),
        "mixed": evaluate({"mixed": results["mixed"]}, labels),
    }
    if target := os.environ.get("EVALUATION_OUT"):
        Path(target).write_text(json.dumps(report, indent=2))
    return {**report, "_results": results}


@pytest.fixture(scope="module")
def dirs_factory() -> Any:
    os.environ["SURICATA_RULES"] = TEST_RULES
    counter = iter(range(1000))
    return lambda: sandbox.prepare(Path(os.environ.get("WORK_DIR", "/work")),
                                   f"eval-{next(counter)}")  # fmt: skip


def test_every_scenario_parses(evaluation: dict[str, Any]) -> None:
    assert evaluation["parsing_success_rate"] == 1.0


@pytest.mark.parametrize(
    "detector", ["beaconing", "port_scan", "dns_anomaly", "suspicious_traffic"]
)
def test_detector_meets_quality_floors(evaluation: dict[str, Any], detector: str) -> None:
    scores = evaluation["detectors"][detector]
    assert scores["tp"] > 0, scores
    for metric, floor in FLOORS.items():
        assert scores[metric] >= floor, (detector, scores)


def test_no_detector_fires_on_benign_scenarios(evaluation: dict[str, Any]) -> None:
    for detector, scores in evaluation["detectors"].items():
        if scores["tp"] == 0:  # detectors without labelled positives must stay silent
            assert scores["fp"] == 0, (detector, scores)


def test_mixed_capture_finds_everything(evaluation: dict[str, Any]) -> None:
    for detector, scores in evaluation["mixed"].items():
        assert scores["fn"] == 0 and scores["recall"] == 1.0, (detector, scores)


def test_limits_constant_is_shared() -> None:
    assert isinstance(LIMITS, JobLimits)


def test_findings_never_claim_maliciousness(evaluation: dict[str, Any]) -> None:
    """Heuristics describe behaviour; verdict words are reserved for analysts."""
    for scenario, out in evaluation["_results"].items():
        for finding in out.get("finding", []):
            text = f"{finding.title} {finding.description}".lower()
            assert "malicious" not in text and "malware detected" not in text, scenario
