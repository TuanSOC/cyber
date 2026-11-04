"""Detector quality on the labeled synthetic sample set (requirement §14 metrics).

Every scenario runs through the real engines with its labelled profile: the test ClamAV DB
(EICAR hash + test marker), baked + test YARA rules, capa with the baked capa-rules v10.0.0
on every PE/ELF, FLOSS where labelled (it costs 10-40 s per sample). A label is a true
positive if a finding of the same detector and type (and engine-supplied name, when the
label names one) exists; every other finding is a false positive. The report gives the raw
tp / fp / fn counts next to precision / recall (the set is small: the counts matter more
than the ratios). Near-miss negatives (one API short of each suspicious set, a single
packer indicator, a high-entropy icon) must not produce any finding above info. Set
EVALUATION_OUT to also write the report as JSON.

These are synthetic-data numbers: they show the detectors behave as specified on controlled
samples, not real-world precision.
"""

import json
import os
import time
import uuid
from collections import defaultdict
from dataclasses import replace
from typing import Any

import pytest
from cyberlab_jobs.static import Profile
from cyberlab_worker import sandbox

from static_worker import analyzer
from static_worker.detections.base import SEVERITY_RANK
from static_worker.engines.workspace import Budget
from tests.conftest import SampleSet, in_container
from tests.helpers import FAST, LIMITS, fresh_dirs, parse, place

FLOORS = {"precision": 0.9, "recall": 0.9}
DETECTORS = ["suspicious_api", "packer", "pe_anomaly", "clamav", "yara", "capa"]
PARSE_FAILURES = ("_failed", "_timeout", "_parse_error", "_unavailable", "probe_inconsistent")

pytestmark = in_container


def detector(finding: Any) -> str:
    return str(finding.detection_method).split(":", 1)[1].split("@", 1)[0]


def _matches(label: dict[str, Any], finding: Any) -> bool:
    if detector(finding) != label["detector"] or finding.type != label["type"]:
        return False
    name = label.get("name")
    return name is None or str(finding.attributes.get("name", "")).startswith(name)


def evaluate(results: dict[str, dict[str, Any]], labels: dict[str, Any]) -> dict[str, Any]:
    tally: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for scenario, out in results.items():
        found = list(out.get("finding", []))
        matched: set[int] = set()
        for label in labels[scenario]["findings"]:
            hit = next(
                (i for i, f in enumerate(found) if i not in matched and _matches(label, f)), None
            )
            if hit is None:
                tally[label["detector"]]["fn"] += 1
            else:
                matched.add(hit)
                tally[label["detector"]]["tp"] += 1
        for i, finding in enumerate(found):
            if i not in matched:
                tally[detector(finding)]["fp"] += 1
    report = {}
    for name in sorted(set(tally) | set(DETECTORS)):
        t = tally[name]
        predicted, actual = t["tp"] + t["fp"], t["tp"] + t["fn"]
        report[name] = {
            **t,
            "precision": round(t["tp"] / predicted, 3) if predicted else 1.0,
            "recall": round(t["tp"] / actual, 3) if actual else 1.0,
        }
    return report


def _parsed(header: Any) -> bool:
    return not any(e.endswith(PARSE_FAILURES) or e in PARSE_FAILURES for e in header.engine_errors)


@pytest.fixture(scope="module")
def evaluation(sample_set: SampleSet) -> dict[str, Any]:
    results: dict[str, dict[str, Any]] = {}
    latency: dict[str, float] = {}
    for scenario, path in sorted(sample_set.paths.items()):
        label = sample_set.labels[scenario]
        engines = replace(FAST, capa_enabled=True, floss_enabled=bool(label.get("floss")))
        dirs = fresh_dirs(f"eval-{scenario}")
        try:
            place(dirs, path)
            started = time.monotonic()
            result = analyzer.analyze_file(
                dirs, uuid.uuid4(), Profile(label["profile"]), LIMITS, Budget(LIMITS), engines
            )
            latency[scenario] = round(time.monotonic() - started, 2)
            results[scenario] = parse(result)
        finally:
            sandbox.cleanup(dirs)
    labels = sample_set.labels
    ioc_hits = ioc_total = 0
    for scenario, out in results.items():
        got = {(i.type, i.value, i.source) for i in out.get("ioc", [])}
        for expected in labels[scenario]["iocs"]:
            ioc_total += 1
            source = expected.get("source")
            ioc_hits += any(
                t == expected["type"] and v == expected["value"] and (source in (None, s))
                for t, v, s in got
            )
    report = {
        "dataset": "synthetic (samples/generate.py, seed 20261105) + mingw-w64 C programs",
        "engines": "ClamAV test DB, YARA baked + test rules, capa-rules v10.0.0, FLOSS on "
        "labelled scenarios",
        "scenarios": len(results),
        "benign_scenarios": sum(1 for name in results if labels[name]["benign"]),
        "near_miss_scenarios": sorted(n for n in results if labels[n].get("near_miss")),
        "parsing_success_rate": round(
            sum(_parsed(out["header"]) for out in results.values()) / len(results), 3
        ),
        "latency_s": latency,
        "latency_max_s": max(latency.values()),
        "detectors": evaluate(results, labels),
        "ioc_recall": round(ioc_hits / ioc_total, 3) if ioc_total else 1.0,
        "engine_errors": {k: v["header"].engine_errors for k, v in results.items()
                          if v["header"].engine_errors},
    }  # fmt: skip
    if target := os.environ.get("EVALUATION_OUT"):
        with open(target, "w") as f:
            json.dump(report, f, indent=2)
    return {**report, "_results": results, "_labels": labels}


def test_every_scenario_parses(evaluation: dict[str, Any]) -> None:
    assert evaluation["parsing_success_rate"] == 1.0, evaluation["engine_errors"]


@pytest.mark.parametrize("name", DETECTORS)
def test_detector_meets_quality_floors(evaluation: dict[str, Any], name: str) -> None:
    scores = evaluation["detectors"][name]
    assert scores["tp"] > 0, scores
    for metric, floor in FLOORS.items():
        assert scores[metric] >= floor, (name, scores)


def test_benign_samples_have_nothing_above_info(evaluation: dict[str, Any]) -> None:
    for scenario, out in evaluation["_results"].items():
        if evaluation["_labels"][scenario]["benign"]:
            loud = [f for f in out.get("finding", []) if SEVERITY_RANK[f.severity] > 0]
            assert loud == [], (scenario, [(f.type, f.severity) for f in loud])


def test_expected_signatures_and_capabilities(evaluation: dict[str, Any]) -> None:
    for scenario, out in evaluation["_results"].items():
        label = evaluation["_labels"][scenario]
        matches = [(m.engine, m.name) for m in out.get("signature_match", [])]
        for expected in label["signatures"]:
            assert any(
                e == expected["engine"] and n.startswith(expected["name"]) for e, n in matches
            ), (scenario, expected, matches)
        if not label["signatures"]:
            assert matches == [], (scenario, matches)
        capabilities = {c.name for c in out.get("capability", [])}
        assert set(label["capabilities"]) <= capabilities, (scenario, capabilities)


def test_iocs_are_recovered(evaluation: dict[str, Any]) -> None:
    assert evaluation["ioc_recall"] == 1.0


def test_zip_bombs_are_flagged(evaluation: dict[str, Any]) -> None:
    for scenario, out in evaluation["_results"].items():
        if evaluation["_labels"][scenario].get("expect_not_fully_scanned"):
            assert "av_not_fully_scanned" in out["header"].engine_errors, scenario


def test_only_signature_engines_reach_high(evaluation: dict[str, Any]) -> None:
    for out in evaluation["_results"].values():
        for f in out.get("finding", []):
            if f.severity == "high":
                assert f.detection_method.startswith("signature:"), f
            if f.detection_method.startswith(("heuristic:", "capability:")):
                assert SEVERITY_RANK[f.severity] <= SEVERITY_RANK["medium"], f


def test_findings_never_claim_maliciousness(evaluation: dict[str, Any]) -> None:
    """Our wording; engine-supplied names are excluded (tested on the templates as well)."""
    for scenario, out in evaluation["_results"].items():
        for f in out.get("finding", []):
            text = f"{f.title} {f.description}"
            for value in f.attributes.values():
                text = text.replace(str(value), "")
            lowered = text.lower()
            assert "malicious" not in lowered and "is malware" not in lowered, scenario


def test_report_has_counts_next_to_ratios(evaluation: dict[str, Any]) -> None:
    for name, scores in evaluation["detectors"].items():
        assert {"tp", "fp", "fn", "precision", "recall"} <= set(scores), name
    assert evaluation["near_miss_scenarios"] == [
        "near_miss_apis", "near_miss_icon", "near_miss_packer",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("scenario", "silent"),
    [
        ("near_miss_apis", "heuristic:suspicious_api@1"),
        ("near_miss_packer", "heuristic:packer@1"),
        ("near_miss_icon", "heuristic:pe_anomaly@1"),
    ],
)
def test_near_misses_stay_quiet(evaluation: dict[str, Any], scenario: str, silent: str) -> None:
    found = evaluation["_results"][scenario].get("finding", [])
    assert [f.type for f in found if f.detection_method == silent] == [], scenario
    assert all(SEVERITY_RANK[f.severity] == 0 for f in found), [(f.type, f.severity) for f in found]
