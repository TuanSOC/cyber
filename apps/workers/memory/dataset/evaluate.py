"""Runs every labelled scenario through `detections.run` and reports TP / FP / FN, precision
and recall per detector (detection method), plus IOC recall (M8 phase 3; phase 11 writes the
table into `plans/reports/memory-metric-YYMMDD.md`).

    python -m dataset.evaluate          (from apps/workers/memory; pure Python, no image)

Caveat (also in README.md): the scenarios were designed alongside the detectors, so these
numbers show that the detectors behave as specified, not their real-world quality.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberlab_jobs.results import FindingRecord

from dataset.scenarios import LIMITS, SCENARIOS, build
from memory_worker import detections
from memory_worker.detections.base import METHOD_MAX
from memory_worker.view import DetectionOutput

LABELS = Path(__file__).with_name("labels.json")


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class Report:
    per_method: dict[str, Counts] = field(default_factory=lambda: {m: Counts() for m in METHOD_MAX})
    ioc_expected: int = 0
    ioc_found: int = 0
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    outputs: dict[str, DetectionOutput] = field(default_factory=dict)

    @property
    def ioc_recall(self) -> float | None:
        return self.ioc_found / self.ioc_expected if self.ioc_expected else None

    @property
    def total(self) -> Counts:
        return Counts(
            sum(c.tp for c in self.per_method.values()),
            sum(c.fp for c in self.per_method.values()),
            sum(c.fn for c in self.per_method.values()),
        )


def load_labels() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(LABELS.read_text(encoding="utf-8"))
    return data


def finding_pid(finding: FindingRecord) -> int | None:
    value = finding.attributes.get("pid")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _matches(finding: FindingRecord, label: dict[str, Any]) -> bool:
    return (
        finding.detection_method == label["method"]
        and finding.type == label["type"]
        and finding_pid(finding) == label["pid"]
        and ("severity" not in label or finding.severity == label["severity"])
    )


def evaluate() -> Report:
    labels = load_labels()["scenarios"]
    report = Report()
    for name in SCENARIOS:
        expected = labels[name]
        out = detections.run(build(name), LIMITS)
        report.outputs[name] = out
        remaining = [f for f in out.findings if f.severity != "info"]
        for label in expected["findings"]:
            hit = next((f for f in remaining if _matches(f, label)), None)
            counts = report.per_method.setdefault(label["method"], Counts())
            if hit is None:
                counts.fn += 1
                report.false_negatives.append(f"{name}: {label['type']} pid {label['pid']}")
            else:
                counts.tp += 1
                remaining.remove(hit)
        for finding in remaining:
            report.per_method.setdefault(finding.detection_method, Counts()).fp += 1
            report.false_positives.append(
                f"{name}: {finding.type} pid {finding_pid(finding)} ({finding.severity})"
            )
        iocs = {(i.type, i.value): i for i in out.iocs}
        for ioc in expected["iocs"]:
            report.ioc_expected += 1
            found = iocs.get((ioc["type"], ioc["value"]))
            if found is not None and ioc.get("source", found.source) == found.source:
                report.ioc_found += 1
            else:
                report.false_negatives.append(f"{name}: IOC {ioc['type']} {ioc['value']}")
    return report


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def table(report: Report) -> str:
    rows = [
        "| Detector | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for method, c in sorted(report.per_method.items()):
        ratios = f"{_ratio(c.precision)} | {_ratio(c.recall)}"
        rows.append(f"| `{method}` | {c.tp} | {c.fp} | {c.fn} | {ratios} |")
    t = report.total
    rows.append(
        f"| **all** | {t.tp} | {t.fp} | {t.fn} | {_ratio(t.precision)} | {_ratio(t.recall)} |"
    )
    rows.append("")
    rows.append(
        f"IOC recall: {report.ioc_found}/{report.ioc_expected} ({_ratio(report.ioc_recall)})"
    )
    rows.append(f"Scenarios: {len(SCENARIOS)}. {load_labels()['caveat']}")
    return "\n".join(rows)


def main() -> int:
    report = evaluate()
    print(table(report))
    for line in report.false_positives:
        print(f"FP {line}")
    for line in report.false_negatives:
        print(f"FN {line}")
    return 0 if not report.false_positives and not report.false_negatives else 1


if __name__ == "__main__":
    raise SystemExit(main())
