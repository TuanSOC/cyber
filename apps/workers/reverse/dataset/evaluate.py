"""Runs every labelled RE scenario through `detections.run` and `priority.rank` (M10 phase 5):
TP / FP / FN, precision and recall per rule (detection method), IOC recall and unexpected
IOCs, the priority-order checks, and the M3 file-level comparison (the split near miss).

    python -m dataset.evaluate          (from apps/workers/reverse; pure Python, no image)

A finding matches a label on (method, type, function name, severity); every unmatched
finding is a false positive, every unmatched label a false negative. Caveat (labels.json):
the scenarios were designed alongside the rules, so these numbers show that the rules behave
as specified, not their real-world quality.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberlab_worker.apisets import API_SETS

from dataset.generate import LIMITS, SCENARIOS, build, entry_names
from re_worker import detections, priority
from re_worker.detections import KNOWN_APIS
from re_worker.detections.apisets import matches
from re_worker.detections.base import METHOD_MAX, called_api_names
from re_worker.view import DetectionOutput, ReView

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
    unexpected_iocs: list[str] = field(default_factory=list)
    priority_failures: list[str] = field(default_factory=list)
    priority_checks: int = 0
    m3_file_level: dict[str, list[str]] = field(default_factory=dict)
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


def m3_file_level(view: ReView) -> list[str]:
    """The set types M3's file-level rule would report for the union of every API called."""
    names: frozenset[str] = frozenset()
    for entry in view.functions:
        names |= called_api_names(view, entry, KNOWN_APIS)
    return [s.type for s in API_SETS if matches(s, names) is not None]


def _function_name(view: ReView, value: object) -> str | None:
    if not isinstance(value, str):
        return None
    entry = int(value, 16)
    function = view.functions.get(entry)
    return function.name if function is not None else None


def evaluate() -> Report:
    labels = load_labels()["scenarios"]
    report = Report()
    for name in SCENARIOS:
        expected = labels[name]
        scenario = build(name)
        view = scenario.view
        out = detections.run(view, LIMITS)
        report.outputs[name] = out
        remaining = list(out.findings)
        for label in expected["findings"]:
            hit = next(
                (
                    f
                    for f in remaining
                    if f.detection_method == label["method"]
                    and f.type == label["type"]
                    and f.severity == label["severity"]
                    and _function_name(view, f.attributes.get("function_entry"))
                    == label["function"]
                ),
                None,
            )
            counts = report.per_method.setdefault(label["method"], Counts())
            if hit is None:
                counts.fn += 1
                report.false_negatives.append(f"{name}: {label['type']} in {label['function']}")
            else:
                counts.tp += 1
                remaining.remove(hit)
        for finding in remaining:
            report.per_method.setdefault(finding.detection_method, Counts()).fp += 1
            where = _function_name(view, finding.attributes.get("function_entry"))
            report.false_positives.append(f"{name}: {finding.type} in {where} ({finding.severity})")
        found = {(i.type, i.value) for i in out.iocs}
        wanted = {(i["type"], i["value"]) for i in expected["iocs"]}
        report.ioc_expected += len(wanted)
        report.ioc_found += len(found & wanted)
        report.false_negatives += [f"{name}: IOC {t} {v}" for t, v in sorted(wanted - found)]
        report.unexpected_iocs += [f"{name}: IOC {t} {v}" for t, v in sorted(found - wanted)]
        if "priority" in expected:
            report.priority_checks += 1
            names = entry_names(view)
            order = [names[e] for e in priority.rank(view, scenario.job)]
            missing = [f"0x{a:x}" for a in priority.missing_addresses(view, scenario.job)]
            if order != expected["priority"]["order"] or missing != expected["priority"]["missing"]:
                report.priority_failures.append(f"{name}: {order} missing {missing}")
        if expected["kind"] == "near_miss":
            file_level = m3_file_level(view)
            if file_level:
                report.m3_file_level[name] = file_level
    return report


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def table(report: Report) -> str:
    rows = [
        "| Rule | TP | FP | FN | Precision | Recall |",
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
        f"IOC recall: {report.ioc_found}/{report.ioc_expected} ({_ratio(report.ioc_recall)}); "
        f"unexpected IOCs: {len(report.unexpected_iocs)}"
    )
    passed = report.priority_checks - len(report.priority_failures)
    rows.append(f"Priority-order checks: {passed}/{report.priority_checks}")
    split = ", ".join(f"{k} ({', '.join(v)})" for k, v in sorted(report.m3_file_level.items()))
    rows.append(f"Near misses M3's file-level rule would report: {split or 'none'}")
    rows.append(f"Scenarios: {len(SCENARIOS)}. {load_labels()['caveat']}")
    return "\n".join(rows)


def as_json(report: Report) -> dict[str, Any]:
    return {
        "caveat": load_labels()["caveat"],
        "scenarios": len(SCENARIOS),
        "per_rule": {
            method: {"tp": c.tp, "fp": c.fp, "fn": c.fn, "precision": c.precision,
                     "recall": c.recall}  # fmt: skip
            for method, c in sorted(report.per_method.items())
        },
        "ioc_recall": report.ioc_recall,
        "unexpected_iocs": report.unexpected_iocs,
        "priority_checks": report.priority_checks,
        "priority_failures": report.priority_failures,
        "m3_file_level_near_misses": report.m3_file_level,
        "false_positives": report.false_positives,
        "false_negatives": report.false_negatives,
    }


def main() -> int:
    report = evaluate()
    print(table(report))
    for line in report.false_positives:
        print(f"FP {line}")
    for line in report.false_negatives:
        print(f"FN {line}")
    for line in report.priority_failures:
        print(f"PRIORITY {line}")
    bad = report.false_positives or report.false_negatives or report.priority_failures
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
