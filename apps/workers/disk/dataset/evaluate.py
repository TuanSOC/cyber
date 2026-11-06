"""Runs every labelled disk scenario through `detections.run` and reports TP / FP / FN, precision
and recall per detection method and overall, plus IOC recall (M9 phase 6; phase 13 copies the
table into the metric report).

    python -m dataset.evaluate          (from apps/workers/disk; pure Python, no image)

Matching: a finding matches a label on (detection method, type, `subject` attribute) and, when
the label gives one, severity; each label consumes one finding. Findings at `info` are ignored;
any other unmatched finding is a false positive of its method (baselines and hard negatives
expect none). An IOC label matches on (type, value) and, when given, the IOC's source.

Caveat: synthetic scenarios designed alongside the detectors. Precision and recall on this set
show that the detectors behave as specified, not their real-world quality.
"""

from dataclasses import dataclass, field

from cyberlab_jobs.disk import DetectionOutput
from cyberlab_jobs.results import FindingRecord, IocRecord

from dataset.generate import build
from dataset.records import limits
from dataset.scenarios import SCENARIOS, SEVERITY_MAP, Expect, ioc_labels
from disk_worker import detections
from disk_worker.detections.base import METHOD_MAX

CAVEAT = (
    "Synthetic scenarios designed alongside the detectors: precision and recall on this set show "
    "that the detectors behave as specified, not their real-world quality."
)
LIMITS = limits()


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


def subject(finding: FindingRecord) -> object:
    return finding.attributes.get("subject")


def matches(finding: FindingRecord, label: Expect) -> bool:
    return (
        finding.detection_method == label.method
        and finding.type == label.type
        and subject(finding) == label.subject
        and (label.severity is None or finding.severity == label.severity)
    )


def run_scenario(name: str) -> DetectionOutput:
    return detections.run(build(name), LIMITS, yara_severity=SEVERITY_MAP)  # type: ignore[arg-type]


def evaluate(names: list[str] | None = None) -> Report:
    report = Report()
    for name in names or list(SCENARIOS):
        scenario = SCENARIOS[name]
        out = run_scenario(name)
        report.outputs[name] = out
        remaining = [f for f in out.findings if f.severity != "info"]
        for label in scenario.expect:
            hit = next((f for f in remaining if matches(f, label)), None)
            counts = report.per_method.setdefault(label.method, Counts())
            if hit is None:
                counts.fn += 1
                report.false_negatives.append(f"{name}: {label.type} {label.subject!r}")
            else:
                counts.tp += 1
                remaining.remove(hit)
        for finding in remaining:
            report.per_method.setdefault(finding.detection_method, Counts()).fp += 1
            report.false_positives.append(
                f"{name}: {finding.type} {subject(finding)!r} ({finding.severity})"
            )
        found: dict[tuple[str, str], IocRecord] = {(i.type, i.value): i for i in out.iocs}
        for ioc in ioc_labels(name):
            report.ioc_expected += 1
            hit_ioc = found.get((ioc.type, ioc.value))
            if hit_ioc is not None and ioc.source in (None, hit_ioc.source):
                report.ioc_found += 1
            else:
                report.false_negatives.append(f"{name}: IOC {ioc.type} {ioc.value}")
    return report


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def table(report: Report) -> str:
    rows = [
        "| Detection method | TP | FP | FN | Precision | Recall |",
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
    kinds = [s.kind for s in SCENARIOS.values()]
    rows.append(
        f"Scenarios: {len(kinds)} ({kinds.count('baseline')} baselines, "
        f"{kinds.count('positive')} positive, {kinds.count('hard_negative')} hard negative). "
        + CAVEAT
    )
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
