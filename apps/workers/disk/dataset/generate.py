"""The disk scenario dataset generator (M9 phase 6): seeded, deterministic, synthetic.

    build(name) -> DiskView                (in memory; what the tests and evaluate.py use)
    python -m dataset.generate --out DIR   (writes one `disk.v1` record file per scenario)

Each written file is NDJSON: a `disk.v1` header whose `tool_versions.dataset` says the scenario
is synthetic, then the scenario's `partition`, `file` and `event` lines (normalised records, the
detection input; no findings and no trailer: the expected findings are in `labels.json` beside
them). No disk image is produced or needed. Nothing is written into the repository by tests.
"""

import argparse
import json
import uuid
from pathlib import Path
from typing import Any

from cyberlab_jobs.disk import DiskResultHeader, DiskView

from dataset import records
from dataset.scenarios import SCENARIOS, SEVERITY_MAP, Scenario, draft, ioc_labels

NAMESPACE = uuid.UUID("a3f1e2d4-6b5c-4e7f-8a9b-0c1d2e3f4a5b")


def build(name: str) -> DiskView:
    return draft(name).view()


def header(scenario: Scenario, view: DiskView) -> DiskResultHeader:
    return DiskResultHeader(
        job_id=uuid.uuid5(NAMESPACE, scenario.name),
        profile=view.profile,
        engine="tsk",
        timeline_engine="replay",
        tool_versions={"dataset": records.HEADER_NOTE, "scenario": scenario.name[:64]},
        image=view.image,
    )


def lines(name: str) -> list[dict[str, Any]]:
    scenario = SCENARIOS[name]
    view = build(name)
    out: list[dict[str, Any]] = [header(scenario, view).model_dump(mode="json")]
    out += [p.model_dump(mode="json", exclude_none=True) for p in view.partitions]
    out += [f.model_dump(mode="json", exclude_none=True) for f in view.files]
    out += [e.model_dump(mode="json", exclude_none=True) for e in view.events()]
    return out


def labels() -> dict[str, Any]:
    return {
        "synthetic": records.HEADER_NOTE,
        "yara_severity": SEVERITY_MAP,
        "scenarios": {
            name: {
                "kind": s.kind,
                "baseline": s.baseline,
                "description": s.description,
                "findings": [
                    {
                        "method": e.method,
                        "type": e.type,
                        "subject": e.subject,
                        "severity": e.severity,
                    }
                    for e in s.expect
                ],
                "iocs": [
                    {"type": i.type, "value": i.value, "source": i.source} for i in ioc_labels(name)
                ],
            }
            for name, s in SCENARIOS.items()
        },
    }


def write(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in SCENARIOS:
        path = out_dir / f"{name}.ndjson"
        with path.open("w", encoding="utf-8", newline="\n") as f:
            for line in lines(name):
                f.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        written.append(path)
    label_path = out_dir / "labels.json"
    label_path.write_text(json.dumps(labels(), indent=2, ensure_ascii=False) + "\n", "utf-8")
    written.append(label_path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    for path in write(args.out):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
