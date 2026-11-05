"""Pipeline snapshots -> committed cases (the API half of `scripts/ai_eval_snapshot.py`).

The worker half runs the real pcap and static pipelines on the generated datasets (`--inject`
on) inside the test worker images and leaves, in the snapshot volume:

    pcap/labels.json, pcap/<name>.ndjson.gz + pcap/<name>.json {job_id}
    static/labels.json, static/<name>.ndjson.gz + static/<name>.json {job_id, sha256, ...}

This module validates each stream exactly as ingest does (`stream.validate`), turns the
records into rows with ingest's own `to_row` / `sample_row` / `build_summary`, trims them to
what a context can select, maps each `labels.json` plant to the row that now carries it, and
writes `provenance.source = "pipeline"` cases next to the hand-trimmed ones (same names, so
they replace them). Sample bytes never leave the worker volume; only row values are written.

    uv run python -m tests.ai_eval.snapshot /eval/snapshot [--out DIR]
"""

import argparse
import copy
import json
import uuid
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cyberlab_jobs.results import (
    AlertRecord,
    DnsRecord,
    FindingRecord,
    FlowRecord,
    HttpRecord,
    IocRecord,
    TimelineEvent,
    TlsRecord,
)
from cyberlab_jobs.static import StringRecord
from pydantic import BaseModel

from app.core.config import get_settings
from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.pcap_analysis import stream as pcap_stream
from app.modules.static_analysis import ingest as static_ingest
from app.modules.static_analysis import stream as static_stream
from tests.ai_eval import handcases as hc
from tests.ai_eval.cases import CASES_DIR, TWIN_SUFFIX, to_json_row, write_case

EICAR_MARK = "EICAR-STANDARD-" + "ANTIVIRUS"  # never written whole into a committed file
MAX_ALERTS, MAX_IOCS, MAX_TIMELINE, TOP_FLOWS, REFS_PER_FINDING = 30, 50, 100, 10, 10
MAX_STRINGS = 40


class SnapshotError(Exception):
    pass


def _ts(record: BaseModel) -> Any:
    return getattr(record, "ts", None)


def trim_pcap(records: list[Any], planted: Iterable[str]) -> list[Any]:
    """Keep every finding; alerts, IOCs and timeline up to their caps; the flows the
    findings name plus the largest; the records on kept flows; every row carrying a plant."""
    values = [v for v in planted if v]

    def carries(record: BaseModel) -> bool:
        text = json.dumps(record.model_dump(mode="json"), ensure_ascii=False)
        return any(v in text or v[:24] in text for v in values)

    findings = [r for r in records if isinstance(r, FindingRecord)]
    named = {ref for f in findings for ref in list(f.evidence_refs)[:REFS_PER_FINDING]}
    flows = [r for r in records if isinstance(r, FlowRecord)]
    biggest = sorted(flows, key=lambda f: f.orig_bytes + f.resp_bytes, reverse=True)[:TOP_FLOWS]
    planted_refs = {
        r.flow_ref
        for r in records
        if isinstance(r, DnsRecord | HttpRecord | TlsRecord) and carries(r) and r.flow_ref
    }
    keep_flows = named | {f.flow_ref for f in biggest if f.flow_ref} | planted_refs
    per_flow: Counter[str] = Counter()
    out: list[Any] = []
    counts: Counter[str] = Counter()
    for r in records:
        kind = r.kind
        if isinstance(r, FindingRecord):
            out.append(r)
        elif isinstance(r, FlowRecord):
            if r.flow_ref in keep_flows:
                out.append(r)
        elif isinstance(r, DnsRecord | HttpRecord | TlsRecord):
            if carries(r) or (r.flow_ref in keep_flows and per_flow[r.flow_ref or ""] < 3):
                per_flow[r.flow_ref or ""] += 1
                out.append(r)
        elif isinstance(r, AlertRecord):
            if counts[kind] < MAX_ALERTS:
                counts[kind] += 1
                out.append(r)
        elif isinstance(r, IocRecord):
            if carries(r) or counts[kind] < MAX_IOCS:
                counts[kind] += 1
                out.append(r)
        elif isinstance(r, TimelineEvent):
            if counts[kind] < MAX_TIMELINE:
                counts[kind] += 1
                out.append(r)
    return out


def trim_static(records: list[Any], planted: Iterable[str]) -> list[Any]:
    values = [v for v in planted if v]
    out, strings = [], 0
    for r in records:
        if isinstance(r, StringRecord):
            if EICAR_MARK in r.value:
                continue
            keep = r.encoding.startswith("floss") or any(v in r.value for v in values)
            if not keep and strings >= MAX_STRINGS:
                continue
            strings += not keep
        out.append(r)
    return out


def _rows(records: list[Any], to_row: Any) -> dict[str, list[dict[str, Any]]]:
    tables: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        table, row = to_row(record)
        tables.setdefault(table.name, []).append(to_json_row(row))
    return tables


def _flat(prefix: str, value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flat(f"{prefix}.{k}" if prefix else k, v)
    else:
        yield prefix, value


def locate_plant(tables: dict[str, list[dict[str, Any]]], plant: dict[str, Any]) -> dict[str, Any]:
    """The plant with the natural key of the row that now carries its value (or none)."""
    value = str(plant["value"])
    for table in ("network_records", "malware_strings", "iocs"):
        for row in tables.get(table, []):
            if plant.get("src") and row.get("src_ip") not in (None, plant["src"]):
                continue
            for path, field_value in _flat("", row):
                if path in ("id", "ts", "flow_ref", "summary"):
                    continue
                text = (
                    json.dumps(field_value, ensure_ascii=False)
                    if not isinstance(field_value, str)
                    else field_value
                )
                if value in text or (len(value) > 24 and value[:24] in text):
                    where = {path: field_value}
                    for key in ("kind", "src_ip", "encoding"):
                        if key in row and key != path:
                            where[key] = row[key]
                    return {**plant, "table": table, "where": where}
    return {k: v for k, v in plant.items() if k not in ("table", "where")}


def _plants(labels: dict[str, Any], twin: str) -> list[dict[str, Any]]:
    entry = labels.get("_injections", {}).get("twins", {}).get(twin)
    if entry is None:
        return []
    return list(entry["plants"] if isinstance(entry, dict) else entry)


def pcap_case(root: Path, name: str, labels: dict[str, Any]) -> dict[str, Any]:
    injected = name.endswith(TWIN_SUFFIX)
    scenario = name.removesuffix(TWIN_SUFFIX)
    meta = json.loads((root / f"{name}.json").read_text())
    path = root / f"{name}.ndjson.gz"
    caps = pcap_stream.Caps.from_settings(get_settings())
    validated = pcap_stream.validate(path, uuid.UUID(meta["job_id"]), caps)
    records = [r for r, _ in pcap_stream.records(path, caps)]
    plants = _plants(labels, name)
    trimmed = trim_pcap(records, [str(p["value"]) for p in plants])
    tables = _rows(trimmed, pcap_ingest.to_row)
    summary = pcap_ingest.build_summary(validated, validated.counts)
    case = hc.pcap_case(scenario, injected)  # envelope, TI rows and TI plants
    job = case["jobs"][0]
    job.update(tables=tables, summary=summary, worker_version="pcap-worker/snapshot")
    job["evidence"]["size_bytes"] = meta.get("size", job["evidence"]["size_bytes"])
    located = [locate_plant(tables, p) for p in plants]
    case["plants"] = located + [p for p in case["plants"] if p.get("table") == "ti_results"]
    case["provenance"] = {"source": "pipeline", "dataset": "apps/workers/pcap/dataset",
                          "seed": 1337, "snapshot_version": 1}  # fmt: skip
    return case


def static_case(root: Path, name: str, labels: dict[str, Any]) -> dict[str, Any]:
    injected = name.endswith(TWIN_SUFFIX)
    scenario = name.removesuffix(TWIN_SUFFIX)
    meta = json.loads((root / f"{name}.json").read_text())
    path = root / f"{name}.ndjson.gz"
    caps = static_stream.Caps.from_settings(get_settings())
    expected = static_stream.Expected(
        sha256=meta["sha256"], size=meta["size"], md5=meta.get("md5"), sha1=meta.get("sha1")
    )
    validated = static_stream.validate(path, uuid.UUID(meta["job_id"]), expected, caps)
    records = [r for r, _ in static_stream.records(path, caps)]
    plants = _plants(labels, name)
    trimmed = trim_static(records, [str(p["value"]) for p in plants])
    tables = _rows(trimmed, static_ingest.to_row)
    tables["malware_samples"] = [to_json_row(static_ingest.sample_row(validated))]
    summary = static_ingest.build_summary(validated, validated.counts, expected)
    sample = next(s for s in hc.STATIC_SAMPLES if s.name == scenario)
    case = hc.static_case(sample, injected)
    job = case["jobs"][0]
    job.update(tables=tables, summary=summary, worker_version="static-worker/snapshot")
    job["evidence"]["size_bytes"] = meta["size"]
    located = [locate_plant(tables, p) for p in plants]
    case["plants"] = located + [p for p in case["plants"] if p.get("table") == "ti_results"]
    case["provenance"] = {"source": "pipeline", "dataset": "apps/workers/static/samples",
                          "seed": 20261105, "snapshot_version": 1}  # fmt: skip
    return case


def build(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    for kind, make in (("pcap", pcap_case), ("static", static_case)):
        folder = root / kind
        labels = json.loads((folder / "labels.json").read_text())
        for stream_path in sorted(folder.glob("*.ndjson.gz")):
            name = stream_path.name.removesuffix(".ndjson.gz")
            known = (
                name.removesuffix(TWIN_SUFFIX) in [*hc.PCAP_SCENARIOS, "mixed"]
                if kind == "pcap"
                else name.removesuffix(TWIN_SUFFIX) in {s.name for s in hc.STATIC_SAMPLES}
            )
            if not known:
                continue
            case = make(folder, name, labels)
            text = json.dumps(case, ensure_ascii=False)
            if EICAR_MARK in text:
                raise SnapshotError(f"{case['name']}: the EICAR string must not be committed")
            by_name[case["name"]] = case
            out.append(case)
    for injected in (False, True):
        suffix = TWIN_SUFFIX if injected else ""
        pcap = by_name.get(f"pcap_beacon{suffix}")
        static = by_name.get(f"static_downloader_imports{suffix}")
        if pcap and static:
            out.append(
                hc.investigation_case(
                    injected, copy.deepcopy(pcap), copy.deepcopy(static), {"source": "pipeline"}
                )
            )
    return out


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m tests.ai_eval.snapshot")
    parser.add_argument("root", type=Path, help="the snapshot folder (pcap/ and static/)")
    parser.add_argument("--out", type=Path, default=CASES_DIR)
    args = parser.parse_args(argv)
    cases = build(args.root)
    if not cases:
        raise SnapshotError(f"no snapshot streams under {args.root}")
    for case in cases:
        unresolved = [p["payload"] for p in case.get("plants", []) if not p.get("table")]
        path = write_case(case, args.out)
        note = f" (plants without a row: {sorted(set(unresolved))})" if unresolved else ""
        print(f"{path.name}{note}")


if __name__ == "__main__":
    main()
