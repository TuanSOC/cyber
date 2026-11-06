"""M9 phase 7 (HEAVY): a `disk.v1` stream at every cap ingests within the framing bounds, the
1 GiB `disk-ingest-worker` limit and DISK_INGEST_TIMEOUT_S, and the numbers are recorded.

A synthetic stream at the settings' caps (500 000 files, 250 000 events, 5 000 findings, 20 000
IOCs, 5 000 timeline lines by default; every file hashed, every finding citing 50 refs) is
checked against the framing bounds, then handed off and ingested in one transaction. The
ingest time, the peak RSS of this process (the ingest runs in it, as on the disk ingest
worker) and the Postgres size per job are printed as one JSON line for the metric report
(phase 13 copies it).

Skipped unless `DISK_INGEST_CAPS=1`: the parent runs it alone, after the lanes:

    DISK_INGEST_CAPS=1 scripts/lane-test.sh 6 uv run pytest -q -p no:cacheprovider -s \\
        tests/integration/test_disk_ingest_caps.py
"""

import gzip
import hashlib
import json
import os
import resource
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.workers import ingest
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.pcap_results import put_result

pytestmark = pytest.mark.skipif(
    os.environ.get("DISK_INGEST_CAPS") != "1", reason="heavy: set DISK_INGEST_CAPS=1 (parent only)"
)

GIB = 1024**3
TABLES = ("disk_files", "disk_events", "analysis_findings", "iocs", "analysis_timeline")


def _hex(seed: str, n: int) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n].ljust(n, "0")


def _write_stream(path: Path, job_id: uuid.UUID) -> dict[str, int]:
    """The capped stream, written line by line (never held in memory)."""
    settings = get_settings()
    caps = {
        "file": settings.disk_max_files,
        "event": settings.disk_max_events,
        "finding": settings.disk_max_findings,
        "ioc": settings.disk_max_iocs,
        "timeline": settings.disk_max_timeline,
    }
    header = dr.retarget(dr.parsed(dr.WINDOWS), job_id)[0]
    digest = hashlib.sha256()
    lines = 0
    raw = 0
    with gzip.open(path, "wb", compresslevel=6) as out:

        def put(obj: dict[str, Any]) -> None:
            nonlocal lines, raw
            data = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
            digest.update(data)
            out.write(data)
            lines += 1
            raw += len(data)

        put(header)
        put(
            {
                "kind": "partition",
                "index": 1,
                "start_sector": 2048,
                "length_sectors": 2**31,
                "vs_flags": "alloc",
                "fs_type": "ntfs",
                "fs_status": "ok",
                "os": "windows",
            }
        )
        for n in range(caps["file"]):
            directory = f"Users/user{n % 50:02d}/AppData/Local/Packages/app{n % 997:03d}"
            put(
                {
                    "kind": "file",
                    "partition_index": 1,
                    "meta_addr": 1000 + n,
                    "meta_seq": 1,
                    "path": f"{directory}/file{n:07d}.dat",
                    "parent_addr": 5 + n % 997,
                    "name": f"file{n:07d}.dat",
                    "ext": "dat",
                    "type": "reg",
                    "flags": 1,
                    "size": 4096 + n,
                    "mtime": "2026-10-01T08:00:00Z",
                    "atime": "2026-10-01T08:00:00Z",
                    "ctime": "2026-10-01T08:00:00Z",
                    "crtime": "2026-09-01T08:00:00Z",
                    "magic": "other",
                    "hash_status": "hashed",
                    "md5": _hex(f"md5{n}", 32),
                    "sha1": _hex(f"sha1{n}", 40),
                    "sha256": _hex(f"sha256{n}", 64),
                }
            )
        for n in range(caps["event"]):
            put(
                {
                    "kind": "event",
                    "ordinal": n,
                    "ts": "2026-10-01T08:30:00Z",
                    "ts_desc": "Creation Time",
                    "artifact": "evtx",
                    "parser": "winevtx",
                    "data_type": "windows:evtx:record",
                    "partition_index": 1,
                    "path": "Windows/System32/winevt/Logs/Security.evtx",
                    "file": {"partition_index": 1, "meta_addr": 1000 + n, "meta_seq": 1},
                    "message": f"[4624 / 0x1210] Logon Type: 3 Account: user{n % 50} " + "x" * 120,
                    "attributes": {"event_identifier": 4624, "logon_type": 3},
                }
            )
        for n in range(caps["finding"]):
            refs = [f"file:1:{1000 + n * 50 + i}:1" for i in range(25)]
            refs += [f"event:{(n * 25 + i) % caps['event']}" for i in range(25)]
            put(
                {
                    "kind": "finding",
                    "finding_id": str(uuid.uuid5(uuid.NAMESPACE_OID, f"f{n}")),
                    "type": "disk_exec_user_writable",
                    "title": "Executable in a user-writable path",
                    "description": "Synthetic capped finding (an observation, not a verdict).",
                    "severity": "low",
                    "confidence": 0.5,
                    "detection_method": "heuristic:disk_exec_user_writable@1",
                    "ts": "2026-10-01T08:50:00Z",
                    "evidence_refs": refs,
                    "attributes": {},
                }
            )
        for n in range(caps["ioc"]):
            put(
                {
                    "kind": "ioc",
                    "type": "file_sha256",
                    "value": _hex(f"ioc{n}", 64),
                    "first_seen": "2026-10-01T08:50:00Z",
                    "last_seen": "2026-10-01T08:50:00Z",
                    "count": 1,
                    "source": "disk",
                }
            )
        for n in range(caps["timeline"]):
            put(
                {
                    "kind": "timeline",
                    "ts": "2026-10-01T08:30:00Z",
                    "event": "logon",
                    "title": f"Logon {n}",
                    "severity": "info",
                    "ref": f"event:{n}",
                }
            )
        trailer = {"kind": "trailer", "line_count": lines, "sha256": digest.hexdigest()}
        out.write(json.dumps(trailer).encode() + b"\n")
    return {"lines": lines + 1, "decompressed": raw, "compressed": path.stat().st_size, **caps}


async def _sizes() -> dict[str, int]:
    async with tenant_session(None, None) as session:
        return {
            t: int(await session.scalar(text(f"SELECT pg_total_relation_size('{t}')")) or 0)
            for t in TABLES
        }


async def test_a_stream_at_every_cap_ingests_within_the_bounds(
    sent: SentJobs, handoffs: HandOffs, tmp_path: Path
) -> None:
    settings = get_settings()
    _, _, item = await dr.queued_job(sent)
    path = tmp_path / "capped.ndjson.gz"
    shape = _write_stream(path, item.job_id)
    # The framing bounds the worker is held to (a capped stream must fit them).
    assert shape["compressed"] <= settings.disk_max_result_bytes
    assert shape["decompressed"] <= settings.disk_max_result_decompressed_bytes
    assert shape["lines"] <= settings.disk_max_result_lines()

    version = put_result(item.organization_id, item.job_id, path.read_bytes())
    await ingest.handle_event(dr.finished(item, version))
    before = await _sizes()
    started = time.monotonic()
    await ingest.handle_disk_ingest(handoffs[-1])
    elapsed = time.monotonic() - started
    after = await _sizes()
    job = await dr.job_of(item)
    assert job.status == "succeeded", job.error_code
    peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024  # KiB on Linux
    record = {
        "metric": "disk_ingest_caps",
        "shape": shape,
        "ingest_s": round(elapsed, 1),
        "peak_rss_bytes": peak_rss,
        "pg_bytes": {t: after[t] - before[t] for t in TABLES},
        "counts": job.summary["counts"],
    }
    print(json.dumps(record))
    assert peak_rss <= GIB, record
    assert elapsed < settings.disk_ingest_timeout_s, record
