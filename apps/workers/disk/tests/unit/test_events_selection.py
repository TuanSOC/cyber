"""Storage selection, pass 2 (M9 phase 3, RT10; pure): per-category quotas keep the most recent
events, every finding-cited event is stored whatever the quotas (also one cited after its quota
was full), the header counts are known before the stream is written, and memory stays bounded
by the quotas, not by the number of events."""

import dataclasses
from pathlib import Path

from cyberlab_jobs.disk import DiskArtifact

from dataset import records
from disk_worker import detections
from disk_worker.normalize import events
from tests.unit.timeline_helpers import (
    PSORT_FIXTURES,
    WINDOWS_FIXTURES,
    manifest,
    psort_line,
    quota_limits,
    source,
    write_jsonl,
)

T = 1_790_000_000_000_000
A = DiskArtifact


def _mixed(tmp_path: Path) -> Path:
    rows = [psort_line("var/log/syslog", T + i * 1_000_000) for i in range(10)]
    rows += [psort_line("var/log/auth.log", T + i * 1_000_000) for i in range(5)]
    rows += [psort_line("etc/hostname", T)]  # `preprocess`: quota 0
    ev = write_jsonl(tmp_path / "events.jsonl", rows)
    return manifest(tmp_path, [source(ev, replay=True)])


def test_quotas_keep_the_most_recent_plus_every_cited_event(tmp_path: Path) -> None:
    limits = quota_limits({A.SYSLOG: 3, A.AUTH_LOG: 2})
    src = events.EventSource(_mixed(tmp_path), limits)
    assert len(list(src.events())) == 16
    # Ordinal 0 is the oldest syslog line (evicted by the quota) and 15 the preprocess file
    # (quota 0): both cited, both stored. 99 does not exist and is ignored.
    selection = src.select({0, 15, 99})
    assert selection.kept == frozenset({0, 7, 8, 9, 13, 14, 15})
    assert selection.read == {A.SYSLOG: 10, A.AUTH_LOG: 5, A.PREPROCESS: 1}
    assert selection.stored == {A.SYSLOG: 4, A.AUTH_LOG: 2, A.PREPROCESS: 1}
    assert [e.ordinal for e in selection.records()] == sorted(selection.kept)
    # The stream can be written twice (a retry): `records` re-reads the files each time.
    assert [e.ordinal for e in selection.records()] == sorted(selection.kept)


def test_select_runs_pass_one_itself_when_it_did_not_complete(tmp_path: Path) -> None:
    limits = quota_limits({A.SYSLOG: 3, A.AUTH_LOG: 2})
    src = events.EventSource(_mixed(tmp_path), limits)
    stream = src.events()
    next(stream)  # a detector that stopped early
    selection = src.select(set())
    assert selection.kept == frozenset({7, 8, 9, 13, 14})
    assert sum(selection.read.values()) == 16


def test_memory_is_bounded_by_the_quotas(tmp_path: Path) -> None:
    rows = [psort_line("var/log/syslog", T + i) for i in range(20_000)]
    ev = write_jsonl(tmp_path / "events.jsonl", rows)
    path = manifest(tmp_path, [source(ev, replay=True)])
    src = events.EventSource(path, quota_limits({A.SYSLOG: 10}))
    for _ in src.events():
        assert len(src._heaps[A.SYSLOG]) <= 10
    selection = src.select({5})
    assert len(selection.kept) == 11
    assert selection.stored == {A.SYSLOG: 11}
    assert len(src._categories) == 20_000  # one byte per event read, never the events


def test_events_cited_beyond_the_quota_are_stored(tmp_path: Path) -> None:
    """Phase 6's detections over the replayed Windows rows: with room for one EVTX event and
    none elsewhere, every event a finding cites is still stored (RT10)."""
    sources = [
        source(PSORT_FIXTURES / n, os="windows", profile="triage", replay=True)
        for n in WINDOWS_FIXTURES
    ]
    path = manifest(tmp_path, sources)
    limits = quota_limits({A.EVTX: 1})
    src = events.EventSource(path, limits)
    view = records.view([records.partition(1, "ntfs", "windows")], [], [])
    found = detections.run(dataclasses.replace(view, events=src.events), limits)
    assert found.cited_events, "the replayed rows raise findings that cite events"
    selection = src.select(set(found.cited_events))
    assert found.cited_events <= selection.kept
    assert sum(selection.stored.values()) == len(selection.kept) > 1
    stored = {e.ordinal for e in selection.records()}
    assert stored == selection.kept
