# ruff: noqa: E501 - test data tables
"""`detections.run` as a whole: the streaming `Detector` API, correlation, stable ids, valid
`disk.v1` records, caps and `truncated`, cited events for pass 2 (RT10), out-of-range times and a
bounded-memory pass over a large synthetic event stream."""

import gc
import os
import tracemalloc
from collections.abc import Iterator
from datetime import timedelta

import pytest
from cyberlab_jobs.disk import DISK_RECORD_ADAPTER, DiskEventRecord

from dataset import records as r
from dataset.baselines import Draft
from dataset.generate import build
from disk_worker import detections
from disk_worker.detections import base

LIMITS = r.limits()
NTFS, EXT = r.NTFS_PARTITION, r.EXT_PARTITION
T0 = r.ts("2026-10-06T10:00:00")
SECURITY = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"


def draft() -> Draft:
    return Draft(
        "unit", "triage", [r.partition(EXT, "ext4", "linux"), r.partition(NTFS, "ntfs", "windows")]
    )


def run(d: Draft, **caps: int) -> detections.DiskDetectionOutput:
    out = detections.run(d.view(), r.limits(**caps) if caps else LIMITS)
    assert isinstance(out, detections.DiskDetectionOutput)
    return out


# --- records, ids, streaming --------------------------------------------------------------------


def test_every_output_line_is_a_valid_disk_record() -> None:
    out = detections.run(build("win_correlated"), LIMITS)
    for item in [*out.findings, *out.iocs, *out.timeline]:
        DISK_RECORD_ADAPTER.validate_python(item.model_dump())
    assert len({f.finding_id for f in out.findings}) == len(out.findings)


def test_output_is_deterministic_and_ids_are_stable() -> None:
    first = detections.run(build("win_persistence"), LIMITS)
    second = detections.run(build("win_persistence"), LIMITS)
    assert first == second


def test_detector_streaming_api_equals_run() -> None:
    view = build("win_remote_logon")
    detector = detections.Detector(view, LIMITS)
    for event in view.events():
        detector.observe(event)
    assert detector.finish() == detections.run(view, LIMITS)
    with pytest.raises(RuntimeError):
        detector.finish()


def test_events_are_read_once() -> None:
    calls = 0
    view = build("linux_remote_logon")
    inner = view.events

    def counted() -> Iterator[DiskEventRecord]:
        nonlocal calls
        calls += 1
        return inner()

    detections.run(
        type(view)(view.profile, view.image, view.partitions, view.files, counted), LIMITS
    )
    assert calls == 1


# --- correlation ----------------------------------------------------------------------------------


def test_two_heuristics_on_one_path_add_one_correlated_finding() -> None:
    d = draft()
    d.add_file(NTFS, "Users/alice/Downloads/invoice.pdf.exe", magic="pe", mtime=T0)
    out = run(d)
    assert sorted(f.type for f in out.findings) == [
        "disk_correlated_indicators",
        "disk_double_extension",
        "disk_exec_user_writable",
    ]
    corr = next(f for f in out.findings if f.type == "disk_correlated_indicators")
    others = {str(f.finding_id) for f in out.findings if f is not corr}
    assert {
        x.removeprefix("finding:") for x in corr.evidence_refs if x.startswith("finding:")
    } == others
    assert corr.attributes["subject"] == "users/alice/downloads/invoice.pdf.exe"
    assert corr.severity == "medium" and corr.confidence >= 0.8
    assert (
        next(f for f in out.findings if f.type == "disk_exec_user_writable").severity == "low"
    )  # never raised


def test_time_window_correlation_and_its_limits() -> None:
    d = draft()
    d.add_evtx(T0, EVENTLOG, 1102, r.log_cleared_strings())
    d.add_evtx(T0 + timedelta(minutes=9), SECURITY, 4720, r.user_created_strings("x"))
    # 11 minutes after the first: outside the window
    d.add_evtx(T0 + timedelta(minutes=30), SECURITY, 4624, r.logon_strings("a", 10, "203.0.113.5"))
    d.add_evtx(T0 + timedelta(minutes=41), SECURITY, 4720, r.user_created_strings("y"))
    out = run(d)
    corr = [f for f in out.findings if f.type == "disk_correlated_indicators"]
    assert [c.attributes["subject"] for c in corr] == ["window:2026-10-06T10:00:00Z"]


def test_one_method_twice_and_signatures_do_not_correlate() -> None:
    d = draft()
    d.add_file(NTFS, "Users/Public/a.exe", magic="pe", mtime=T0)
    d.add_file(NTFS, "Users/Public/b.exe", magic="pe", mtime=T0)
    d.add_file(
        NTFS,
        "Users/Public/c.exe",
        magic="pe",
        mtime=T0,
        known="bad",
        known_set="ops",
        yara=["image.x.R"],
    )
    out = run(d)
    assert "disk_correlated_indicators" not in {f.type for f in out.findings}


# --- caps and truncation -------------------------------------------------------------------------


def noisy(n: int) -> Draft:
    d = draft()
    for i in range(n):
        d.add_file(
            NTFS,
            f"Users/Public/x{i}.exe",
            magic="pe",
            mtime=T0 + timedelta(hours=1, minutes=30 * i),
        )
    d.add_evtx(T0, EVENTLOG, 1102, r.log_cleared_strings())
    return d


def test_findings_cap_keeps_the_most_severe_and_flags() -> None:
    out = run(noisy(12), max_findings=5)
    assert len(out.findings) == 5 and out.truncated and out.truncated_parts["findings"]
    assert out.findings[0].type == "disk_log_cleared"  # medium first
    # every cited event belongs to a kept finding
    refs = {
        int(x.split(":")[1])
        for f in out.findings
        for x in f.evidence_refs
        if x.startswith("event:")
    }
    assert out.cited_events == refs


def test_ioc_and_timeline_caps() -> None:
    out = run(noisy(12), max_iocs=4, max_timeline=3)
    assert len(out.iocs) == 4 and len(out.timeline) == 3
    assert out.truncated_parts.get("iocs") and out.truncated_parts.get("timeline")
    assert all(e.event == "finding" for e in out.timeline)  # finding entries go first


def test_detector_state_budget_flags_instead_of_growing() -> None:
    d = draft()
    for k in range(50):
        d.add_evtx(
            T0 + timedelta(minutes=k),
            SECURITY,
            4624,
            r.logon_strings(f"u{k}", 3, f"198.51.100.{k + 1}"),
        )
    view = d.view()
    detector = detections.Detector(view, LIMITS, max_keys=10)
    for event in view.events():
        detector.observe(event)
    out = detector.finish()
    assert out.truncated and out.truncated_parts["detector_state"]
    assert len(out.findings) == 10


def test_nothing_found_is_not_truncated() -> None:
    out = detections.run(build("debian_server"), LIMITS)
    assert out.findings == [] and out.iocs == [] and out.timeline == [] and not out.truncated
    assert out.cited_events == set()


# --- RT10, timeline, times -----------------------------------------------------------------------


def test_timeline_refs_are_cited_events_or_findings() -> None:
    out = detections.run(build("win_correlated"), LIMITS)
    ids = {str(f.finding_id) for f in out.findings}
    for entry in out.timeline:
        if entry.event == "finding":
            assert entry.ref in ids
        else:
            assert (
                entry.ref is not None and int(entry.ref.removeprefix("event:")) in out.cited_events
            )
    assert [e.ts for e in out.timeline] == sorted(e.ts for e in out.timeline)


def test_pass_two_keeps_every_cited_event() -> None:
    """A storage pass that keeps per-category quotas *plus* `cited_events` (phase 3) never drops
    an event a finding cites, even an early one cited by a burst found at the end."""
    view = build("win_remote_logon")
    out = detections.run(view, LIMITS)
    quota = 10  # newest 10 evtx events only
    events = list(view.events())
    newest = {e.ordinal for e in sorted(events, key=lambda e: e.ts)[-quota:]}
    stored = newest | out.cited_events
    for finding in out.findings:
        for ref in finding.evidence_refs:
            if ref.startswith("event:"):
                assert int(ref[6:]) in stored
    assert out.cited_events - newest  # the quota alone would have lost evidence


def test_out_of_range_times_use_the_reference_time() -> None:
    d = draft()
    d.add_evtx(T0, EVENTLOG, 1102, r.log_cleared_strings())
    d.add_file(NTFS, "Users/Public/old.exe", magic="pe", mtime=r.ts("1601-01-02T00:00:00"))
    out = run(d)
    old = next(f for f in out.findings if f.type == "disk_exec_user_writable")
    assert old.ts == T0
    corr = [f for f in out.findings if f.type == "disk_correlated_indicators"]
    assert corr == []  # an unusable time takes no part in the windows


def test_window_without_events_uses_file_times() -> None:
    d = draft()
    d.add_file(EXT, "etc/hostname", mtime=T0)
    d.add_file(EXT, "etc/cron.d/new", mtime=T0 - timedelta(days=2))
    d.add_file(EXT, "etc/cron.d/old", mtime=T0 - timedelta(days=20))
    assert [f.attributes["subject"] for f in run(d).findings] == ["etc/cron.d/new"]


# --- bounded memory ---------------------------------------------------------------------------------


def _stream(n: int) -> Iterator[DiskEventRecord]:
    """`n` synthetic events (built without validation for speed): benign EVTX logons, syslog and
    shell lines, with a failure burst at the very start (cited at the end, RT10)."""
    logon = r.evtx(0, T0, SECURITY, 4624, r.logon_strings("SYSTEM", 5, "-"))
    burst = r.evtx(0, T0, SECURITY, 4625, r.failed_logon_strings("admin", "198.51.100.66"))
    cron = r.event(
        0,
        T0,
        "syslog",
        "syslog:line",
        "var/log/syslog",
        "[CRON, pid: 1] (root) CMD (cd / && run-parts /etc/cron.hourly)",
        {"reporter": "CRON", "body": "(root) CMD (cd / && run-parts /etc/cron.hourly)"},
        part=EXT,
    )
    shell = r.event(
        0,
        T0,
        "shell_history",
        "bash:history:command",
        "home/a/.bash_history",
        "Command executed: ls",
        {"command": "ls -la"},
        part=EXT,
    )
    templates = (logon, cron, shell)
    for i in range(n):
        source = burst if i < 25 else templates[i % 3]
        when = T0 + timedelta(seconds=i if i < 25 else 30 + i)
        yield DiskEventRecord.model_construct(**{**dict(source), "ordinal": i, "ts": when})


def _peak(n: int) -> tuple[int, detections.DiskDetectionOutput]:
    view = r.mini(label="stream")
    view = type(view)(view.profile, view.image, view.partitions, view.files, lambda: _stream(n))
    gc.collect()
    tracemalloc.start()
    try:
        out = detections.run(view, LIMITS)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert isinstance(out, detections.DiskDetectionOutput)
    return peak, out


def test_streaming_pass_keeps_memory_bounded() -> None:
    """Success criterion: a 2 M-event stream stays under 300 MiB RSS. The pass keeps aggregates
    only, so the heap it allocates does not grow with the number of events: a stream six times
    longer peaks at about the same size (DISK_DETECTIONS_STREAM_EVENTS raises N; the 2 M run is
    the same code inside the worker image)."""
    n = int(os.environ.get("DISK_DETECTIONS_STREAM_EVENTS", "60000"))
    small, _ = _peak(n // 6)
    peak, out = _peak(n)
    assert peak < 64 * 1024**2, peak
    assert peak < small * 1.5 + 2 * 1024**2, (small, peak)
    (burst,) = out.findings
    assert burst.type == "disk_logon_failure_burst" and min(out.cited_events) == 0
    assert out.counts["events"] == n


def test_budget_constant_is_sane() -> None:
    assert base.MAX_DETECTOR_KEYS >= 10_000 and base.MAX_CITED_EVENTS <= base.MAX_REFS
