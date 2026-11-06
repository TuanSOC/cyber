"""The Plaso event normalizer (M9 phase 3; pure, over hand-written psort `json_line` rows, no
Plaso): field maps, paths back to the original tree, the collect manifest checked against root's
plan, hostile rows (dropped and counted), the attribute budget and the ordinal order."""

import json
from datetime import UTC, datetime
from pathlib import Path

from cyberlab_jobs.disk import MAX_ATTRIBUTES_BYTES, DiskArtifact, DiskEventRecord

from disk_worker.detections import evtx_fields
from disk_worker.normalize import events
from tests.unit.phase2_helpers import limits
from tests.unit.timeline_helpers import (
    LINUX_FIXTURES,
    PSORT_EXTRA,
    PSORT_FIXTURES,
    WINDOWS_FIXTURES,
    collect_outputs,
    manifest,
    psort_line,
    source,
    write_jsonl,
)

T = 1_790_000_000_000_000


def _all(path: Path, **overrides: object) -> tuple[list[DiskEventRecord], events.Counts]:
    src = events.EventSource(path, limits(**overrides))
    out = list(src.events())
    return out, src.counts


def _replay(tmp_path: Path, names: tuple[str, ...], os: str, profile: str) -> Path:
    sources = [
        source(PSORT_FIXTURES / n, os=os, profile=profile, replay=True) for n in names
    ]
    return manifest(tmp_path, sources)


def test_windows_fixtures_normalize(tmp_path: Path) -> None:
    out, counts = _all(_replay(tmp_path, WINDOWS_FIXTURES, "windows", "full"))
    assert counts.accepted == len(out) == 15
    assert not counts.dropped and counts.bad_lines == 0
    assert [e.ordinal for e in out] == list(range(15))
    logon = out[0]
    assert logon.artifact == DiskArtifact.EVTX
    assert logon.path == "Windows/System32/winevt/Logs/Security.evtx"
    assert logon.ts == datetime.fromtimestamp(T / 1e6, UTC)
    assert (logon.parser, logon.data_type, logon.ts_desc) == (
        "winevtx",
        "windows:evtx:record",
        "Creation Time",
    )
    assert logon.file is None and logon.partition_index == 1
    assert logon.attributes["event_identifier"] == 4624
    assert logon.attributes["source_name"] == "Microsoft-Windows-Security-Auditing"
    assert logon.attributes[evtx_fields.STRINGS_COUNT] == 6
    assert logon.attributes["strings.5"] == "203.0.113.50"
    assert logon.attributes["record_number"] == 1000
    by_type = {e.data_type: e for e in out}
    run = by_type["windows:registry:run"]
    assert run.artifact == DiskArtifact.REGISTRY_USER
    assert run.attributes["entries_count"] == 1
    assert run.attributes["entries.0"].endswith("updater.exe")
    assert by_type["windows:registry:service"].artifact == DiskArtifact.REGISTRY_SYSTEM
    assert by_type["windows:registry:service"].attributes["image_path"].endswith("updater.exe")
    assert by_type["windows:prefetch:execution"].attributes["path_hints.0"].endswith("UPDATER.EXE")
    assert by_type["windows:registry:amcache"].artifact == DiskArtifact.AMCACHE
    mft = by_type["fs:stat:ntfs"]
    assert mft.artifact == DiskArtifact.MFT
    assert mft.attributes["file_reference"] == str(1234 | (1 << 48))  # 64-bit: a string
    assert by_type["chrome:history:page_visited"].artifact == DiskArtifact.BROWSER


def test_full_only_artifacts_are_unknown_paths_in_triage(tmp_path: Path) -> None:
    out, counts = _all(_replay(tmp_path, WINDOWS_FIXTURES, "windows", "triage"))
    assert len(out) == 13
    assert counts.dropped == {"unknown_path": 2}  # $MFT and the Chrome history
    assert {e.artifact for e in out} == {
        DiskArtifact.EVTX,
        DiskArtifact.REGISTRY_USER,
        DiskArtifact.REGISTRY_SYSTEM,
        DiskArtifact.AMCACHE,
        DiskArtifact.PREFETCH,
        DiskArtifact.LNK,
    }


def test_linux_fixtures_through_the_collect_manifest(tmp_path: Path) -> None:
    collected, plan = collect_outputs(
        tmp_path,
        1,
        [
            ("var/log/syslog", "var/log/syslog", DiskArtifact.SYSLOG, 18),
            ("var/log/auth.log", "var/log/auth.log", DiskArtifact.AUTH_LOG, 19),
            ("var/log/wtmp", "var/log/wtmp", DiskArtifact.UTMP, 20),
            ("root/.bash_history", "root/.bash_history", DiskArtifact.SHELL_HISTORY, 21),
        ],
    )
    sources = [
        source(PSORT_FIXTURES / n, collected=collected, plan=plan) for n in LINUX_FIXTURES
    ]
    out, counts = _all(manifest(tmp_path, sources))
    assert len(out) == 4
    assert counts.dropped == {"bad_timestamp": 3}  # each file's `__fixture__` row
    by_path = {e.path: e for e in out}
    assert by_path["var/log/auth.log"].artifact == DiskArtifact.AUTH_LOG
    assert by_path["var/log/auth.log"].attributes["address"] == "198.51.100.7"
    assert by_path["var/log/auth.log"].file is not None
    assert by_path["var/log/auth.log"].file.meta_addr == 19
    assert by_path["root/.bash_history"].attributes["command"].startswith("curl -s")
    assert by_path["var/log/wtmp"].attributes["ip_address"] == "198.51.100.7"


def test_a_sanitized_target_maps_back_to_the_original_path(tmp_path: Path) -> None:
    target = "home/j_rg_3fa1c2/.bash_history"  # the collect sanitizer's name (RT31)
    collected, plan = collect_outputs(
        tmp_path, 2, [(target, "home/jürg/.bash_history", DiskArtifact.SHELL_HISTORY, 44)]
    )
    rows = [
        psort_line(
            target,
            T,
            data_type="bash:history:command",
            parser="text/bash_history",
            message="Command executed: id",
            command="id",
        )
    ]
    ev = write_jsonl(tmp_path / "events.jsonl", rows)
    out, _ = _all(
        manifest(tmp_path, [source(ev, partition_index=2, collected=collected, plan=plan)])
    )
    assert [(e.path, e.partition_index, e.file and e.file.meta_addr) for e in out] == [
        ("home/jürg/.bash_history", 2, 44)
    ]


def test_plaso_paths_relative_to_the_source_also_map(tmp_path: Path) -> None:
    collected, plan = collect_outputs(
        tmp_path, 1, [("var/log/syslog", "var/log/syslog", DiskArtifact.SYSLOG, 18)]
    )
    row = psort_line("var/log/syslog", T)
    row["filename"] = "/var/log/syslog"  # Plaso may strip the mount path
    row.pop("display_name")
    row.pop("pathspec")
    ev = write_jsonl(tmp_path / "events.jsonl", [row])
    out, _ = _all(manifest(tmp_path, [source(ev, collected=collected, plan=plan)]))
    assert [e.path for e in out] == ["var/log/syslog"]


def test_a_lying_collect_manifest_maps_nothing(tmp_path: Path) -> None:
    collected, plan = collect_outputs(
        tmp_path,
        1,
        [
            ("var/log/syslog", "var/log/syslog", DiskArtifact.SYSLOG, 18),
            ("var/log/auth.log", "var/log/auth.log", DiskArtifact.AUTH_LOG, 19),
        ],
    )
    rows = [json.loads(line) for line in collected.read_text().splitlines()]
    rows[0]["artifact"] = "evtx"  # the probe claims another category
    rows[1]["meta_addr"] = 999  # ... or another file
    write_jsonl(collected, rows)
    rows = [psort_line("var/log/syslog", T), psort_line("var/log/auth.log", T)]
    ev = write_jsonl(tmp_path / "events.jsonl", rows)
    out, counts = _all(manifest(tmp_path, [source(ev, collected=collected, plan=plan)]))
    assert out == []
    assert counts.dropped == {"unknown_path": 2}


def test_hostile_rows_are_dropped_and_counted(tmp_path: Path) -> None:
    collected, plan = collect_outputs(
        tmp_path, 1, [("var/log/syslog", "var/log/syslog", DiskArtifact.SYSLOG, 18)]
    )
    hostile = PSORT_EXTRA / "hostile" / "edge_cases.jsonl"
    out, counts = _all(manifest(tmp_path, [source(hostile, collected=collected, plan=plan)]))
    assert counts.bad_lines == 2  # the 70 KB line and the invalid JSON
    assert counts.dropped == {"bad_timestamp": 4, "unknown_path": 2, "not_event": 1}
    assert len(out) == 1
    e = out[0]
    assert "\x00" not in e.message and len(e.message) == 2048
    assert e.ts_desc == "ContentModification Time"
    assert e.attributes["hostname"] == "srv-01x"
    assert e.attributes["pid"] == str(2**60)  # beyond 2^53: a string
    assert len(e.attributes["body"]) <= 1024
    assert "severity" not in e.attributes and "facility" not in e.attributes  # float, object
    assert "unknown_field" not in e.attributes


def test_evtx_attributes_keep_positions_within_the_budget() -> None:
    raw = {
        "event_identifier": 4624,
        "source_name": "Microsoft-Windows-Security-Auditing",
        "record_number": 7,
        "computer_name": "WKS-01",
        "user_sid": "S-1-5-18",
        "strings": ["s" * 2000] * 27,
        "xml_string": "<Event>never kept</Event>",
    }
    attrs = events.attributes_of("windows:evtx:record", raw)
    assert len(attrs) == 32
    assert attrs["strings_count"] == 27 and "strings.26" in attrs
    assert "xml_string" not in attrs and "user_sid" not in attrs  # the 33rd slot is cut
    compact = json.dumps(attrs, ensure_ascii=False, separators=(",", ":"))
    assert len(compact.encode()) + 2 * len(attrs) <= MAX_ATTRIBUTES_BYTES
    record = evtx_fields.read(
        DiskEventRecord(
            ordinal=0,
            ts=datetime(2026, 10, 1, tzinfo=UTC),
            ts_desc="Creation Time",
            artifact=DiskArtifact.EVTX,
            parser="winevtx",
            data_type="windows:evtx:record",
            partition_index=1,
            path="Windows/System32/winevt/Logs/Security.evtx",
            message="m",
            attributes=attrs,
        )
    )
    assert record is not None and record.fields is not None  # the 27-string layout is known


def test_extra_fixtures_cover_more_data_types(tmp_path: Path) -> None:
    sources = [
        source(PSORT_EXTRA / "windows_extra.jsonl", os="windows", profile="full", replay=True),
        source(PSORT_EXTRA / "linux_extra.jsonl", partition_index=2, replay=True),
    ]
    out, counts = _all(manifest(tmp_path, sources))
    assert not counts.dropped
    by_type = {e.data_type: e for e in out}
    assert by_type["windows:registry:bam"].attributes["binary_path"].endswith("updater.exe")
    assert by_type["windows:metadata:deleted_item"].artifact == DiskArtifact.RECYCLE_BIN
    assert by_type["syslog:cron:task_run"].attributes["command"] == "/tmp/.x/miner"
    assert by_type["syslog:ssh:failed_connection"].attributes["username"] == "admin"
    assert by_type["dpkg:line"].artifact == DiskArtifact.PACKAGES
    assert by_type["shell:zsh:history"].artifact == DiskArtifact.SHELL_HISTORY
    assert by_type["shell:zsh:history"].partition_index == 2
    logon = next(e for e in out if e.attributes.get("event_identifier") == 4624)
    assert len(logon.attributes) == 32
    assert logon.attributes["strings.18"] == "203.0.113.60"


def test_ordinals_run_across_sources_and_the_read_cap_truncates(tmp_path: Path) -> None:
    rows = [psort_line("var/log/syslog", T + i) for i in range(5)]
    a = write_jsonl(tmp_path / "a.jsonl", rows)
    b = write_jsonl(tmp_path / "b.jsonl", rows)
    path = manifest(
        tmp_path,
        [source(a, replay=True), source(b, partition_index=2, replay=True)],
    )
    out, counts = _all(path)
    assert [e.ordinal for e in out] == list(range(10))
    assert [e.partition_index for e in out] == [1] * 5 + [2] * 5
    capped, capped_counts = _all(path, max_events_read=7, max_events_stored=7, event_quotas={
        a.value: (7 if a == DiskArtifact.EVTX else 0) for a in DiskArtifact
    })
    assert len(capped) == 7 and capped_counts.truncated


def test_the_module_functions_match_the_source(tmp_path: Path) -> None:
    path = _replay(tmp_path, LINUX_FIXTURES, "linux", "triage")
    lim = limits()
    first = [e.ordinal for e in events.iter_events(path, lim)]
    assert first == [0, 1, 2, 3]
    assert [e.ordinal for e in events.select_events(path, lim, set())] == first
