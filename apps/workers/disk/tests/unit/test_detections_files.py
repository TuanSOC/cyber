# ruff: noqa: E501 - test data tables (long literal paths)
"""File-listing rules: executables in user-writable classes, double extensions and RTLO,
extension mismatches, executable named streams, YARA hits and hash-set matches; `known = good`
never suppresses a heuristic (RT18)."""

from cyberlab_jobs.disk import DiskFileRecord
from cyberlab_jobs.results import FindingRecord

from dataset import records as r
from disk_worker import detections

LIMITS = r.limits()
NTFS, EXT = r.NTFS_PARTITION, r.EXT_PARTITION
WHEN = r.ts("2026-10-06T10:00:00")


def run(*files: DiskFileRecord, yara: dict[str, str] | None = None) -> list[FindingRecord]:
    return detections.run(r.mini(files), LIMITS, yara_severity=yara).findings  # type: ignore[arg-type]


def kinds(findings: list[FindingRecord]) -> list[tuple[str, str]]:
    return sorted((f.type, f.severity) for f in findings)


def test_pe_in_temp_is_low_and_cites_the_file() -> None:
    m = r.FileMaker()
    f = m.file(NTFS, "Users/alice/AppData/Local/Temp/x.exe", magic="pe", mtime=WHEN)
    (finding,) = run(f)
    assert (finding.type, finding.severity, finding.detection_method) == (
        "disk_exec_user_writable",
        "low",
        "heuristic:disk_exec_user_writable@1",
    )
    assert finding.evidence_refs == [f"file:{NTFS}:{f.meta_addr}:1"]
    assert finding.attributes["subject"] == f.path and finding.attributes["sha256"] == f.sha256
    assert finding.ts == WHEN


def test_known_good_never_suppresses_a_heuristic() -> None:
    m = r.FileMaker()
    f = m.file(
        NTFS,
        "Users/Public/tool.exe",
        magic="pe",
        mtime=WHEN,
        known="good",
        known_set="nsrl-minimal",
    )
    (finding,) = run(f)
    assert finding.type == "disk_exec_user_writable" and finding.attributes["known"] == "good"


def test_elf_in_hidden_home_dir_and_case_sensitivity() -> None:
    m = r.FileMaker()
    assert kinds(run(m.file(EXT, "home/a/.x/run", magic="elf", mtime=WHEN))) == [
        ("disk_exec_user_writable", "low")
    ]
    # ext is case-sensitive: TMP is not /tmp
    assert run(m.file(EXT, "TMP/run", magic="elf", mtime=WHEN)) == []
    # NTFS is not: TEMP in any case is the temp class
    assert (
        len(run(m.file(NTFS, "USERS/ALICE/APPDATA/LOCAL/TEMP/RUN.EXE", magic="pe", mtime=WHEN)))
        == 1
    )


def test_exclusions_non_executables_streams_and_deleted_entries_are_silent() -> None:
    m = r.FileMaker()
    assert (
        run(
            m.file(
                NTFS,
                "ProgramData/Microsoft/Windows Defender/Platform/4.18.1-0/MsMpEng.exe",
                magic="pe",
                mtime=WHEN,
            ),
            m.file(NTFS, "Users/alice/AppData/Local/Temp/notes.txt", magic="other", mtime=WHEN),
            m.file(NTFS, "Users/alice/AppData/Local/Temp/old.exe", deleted=True, mtime=WHEN),
            m.file(EXT, "home/alice/.cache/pip/x.so", magic="elf", mtime=WHEN),
        )
        == []
    )


def test_double_extension_and_near_misses() -> None:
    m = r.FileMaker()
    found = run(
        m.file(NTFS, "Users/a/Documents/invoice.pdf.exe", magic="pe", mtime=WHEN),
        m.file(NTFS, "Users/a/Documents/photo.jpg      .scr", magic="pe", mtime=WHEN),
        m.file(NTFS, "Users/a/Documents/gone.docx.js", deleted=True, mtime=WHEN),
        # near misses
        m.file(
            NTFS, "Users/a/AppData/Roaming/Microsoft/Windows/Recent/invoice.pdf.lnk", mtime=WHEN
        ),
        m.file(NTFS, "Program Files/App/setup.x64.exe", magic="pe", mtime=WHEN),
        m.file(NTFS, "Users/a/Documents/report.final.pdf", magic="document", mtime=WHEN),
        m.file(NTFS, "Users/a/Documents/archive.tar.gz", magic="archive", mtime=WHEN),
        m.file(NTFS, "Program Files/App/jquery.min.js", magic="script", mtime=WHEN),
        m.file(NTFS, "Users/a/Documents/.pdf.exe", magic="pe", mtime=WHEN),
    )
    assert kinds(found) == [("disk_double_extension", "medium")] * 3


def test_rtlo_name_is_shown_escaped() -> None:
    m = r.FileMaker()
    (finding,) = run(m.file(NTFS, "Users/a/Desktop/report‮fdp.exe", magic="pe", mtime=WHEN))
    assert finding.type == "disk_rtlo_name"
    assert "‮" not in finding.description and "<U+202E>" in finding.description
    assert "‮" not in str(finding.attributes)


def test_extension_mismatch() -> None:
    m = r.FileMaker()
    found = run(
        m.file(NTFS, "Users/a/Documents/holiday.JPG", magic="pe", mtime=WHEN),
        m.file(EXT, "srv/www/index.html", magic="elf", mtime=WHEN),
        # near misses: executable-ish or no extension, data content
        m.file(NTFS, "Windows/System32/en-US/kernel32.dll.mui", magic="pe", mtime=WHEN),
        m.file(NTFS, "Program Files/App/update.tmp", magic="pe", mtime=WHEN),
        m.file(EXT, "usr/bin/tool", magic="elf", mtime=WHEN),
        m.file(NTFS, "Users/a/Documents/photo.jpg", magic="other", mtime=WHEN),
    )
    assert kinds(found) == [("disk_extension_mismatch", "medium")] * 2


def test_ads_executable_but_never_zone_identifier() -> None:
    m = r.FileMaker()
    host = m.file(NTFS, "Users/a/Documents/notes.txt", mtime=WHEN)
    stream = m.file(NTFS, host.path, magic="pe", stream="payload", mtime=WHEN, addr=host.meta_addr)
    zone_host = m.file(NTFS, "Users/a/Downloads/x.pdf", magic="document", mtime=WHEN)
    zone = m.file(
        NTFS,
        zone_host.path,
        magic="pe",
        stream="Zone.Identifier",
        mtime=WHEN,
        addr=zone_host.meta_addr,
    )
    other = m.file(
        NTFS,
        zone_host.path,
        magic="other",
        stream="SmartScreen",
        mtime=WHEN,
        addr=zone_host.meta_addr,
    )
    (finding,) = run(host, stream, zone_host, zone, other)
    assert (
        finding.type == "disk_ads_executable"
        and finding.attributes["subject"] == "Users/a/Documents/notes.txt:payload"
    )
    assert finding.evidence_refs == [f"file:{NTFS}:{host.meta_addr}:1:payload"]


def test_long_stream_names_get_a_hashed_ref() -> None:
    m = r.FileMaker()
    host = m.file(NTFS, "Users/a/x.txt", mtime=WHEN)
    stream = m.file(NTFS, host.path, magic="pe", stream="s" * 200, mtime=WHEN, addr=host.meta_addr)
    (finding,) = run(host, stream)
    (ref,) = finding.evidence_refs
    assert len(ref) <= 64 and ref.startswith(f"file:{NTFS}:{host.meta_addr}:1:#")


def test_yara_severity_from_the_allow_list_map_only() -> None:
    m = r.FileMaker()
    f = m.file(
        NTFS,
        "Program Files/App/a.dll",
        magic="pe",
        mtime=WHEN,
        yara=["image.cyberlab_baseline.Allowed", "image.x.Unlisted"],
    )
    found = run(f, yara={"image.cyberlab_baseline.Allowed": "high"})
    assert sorted((x.attributes["rule"], x.severity) for x in found) == [
        ("image.cyberlab_baseline.Allowed", "high"),  # signatures may reach high
        ("image.x.Unlisted", "low"),  # unknown: the M3 default
    ]
    assert all(x.detection_method == "signature:yara@1" for x in found)


def test_hashset_bad_and_notable_but_never_good() -> None:
    m = r.FileMaker()
    found = run(
        m.file(
            NTFS,
            "Users/a/Documents/x.exe",
            magic="pe",
            mtime=WHEN,
            known="bad",
            known_set="ops-bad",
        ),
        m.file(
            NTFS,
            "Users/a/Documents/y.exe",
            magic="pe",
            mtime=WHEN,
            known="notable",
            known_set="dfir",
        ),
        m.file(
            NTFS, "Users/a/Documents/z.exe", magic="pe", mtime=WHEN, known="good", known_set="nsrl"
        ),
    )
    assert kinds(found) == [("disk_hashset_match", "medium")] * 2
    assert {f.attributes["hashset"] for f in found} == {"ops-bad", "dfir"}
    assert all(f.detection_method == "known_file:hashset@1" for f in found)


def test_listing_paths_are_not_mangled_by_the_secret_masker() -> None:
    """A `/`-separated path of 40 mixed-case characters looks like an AWS secret to the
    masker; listing paths are shown, not masked."""
    m = r.FileMaker()
    f = m.file(NTFS, "Users/alice/AppData/Local/Temp/svchost32.exe", magic="pe", mtime=WHEN)
    (finding,) = run(f)
    assert finding.attributes["subject"] == f.path and f.path in finding.description
