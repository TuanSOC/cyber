"""Real engines (probes, ClamAV, YARA, capa, FLOSS) over the synthetic samples, in-container."""

import hashlib
import io
import os
import stat
import uuid
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.static import Profile, StringRecord
from cyberlab_worker import sandbox

from samples import pe
from samples.generate import STACK_STRING, eicar
from static_worker import analyzer
from static_worker.config import Engines
from static_worker.engines import probes
from static_worker.engines.probes import Archive, archive_result, run_probe
from static_worker.engines.workspace import Budget, Workspace
from tests.conftest import CLAMAV_TEST_DB, SampleSet, in_container
from tests.helpers import FAST, LIMITS, WITH_CAPA_FIXTURE, analyze, findings, names, place

pytestmark = in_container


def test_benign_pe32_is_parsed_completely(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["benign_pe32"])
    header = out["header"]
    assert header.file_format == "pe" and header.profile == "full"
    assert header.engine_errors == [] and header.truncated == {}
    assert header.tool_versions["clamav_db"] == "custom:clamav"
    [info] = out["pe"]
    assert (info.machine, info.bits, info.is_dll, info.subsystem) == (
        "i386",
        32,
        False,
        "WINDOWS_CUI",
    )
    assert info.entry_section == ".text" and info.imphash and info.rich_header_hash
    assert info.overlay_size == 0 and info.tls_callbacks == 0 and not info.has_authenticode
    assert [s.name for s in out["section"]] == [".text", ".rdata", ".data", ".idata", ".rsrc"]
    assert {(i.library, i.function) for i in out["import"]} >= {("USER32.dll", "MessageBoxA")}
    assert {r.type for r in out["resource"]} == {"RT_MANIFEST", "RT_RCDATA"}
    assert all(r.sha256 and 0 <= r.entropy <= 8 for r in out["resource"])
    values = {s.value for s in out["string"]}
    assert "Hello from the CyberLab benign sample" in values
    assert "CyberLab Benign Sample" in {s.value for s in out["string"] if s.encoding == "utf16le"}
    assert "finding" not in out and "signature_match" not in out


def test_sample_facts_are_trusted_hashes(sample_set: SampleSet) -> None:
    path = sample_set.paths["benign_pe64"]
    data = path.read_bytes()
    [sample] = analyze(path)["sample"]
    assert sample.size == len(data)
    assert sample.sha256 == hashlib.sha256(data).hexdigest()
    assert sample.md5 == hashlib.md5(data).hexdigest()  # noqa: S324
    assert sample.sha1 == hashlib.sha1(data).hexdigest()  # noqa: S324
    assert sample.ssdeep and sample.ssdeep.count(":") == 2
    assert sample.file_type and "PE32+" in sample.file_type and "DLL" in sample.file_type
    assert sample.mime == "application/vnd.microsoft.portable-executable"


def test_pe64_dll_exports_and_authenticode(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["benign_pe64"])
    [info] = out["pe"]
    assert info.bits == 64 and info.is_dll and info.machine == "amd64"
    assert info.has_authenticode and info.overlay_size == 0  # the certificate is not overlay
    assert sorted(e.name for e in out["export"]) == [
        "CyberLabInit", "CyberLabProcess", "CyberLabShutdown",
    ]  # fmt: skip
    assert "finding" not in out


def test_elf_facts(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["benign_elf"])
    assert out["header"].file_format == "elf" and out["header"].engine_errors == []
    [info] = out["elf"]
    assert (info.elf_class, info.machine, info.elf_type) == (64, "EM_X86_64", "ET_EXEC")
    assert info.interpreter == "/lib64/ld-linux-x86-64.so.2" and info.needed == ["libc.so.6"]
    assert not info.stripped
    assert {i.function for i in out["import"]} == {
        "puts", "printf", "malloc", "free", "__libc_start_main",
    }  # fmt: skip
    assert {i.library for i in out["import"]} == {"libc.so.6"}
    text = next(s for s in out["section"] if s.name == ".text")
    assert "execute" in text.flags and text.raw_size > 0
    assert "finding" not in out


def test_eicar_is_a_clamav_match(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["eicar"], profile=Profile.AV)
    assert out["header"].file_format == "other" and out["header"].engine_errors == []
    assert names(out, "clamav") == ["CyberLab.Test.EICAR.UNOFFICIAL"]
    [finding] = findings(out)
    assert finding.severity == "high" and finding.detection_method == "signature:clamav@1"


def test_eicar_with_the_full_clamav_database() -> None:
    """The image's freshclam DB (~15 s to load): EICAR is recognised by the real signatures."""
    out = analyze(eicar(), profile=Profile.AV, engines=replace(FAST, clamav_db=None))
    assert out["header"].engine_errors == []
    assert any("eicar" in name.lower() for name in names(out, "clamav")), names(out, "clamav")
    assert out["header"].tool_versions["clamav_db"] not in {"", "unavailable"}


def test_test_marker_hits_yara_and_clamav(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["test_marker"])
    assert names(out, "yara") == ["CyberLab_Test_Marker"]
    [match] = [m for m in out["signature_match"] if m.engine == "yara"]
    assert match.namespace == "test.cyberlab_test" and match.tags == ["test"]
    assert match.meta["severity"] == "medium"
    assert names(out, "clamav") == ["PUA.CyberLab.TestMarker.UNOFFICIAL"]
    severities = {f.attributes["engine"]: f.severity for f in findings(out)}
    assert severities == {"yara": "medium", "clamav": "medium"}  # allowlisted / PUA


def test_unlisted_yara_rule_is_capped_at_low() -> None:
    data = pe.build(
        pe.PeSpec(
            sections=[
                pe.Section(".text", b"\x90" * 64 + b"\xc3", pe.TEXT),
                pe.Section(".rdata", b"CYBERLAB-SEVERITY-CLAMP-TEST\0", pe.RDATA),
            ],
            imports={"KERNEL32.dll": ["ExitProcess"]},
        )
    )
    out = analyze(data)
    [finding] = findings(out, "yara_match")
    assert finding.attributes["name"] == "CyberLab_Test_Unlisted_High"
    assert finding.severity == "low"


RT2_SAMPLES = [
    "nested_zip_bomb",
    "zip_large_member",
    "zip_prefixed_large_member",  # zip after leading data
    "sfx_pe_zip_large_member",  # PE + appended zip
    "zip_nested_prefixed",  # a prefixed zip inside a zip
    "zip64_data_descriptor",  # ClamAV does not scan zip64 members
    "tar_gz_large_member",  # ClamAV's own limit alert (tar / gzip / bzip2 / xz)
    "zip_prefixed_lying_size",  # headers claim 1 KiB, the stream inflates to 70 MiB
    "zip_local_header_nameless",  # no central directory, name length 0
    "zip_hidden_in_extra_field",  # a zip entry inside a member's local extra field
]


@pytest.mark.parametrize("scenario", RT2_SAMPLES)
def test_archives_are_never_silently_clean(sample_set: SampleSet, scenario: str) -> None:
    out = analyze(sample_set.paths[scenario], profile=Profile.AV)
    assert "av_not_fully_scanned" in out["header"].engine_errors
    assert out["header"].truncated.get("clamav_limits")


def _small_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "a small, complete zip.\n" * 20)
    return buffer.getvalue()


def test_small_zip_is_fully_scanned() -> None:
    out = analyze(_small_zip(), profile=Profile.AV)
    assert out["header"].engine_errors == [] and out["header"].truncated == {}


@pytest.mark.parametrize("failure", ["timeout", "skipped", "inconsistent"])
def test_missing_archive_precheck_fails_closed(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """Without a usable archive pre-check, ClamAV's result is never complete."""
    real = run_probe

    def probe(ws: Workspace, engines: Engines, mode: str, options: list[str], **kw: Any) -> Any:
        if mode == "archive" and failure == "timeout":
            kw["seconds"] = 0.01  # killed before it printed anything
        return real(ws, engines, mode, options, **kw)

    monkeypatch.setattr(analyzer, "run_probe", probe)
    if failure == "skipped":
        tool = Budget.tool
        calls = iter(range(100))

        def budget(self: Budget, cap: float | None = None) -> float | None:
            return None if next(calls) == 2 else tool(self, cap)  # 3rd engine: archive

        monkeypatch.setattr(Budget, "tool", budget)
    if failure == "inconsistent":
        # A clean-looking record for other bytes than root hashed: must be discarded.
        clean: dict[str, int | bool | str] = {
            "format": "zip", "members": 1, "declared_bytes": 9, "largest_member": 9,
            "depth": 1, "encrypted": False, "unchecked": False,
        }  # fmt: skip
        monkeypatch.setattr(
            analyzer, "archive_result", lambda run: Archive(record=clean, sha256="0" * 64)
        )
    out = analyze(_small_zip(), profile=Profile.AV)
    header = out["header"]
    assert "av_not_fully_scanned" in header.engine_errors, header.engine_errors
    assert header.truncated.get("archive_precheck_missing")
    expected = {"timeout": "archive_timeout", "skipped": "archive_skipped",
                "inconsistent": "probe_inconsistent"}[failure]  # fmt: skip
    assert expected in header.engine_errors


def test_missing_av_database_is_reported(tmp_path: Path, sample_set: SampleSet) -> None:
    empty = tmp_path / "no-db"
    empty.mkdir()
    out = analyze(sample_set.paths["eicar"], profile=Profile.AV,
                  engines=replace(FAST, clamav_db=empty))  # fmt: skip
    assert "av_unavailable" in out["header"].engine_errors
    assert "signature_match" not in out


def test_av_profile_skips_structure_engines(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["injection_imports"], profile=Profile.AV)
    assert out["header"].profile == "av" and out["header"].file_format == "pe"
    assert not {"pe", "section", "import", "string", "capability"} & set(out)
    assert names(out, "yara") == ["CyberLab_Process_Injection_API_Names"]
    assert {f.type for f in findings(out)} == {"yara_match"}  # no import-based finding


def test_size_caps_skip_capa_and_floss(
    sample_set: SampleSet, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(analyzer, "CAPA_MAX_BYTES", 1024)
    monkeypatch.setattr(analyzer, "FLOSS_MAX_BYTES", 1024)
    engines = replace(FAST, capa_enabled=True, floss_enabled=True)
    out = analyze(sample_set.paths["benign_pe32"], engines=engines)
    assert {"capa_skipped", "floss_skipped"} <= set(out["header"].engine_errors)
    assert out["header"].truncated["capa_skipped_size_cap"]
    assert out["header"].truncated["floss_skipped_size_cap"]
    elf = analyze(sample_set.paths["benign_elf"], engines=engines)
    assert elf["header"].truncated["floss_skipped_not_pe"]


def test_capa_fixture_rule(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["test_marker"], engines=WITH_CAPA_FIXTURE)
    assert "capa_failed" not in out["header"].engine_errors
    [cap] = out["capability"]
    assert cap.name == "contain CyberLab test marker"
    assert cap.namespace == "anti-analysis/cyberlab-test"
    assert cap.attack == ["T1027"] and cap.mbc == ["B0032"]
    [finding] = findings(out, "capability_anti_analysis")
    assert finding.severity == "low" and finding.detection_method == "capability:capa@1"
    assert "T1027" in str(finding.attributes["attack"])


def test_floss_recovers_a_stack_string(sample_set: SampleSet) -> None:
    out = analyze(sample_set.paths["stack_string"], engines=replace(FAST, floss_enabled=True))
    assert not {"floss_failed", "floss_timeout"} & set(out["header"].engine_errors)
    stack = [s for s in out["string"] if s.encoding == "floss_stack"]
    assert [s.value for s in stack] == [STACK_STRING]
    assert any(i.value == STACK_STRING and i.source == "floss" for i in out["ioc"])


def test_caps_truncate_and_flag(sample_set: SampleSet) -> None:
    limits = LIMITS.model_copy(
        update={"max_sections": 2, "max_imports": 3, "max_strings": 4, "max_findings": 1,
                "max_iocs": 1}
    )  # fmt: skip
    out = analyze(sample_set.paths["downloader_imports"], limits=limits)
    assert len(out["section"]) == 2 and len(out["import"]) == 3 and len(out["string"]) == 4
    flags = out["header"].truncated
    assert flags["sections"] and flags["imports"] and flags["strings"]
    # IOCs come from the strings: cap them separately (7 labelled IOCs in this sample).
    iocs = analyze(sample_set.paths["downloader_imports"], limits=LIMITS.model_copy(
        update={"max_iocs": 1}))  # fmt: skip
    assert len(iocs["ioc"]) == 1 and iocs["header"].truncated["iocs"]
    anomalies = analyze(sample_set.paths["pe_anomalies"], limits=limits)  # 5 findings
    assert len(anomalies["finding"]) == 1 and anomalies["header"].truncated["findings"]


def test_truncated_pe_yields_partial_results(sample_set: SampleSet) -> None:
    data = sample_set.paths["benign_pe32"].read_bytes()
    out = analyze(data[:1500])  # headers + part of the section table
    assert out["header"].file_format == "pe"
    assert "pe" in out and "sample" in out


def test_large_sample_skips_the_fuzzy_hash_only() -> None:
    data = pe.build(
        pe.PeSpec(
            sections=[
                pe.Section(".text", b"\xc3" * 512, pe.TEXT),
                pe.Section(".data", bytes(analyzer.SSDEEP_MAX_BYTES), pe.DATA),
            ],
            imports={"KERNEL32.dll": ["ExitProcess"]},
        )
    )
    out = analyze(data)
    [sample] = out["sample"]
    assert sample.ssdeep is None and sample.file_type and "PE32" in sample.file_type
    assert out["header"].truncated["ssdeep_size_cap"] and out["header"].engine_errors == []


def test_garbage_after_mz_is_other_format() -> None:
    out = analyze(b"MZ" + os.urandom(3000))
    assert out["header"].file_format == "other" and out["header"].engine_errors == []
    assert "pe" not in out and "section" not in out
    engines = replace(FAST, capa_enabled=True, floss_enabled=True)
    skipped = analyze(b"MZ" + os.urandom(3000), engines=engines)["header"]
    assert {"capa_skipped", "floss_skipped"} <= set(skipped.engine_errors)
    assert skipped.truncated["capa_skipped_not_pe_or_elf"]


def test_each_engine_gets_a_fresh_tool_owned_dir(dirs: sandbox.JobDirs) -> None:
    place(dirs, b"MZ" + bytes(100))
    ws = Workspace(dirs)
    errors: list[str] = []
    run = run_probe(ws, FAST, "strings", ["--max-strings", "5"], seconds=30, max_lines=10,
                    errors=errors, truncated={})  # fmt: skip
    out = run.dirs.out
    assert out.parent == dirs.root and out.name == "probe-strings-out"
    assert out.stat().st_uid == sandbox.TOOL_UID and stat.S_IMODE(out.stat().st_mode) == 0o700
    assert errors == []
    with pytest.raises(FileExistsError):
        ws.engine("probe-strings")  # never reused within a job
    assert sandbox.tool_pids() == []


def test_probe_runs_as_tool_uid_in_isolated_mode(dirs: sandbox.JobDirs) -> None:
    """The probe interpreter runs as the tool uid in isolated mode (no cwd / user site)."""
    place(dirs, b"x")
    view = Workspace(dirs).engine("whoami")
    code = "import os, sys; print(os.getuid(), sys.flags.isolated, sys.flags.no_user_site)"
    argv = [FAST.python, "-I", "-s", "-B", "-c", code]
    sandbox.run_tool(argv, view, timeout_s=30, stdout_name="who.txt")
    with sandbox.open_output(view, "who.txt") as f:
        assert f.read().split() == [str(sandbox.TOOL_UID).encode(), b"1", b"1"]


def test_probes_run_in_the_root_owned_input_dir(
    dirs: sandbox.JobDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_probe starts the probe with cwd = the input dir (root-owned, no tool can write)."""
    place(dirs, b"x")
    ws = Workspace(dirs)
    monkeypatch.setattr(probes, "MODULE", "tests.cwd_probe")  # reports its cwd
    run = run_probe(ws, FAST, "strings", [], seconds=30, max_lines=10, errors=[], truncated={})
    assert [r.value for r in run.records() if isinstance(r, StringRecord)] == [str(dirs.input)]
    assert dirs.input.stat().st_uid == 0 and stat.S_IMODE(dirs.input.stat().st_mode) == 0o755
    monkeypatch.undo()
    real = run_probe(ws, FAST, "archive", [], seconds=30, max_lines=10, errors=[], truncated={})
    assert archive_result(real).record == {
        "format": "none", "members": 0, "declared_bytes": 0, "largest_member": 0, "depth": 0,
        "encrypted": False, "unchecked": False,
    }  # fmt: skip


def test_no_tool_process_survives_an_analysis(sample_set: SampleSet) -> None:
    analyze(sample_set.paths["mingw_hello"] if "mingw_hello" in sample_set.paths
            else sample_set.paths["benign_pe64"])  # fmt: skip
    assert sandbox.tool_pids() == []


def test_result_is_deterministic_apart_from_ids(sample_set: SampleSet) -> None:
    first = analyze(sample_set.paths["pe_anomalies"])
    second = analyze(sample_set.paths["pe_anomalies"])

    def comparable(out: dict[str, Any]) -> list[Any]:
        return [(f.type, f.severity, f.title) for f in out["finding"]] + [
            r.model_dump() for k in ("section", "import", "resource", "string") for r in out[k]
        ]

    assert comparable(first) == comparable(second)


def test_job_ids_change_finding_ids_but_not_within_a_job(sample_set: SampleSet) -> None:
    a = analyze(sample_set.paths["test_marker"])
    b = analyze(sample_set.paths["test_marker"])
    ids_a = {f.finding_id for f in a["finding"]}
    assert len(ids_a) == len(a["finding"])  # unique per finding
    assert ids_a.isdisjoint({f.finding_id for f in b["finding"]})  # job id is part of the key
    assert isinstance(next(iter(ids_a)), uuid.UUID)


def test_clamav_test_db_is_small() -> None:
    assert sum(p.stat().st_size for p in CLAMAV_TEST_DB.iterdir()) < 4096
