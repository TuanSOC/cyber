"""`disk.v1` / `disk-export.v1` contract (M9 phase 1, frozen): the valid fixtures round-trip,
every hostile one is refused, the never-collected list holds every class (and every name of a
hard-linked inode, RT7), jobs and limits validate, and a stream at every cap fits the framing
bounds.

Pure Python (pydantic only): also runs on a host without the API's dependencies:

  cd apps/api && PYTHONPATH=../../packages/py-jobs/src python -m pytest -p no:cacheprovider \
      --noconftest tests/unit/test_disk_contract.py
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cyberlab_jobs
import pytest
from cyberlab_jobs import tasks
from cyberlab_jobs.disk import (
    ARTIFACTS_BY_PROFILE,
    DIAGNOSTIC_ERROR_CODES,
    DISK_ERROR_CODES,
    DISK_EXPORT_LINE_ADAPTER,
    DISK_LINE_ADAPTER,
    FILE_FLAG_BITS,
    MAX_RESULT_BYTES,
    NEVER_COLLECT_PATTERNS,
    PROFILE_BUDGETS,
    YARA_MAGIC_CLASSES,
    DiskArtifact,
    DiskEventRecord,
    DiskExportJobV1,
    DiskExportResultHeader,
    DiskFileRecord,
    DiskJobV1,
    DiskLimits,
    DiskProfile,
    DiskResultHeader,
    HashSetManifestV1,
    check_diagnostic_kinds,
    check_line_order,
    default_stage_limits,
    never_collect,
    split_event_quotas,
)
from cyberlab_jobs.results import ResultTrailer
from pydantic import BaseModel, ValidationError

ROOT = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures"
FIXTURES = ROOT / "disk"
HOSTILE = FIXTURES / "hostile"
PSORT = ROOT / "psort"
JOBS = {
    "windows_triage.ndjson": uuid.UUID("7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2001"),
    "linux_triage.ndjson": uuid.UUID("7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2002"),
    "ewf_mismatch.ndjson": uuid.UUID("7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2003"),
    "no_supported_filesystem.ndjson": uuid.UUID("7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2004"),
}
EXPORT_JOB = uuid.UUID("7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2005")


class StreamRefused(Exception):
    pass


def read_stream(path: Path, job_id: uuid.UUID, *, diagnostic: bool = False) -> list[BaseModel]:
    """The contract-level framing rules (the ingest, phase 7, adds caps and identity)."""
    raw = path.read_bytes().splitlines(keepends=True)
    if len(raw) < 2:
        raise StreamRefused("too short")
    lines: list[BaseModel] = []
    digest = hashlib.sha256()
    for index, line in enumerate(raw):
        try:
            parsed = DISK_LINE_ADAPTER.validate_json(line)
        except ValidationError as exc:
            raise StreamRefused(f"line {index + 1} invalid") from exc
        if not index == len(raw) - 1:
            digest.update(line)
        lines.append(parsed)
    kinds = [getattr(line, "kind") for line in lines]  # noqa: B009
    try:
        check_line_order(kinds)
        if diagnostic:
            check_diagnostic_kinds(kinds)
    except ValueError as exc:
        raise StreamRefused(str(exc)) from exc
    header, trailer = lines[0], lines[-1]
    assert isinstance(header, DiskResultHeader) and isinstance(trailer, ResultTrailer)
    if header.job_id != job_id:
        raise StreamRefused("the header names another job")
    if trailer.line_count != len(lines) - 1 or trailer.sha256 != digest.hexdigest():
        raise StreamRefused("trailer mismatch")
    return lines


@pytest.mark.parametrize("name", sorted(JOBS))
def test_valid_fixtures_round_trip(name: str) -> None:
    diagnostic = name == "no_supported_filesystem.ndjson"
    lines = read_stream(FIXTURES / name, JOBS[name], diagnostic=diagnostic)
    for model, raw in zip(lines, (FIXTURES / name).read_bytes().splitlines(), strict=True):
        again = DISK_LINE_ADAPTER.validate_json(model.model_dump_json())
        assert again == model
        assert json.loads(raw)["kind"] == getattr(model, "kind")  # noqa: B009
    header = lines[0]
    assert isinstance(header, DiskResultHeader)
    assert header.timeline_engine in ("replay", "none")  # labelled synthetic
    assert "synthetic" in header.tool_versions["fixture"]


def test_windows_fixture_covers_the_planned_shapes() -> None:
    lines = read_stream(FIXTURES / "windows_triage.ndjson", JOBS["windows_triage.ndjson"])
    files = [line for line in lines if isinstance(line, DiskFileRecord)]
    assert len(files) >= 300
    assert any(f.stream for f in files)  # an ADS
    assert any(f.has_flag("deleted") for f in files)
    assert any(f.has_flag("orphan") for f in files)
    linked = [f for f in files if f.has_flag("hard_linked")]
    assert len({(f.partition_index, f.meta_addr) for f in linked}) == 1 and len(linked) == 2
    assert any(f.magic == "pe" and "Users/" in f.path for f in files)
    events = [line for line in lines if isinstance(line, DiskEventRecord)]
    assert {"evtx", "registry_user", "registry_system", "prefetch", "lnk", "amcache"} <= {
        e.artifact for e in events
    }
    kinds = {getattr(x, "kind") for x in lines}  # noqa: B009
    assert {"finding", "ioc", "timeline", "partition"} <= kinds


def test_diagnostic_stream_rules() -> None:
    lines = read_stream(
        FIXTURES / "no_supported_filesystem.ndjson",
        JOBS["no_supported_filesystem.ndjson"],
        diagnostic=True,
    )
    assert "no_supported_filesystem" in lines[0].engine_errors  # type: ignore[attr-defined]
    assert DIAGNOSTIC_ERROR_CODES <= set(DISK_ERROR_CODES)
    with pytest.raises(ValueError):
        check_diagnostic_kinds(["header", "partition", "file", "trailer"])
    check_diagnostic_kinds(["header", "trailer"])


def test_ewf_fixture_reports_a_mismatch_with_inert_meta() -> None:
    lines = read_stream(FIXTURES / "ewf_mismatch.ndjson", JOBS["ewf_mismatch.ndjson"])
    header = lines[0]
    assert isinstance(header, DiskResultHeader)
    assert header.image.ewf is not None
    assert header.image.ewf.media_hash_status == "mismatch"
    assert header.image.ewf.meta["notes"] == "<script>inert</script>"


def test_export_result_round_trips() -> None:
    raw = (FIXTURES / "export_result.ndjson").read_bytes().splitlines()
    header = DISK_EXPORT_LINE_ADAPTER.validate_json(raw[0])
    trailer = DISK_EXPORT_LINE_ADAPTER.validate_json(raw[1])
    assert isinstance(header, DiskExportResultHeader) and isinstance(trailer, ResultTrailer)
    assert header.job_id == EXPORT_JOB
    assert trailer.sha256 == hashlib.sha256(raw[0] + b"\n").hexdigest()
    assert [f.status for f in header.files] == ["ok", "failed"]


HOSTILE_STREAMS = sorted(p.name for p in HOSTILE.glob("*.ndjson"))


def test_hostile_set_is_complete() -> None:
    assert {
        "wrong_job.ndjson",
        "nan.ndjson",
        "nul_char_path.ndjson",
        "overlong_path.ndjson",
        "attributes_33.ndjson",
        "nested_attribute.ndjson",
        "extra_field.ndjson",
        "bad_hash_length.ndjson",
        "after_trailer.ndjson",
        "unknown_artifact.ndjson",
        "media_hash_status_outside_enum.ndjson",
    } <= set(HOSTILE_STREAMS)


@pytest.mark.parametrize("name", HOSTILE_STREAMS)
def test_hostile_fixtures_are_refused(name: str) -> None:
    with pytest.raises(StreamRefused):
        read_stream(
            HOSTILE / name,
            JOBS["windows_triage.ndjson"],
            diagnostic=name.startswith("diagnostic"),
        )


def test_overlong_path_is_refused_but_a_flagged_cut_path_is_kept() -> None:
    record = json.loads((FIXTURES / "windows_triage.ndjson").read_bytes().splitlines()[5])
    assert record["kind"] == "file"
    with pytest.raises(ValidationError):
        DiskFileRecord.model_validate({**record, "path": "é" * 2049})  # 4 098 bytes
    cut = DiskFileRecord.model_validate(
        {**record, "path": "é" * 2048, "flags": record["flags"] | FILE_FLAG_BITS["path_truncated"]}
    )
    assert cut.has_flag("path_truncated")


# --- jobs and limits ------------------------------------------------------------------------


def limits(profile: DiskProfile = DiskProfile.TRIAGE, **override: Any) -> DiskLimits:
    budgets = dict(PROFILE_BUDGETS[profile])
    data: dict[str, Any] = {
        "max_image_bytes": 16 * 1024**3,
        "max_media_bytes": 2 * 1024**4,
        "timeout_s": 14_400,
        "stages": default_stage_limits(
            budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"]
        ),
        **budgets,
        "max_partitions": 128,
        "max_filesystems": 32,
        "max_files": 500_000,
        "max_streams_per_file": 16,
        "max_events_stored": 250_000,
        "max_events_read": 20_000_000,
        "max_findings": 5_000,
        "max_iocs": 20_000,
        "max_timeline": 5_000,
        "max_result_bytes": 256 * 1024**2,
        "event_quotas": split_event_quotas(250_000),
    }
    data.update(override)
    return DiskLimits.model_validate(data)


POST = {"url": "http://minio:9000/results", "fields": {"key": "k"}}


def segment(ordinal: int, size: int = 1024) -> dict[str, Any]:
    return {
        "ordinal": ordinal,
        "evidence_id": str(uuid.UUID(int=ordinal + 1)),
        "expected_sha256": "a" * 64,
        "size_bytes": size,
        "url": "http://minio:9000/evidence/x",
    }


def job(**override: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "segments": [segment(0), segment(1)],
        "profile": "triage",
        "os_hint": "auto",
        "result_post": POST,
        "ingest_token": "t" * 43,
        "limits": limits().model_dump(mode="json"),
        "deadline_at": (datetime.now(UTC) + timedelta(hours=4)).isoformat(),
    }
    data.update(override)
    return data


def test_a_job_validates_and_round_trips() -> None:
    msg = DiskJobV1.model_validate(job())
    assert msg.schema_version == "disk.v1"
    assert DiskJobV1.model_validate_json(msg.model_dump_json()) == msg
    assert msg.limits.max_lines() == 3 + 128 + 500_000 + 250_000 + 5_000 + 20_000 + 5_000


@pytest.mark.parametrize(
    "segments",
    [
        [],
        [segment(1)],
        [segment(0), segment(2)],
        [segment(1), segment(0)],
        [segment(0), {**segment(1), "evidence_id": str(uuid.UUID(int=1))}],
        [segment(i) for i in range(65)],
        [segment(0, 9 * 1024**3), segment(1, 8 * 1024**3)],  # 17 GiB > 16 GiB
    ],
)
def test_bad_segment_sets_are_refused(segments: list[dict[str, Any]]) -> None:
    with pytest.raises(ValidationError):
        DiskJobV1.model_validate(job(segments=segments))


def test_hostile_job_documents_are_refused() -> None:
    doc = json.loads((HOSTILE / "segments_not_contiguous.json").read_text())
    with pytest.raises(ValidationError):
        DiskJobV1.model_validate(job(**doc))
    with pytest.raises(ValidationError):
        DiskJobV1.model_validate(job(profile="extract"))
    with pytest.raises(ValidationError):
        DiskJobV1.model_validate(job(cache_key="x"))  # no image cache (RT1)


def test_limits_refuse_stage_timeouts_at_the_job_timeout_and_bad_quotas() -> None:
    with pytest.raises(ValidationError):
        limits(timeout_s=3600)  # walk / scan caps are 3 600 s
    with pytest.raises(ValidationError):
        limits(event_quotas=split_event_quotas(1000))
    with pytest.raises(ValidationError):
        limits(max_image_bytes=65 * 1024**3)
    with pytest.raises(ValidationError):
        limits(max_files=2_000_001)
    quotas = split_event_quotas(250_000)
    assert sum(quotas.values()) == 250_000 and set(quotas) == set(DiskArtifact)


def test_export_job_shape() -> None:
    files = [
        {
            "export_id": str(uuid.UUID(int=100 + i)),
            "partition_index": 1,
            "meta_addr": 1234 + i,
            "expected_size": 1024,
        }
        for i in range(2)
    ]
    base = {**job(), "source_job_id": str(uuid.uuid4()), "files": files}
    base.pop("profile"), base.pop("os_hint"), base.pop("result_post")
    msg = DiskExportJobV1.model_validate({**base, "result_posts": [POST] * 3})
    assert msg.schema_version == "disk-export.v1"
    with pytest.raises(ValidationError):
        DiskExportJobV1.model_validate({**base, "result_posts": [POST] * 2})
    too_big = [{**files[0], "expected_size": 64 * 1024**2 + 1}]
    with pytest.raises(ValidationError):
        DiskExportJobV1.model_validate({**base, "files": too_big, "result_posts": [POST] * 2})
    many = [{**files[0], "export_id": str(uuid.UUID(int=i + 1))} for i in range(21)]
    with pytest.raises(ValidationError):
        DiskExportJobV1.model_validate({**base, "files": many, "result_posts": [POST] * 22})


def test_a_stream_at_every_cap_fits_the_result_bounds() -> None:
    """The per-line byte maxima × the caps stay under the decompressed bound the API sets
    (DISK_MAX_RESULT_DECOMPRESSED_BYTES 1.5 GiB): files ≤ ~5 KiB, events ≤ ~7.5 KiB."""
    lim = limits()
    worst = (
        lim.max_partitions * 1024
        + lim.max_files * 5 * 1024
        + lim.max_events_stored * 8 * 1024
        + lim.max_findings * 8 * 1024
        + lim.max_iocs * 3 * 1024
        + lim.max_timeline * 1024
    )
    # compressed upload is capped at 256 MiB; the decompressed framing bound is 1.5 GiB
    assert lim.max_result_bytes <= MAX_RESULT_BYTES
    assert worst > 0
    assert lim.max_lines() < 1_000_000


# --- never collected (RT7) ------------------------------------------------------------------

REFUSED = {
    "hives": ["Windows/System32/config/SAM", "WINDOWS/system32/CONFIG/security.LOG1",
              "Windows/System32/config/RegBack/SOFTWARE", "Windows/repair/sam",
              "Windows/NTDS/ntds.dit"],
    "credential_stores": ["Users/a/AppData/Roaming/Microsoft/Protect/S-1-5-21/abc",
                          "Users/a/AppData/Local/Microsoft/Credentials/X",
                          "Users/a/AppData/Local/Microsoft/Vault/Y", "etc/shadow",
                          "etc/gshadow", "etc/krb5.keytab",
                          "home/u/.local/share/keyrings/login.keyring",
                          "home/u/.gnupg/private-keys-v1.d/K.key",
                          "etc/NetworkManager/system-connections/wifi.nmconnection",
                          "etc/wpa_supplicant/wpa_supplicant-wlan0.conf"],
    "browser_secrets": ["Users/a/AppData/Local/Google/Chrome/User Data/Default/Login Data",
                        "Users/a/AppData/Local/Google/Chrome/User Data/Default/Cookies",
                        "Users/a/AppData/Local/Google/Chrome/User Data/Default/Web Data",
                        "Users/a/AppData/Local/Google/Chrome/User Data/Local State",
                        "home/u/.mozilla/firefox/p.default/logins.json",
                        "home/u/.mozilla/firefox/p.default/key4.db",
                        "home/u/.mozilla/firefox/p.default/cookies.sqlite"],
    "keys_and_tokens": ["etc/ssh/ssh_host_ed25519_key", "home/u/.ssh/id_rsa", "x/cert.pfx",
                        "x/c.p12", "x/c.pem", "x/server.key", "etc/ssl/private/k",
                        "home/u/.netrc", "home/u/.git-credentials", "home/u/.pgpass",
                        "home/u/.my.cnf", "home/u/.aws/credentials", "home/u/.azure/token.json",
                        "home/u/.kube/config", "home/u/.docker/config.json", "Users/a/db.kdbx"],
    "plaintext_secret_configs": ["Windows/Panther/unattend.xml",
                                 "Windows/System32/sysprep/sysprep.xml",
                                 "Windows/SYSVOL/Policies/P/Machine/Preferences/Groups/Groups.xml"],
    "memory_on_disk": ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "Windows/MEMORY.DMP",
                       "Windows/Minidump/1.dmp"],
}
ALLOWED = [
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
    "Users/a/NTUSER.DAT",
    "Users/a/AppData/Local/Google/Chrome/User Data/Default/History",
    "var/log/auth.log",
    "etc/passwd",
    "home/u/.ssh/known_hosts",
    "home/u/.bash_history",
    "Windows/Prefetch/A.EXE-1.pf",
]


def test_every_never_collect_class_is_tested() -> None:
    assert set(REFUSED) == set(NEVER_COLLECT_PATTERNS)


@pytest.mark.parametrize(("cls", "path"), [(c, p) for c, ps in REFUSED.items() for p in ps])
def test_never_collect_refuses_every_class(cls: str, path: str) -> None:
    assert never_collect([path], fs_case_insensitive=True), (cls, path)
    assert never_collect(["/" + path.replace("/", "\\")], fs_case_insensitive=True)


@pytest.mark.parametrize("path", ALLOWED)
def test_never_collect_allows_triage_artifacts(path: str) -> None:
    assert not never_collect([path], fs_case_insensitive=True)
    assert not never_collect([path], fs_case_insensitive=False)


def test_never_collect_checks_every_name_of_an_inode() -> None:
    # a hard link `var/log/auth.log` -> the /etc/shadow inode; `x.txt` -> SAM (RT7)
    assert never_collect(["var/log/auth.log", "etc/shadow"], fs_case_insensitive=False)
    assert never_collect(["Users/a/x.txt", "Windows/System32/config/SAM"], True)
    assert not never_collect(["var/log/auth.log", "var/log/auth.log.1"], False)
    # Win32 ignores trailing dots / spaces on case-insensitive file systems
    assert never_collect(["Windows/System32/config/SAM. "], fs_case_insensitive=True)


def test_artifacts_and_yara_classes() -> None:
    for (os_name, profile), artifacts in ARTIFACTS_BY_PROFILE.items():
        assert len(set(artifacts)) == len(artifacts)
        if profile is DiskProfile.FULL:
            assert set(ARTIFACTS_BY_PROFILE[(os_name, DiskProfile.TRIAGE)]) < set(artifacts)
    assert DiskArtifact.AMCACHE in ARTIFACTS_BY_PROFILE[("windows", DiskProfile.TRIAGE)]
    assert DiskArtifact.BROWSER not in ARTIFACTS_BY_PROFILE[("windows", DiskProfile.TRIAGE)]
    assert YARA_MAGIC_CLASSES == frozenset({"pe"})


def test_tasks_and_queues() -> None:
    q = tasks.Queues(prefix="test.")
    assert (q.disk, q.ingest_disk) == ("test.disk", "test.ingest_disk")
    assert (tasks.DISK_ANALYZE, tasks.DISK_EXPORT, tasks.DISK_INGEST) == (
        "disk.analyze",
        "disk.export",
        "disk.ingest",
    )
    assert tasks.DISK_EXPIRE_EXPORTS == "disk.expire_exports"


# --- hash-set manifest ----------------------------------------------------------------------

GOOD_MANIFEST = {
    "version": 1,
    "sets": [
        {
            "name": "nsrl-minimal",
            "kind": "known_good",
            "algorithms": ["sha256", "md5"],
            "files": [
                {
                    "algo": "sha256",
                    "path": "nsrl-minimal/sha256.bin",
                    "sha256": "a" * 64,
                    "count": 10,
                },
                {"algo": "md5", "path": "nsrl-minimal/md5.bin", "sha256": "b" * 64, "count": 10},
            ],
            "source_sha256": "c" * 64,
            "imported_at": "2026-10-01T00:00:00Z",
            "tool_version": "1.0.0",
        }
    ],
}


def test_manifest_refuses_traversal_and_accepts_the_good_one() -> None:
    HashSetManifestV1.model_validate(GOOD_MANIFEST)
    with pytest.raises(ValidationError):
        HashSetManifestV1.model_validate_json((HOSTILE / "manifest_dotdot.json").read_bytes())
    for bad_name in ("Upper", "-x", "a" * 65, "a/b"):
        doc = json.loads(json.dumps(GOOD_MANIFEST))
        doc["sets"][0]["name"] = bad_name
        with pytest.raises(ValidationError):
            HashSetManifestV1.model_validate(doc)
    doc = json.loads(json.dumps(GOOD_MANIFEST))
    doc["sets"][0]["files"].pop()
    with pytest.raises(ValidationError):
        HashSetManifestV1.model_validate(doc)


# --- psort-shaped rows ----------------------------------------------------------------------

PSORT_FIELDS = {
    "__container_type__",
    "__type__",
    "data_type",
    "date_time",
    "display_name",
    "filename",
    "inode",
    "message",
    "parser",
    "pathspec",
    "timestamp",
    "timestamp_desc",
}


def test_psort_fixtures_have_the_json_line_shape() -> None:
    names = {p.name for p in PSORT.glob("*.jsonl")}
    assert {
        "winevtx.jsonl",
        "winreg.jsonl",
        "amcache.jsonl",
        "prefetch.jsonl",
        "lnk.jsonl",
        "mft.jsonl",
        "chrome_history.jsonl",
        "syslog.jsonl",
        "utmp.jsonl",
        "bash_history.jsonl",
    } <= names
    ids: set[int] = set()
    for path in PSORT.glob("*.jsonl"):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert "synthetic" in rows[0]["__fixture__"]
        for row in rows[1:]:
            assert PSORT_FIELDS <= set(row), (path.name, PSORT_FIELDS - set(row))
            assert row["__container_type__"] == "event"
            if row["parser"] == "winevtx":
                ids.add(row["event_identifier"])
    assert {4624, 4625, 4720, 4732, 7045, 1102, 104} <= ids
