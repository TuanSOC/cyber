"""`disk.v1` / `disk-export.v1`: disk forensics of an ordered segment set (M9).

Same framing as `memory.v1` (gzip NDJSON, header first, hashed trailer last) and the same value
bounds: every value is derived from an attacker-controlled disk image, read by an untrusted
analyzer (TSK through pytsk3, libewf, Plaso on extracted artifacts). The contract is
tool-agnostic: no pytsk3 / Plaso type appears here.

Stream order (one line each): `header`, `partition`*, `file`*, `event`*, `finding`*, `ioc`*,
`timeline`*, `trailer`. A **diagnostic stream** (`no_supported_filesystem`,
`unsupported_disk_format`) holds the header, at most the partitions, and the trailer
(`check_diagnostic_kinds`); it is uploaded with a `failed` ingest report.

`disk-export.v1` (profile `extract`): a header listing each exported file's status, then the
trailer; the file bytes themselves go to one presigned POST each.

Frozen at the end of M9 phase 1: change only together with the trusted ingest (parent).
"""

import enum
import json
import re
import string
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Annotated, Literal, Self, get_args

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BeforeValidator,
    Field,
    StrictBool,
    StrictInt,
    TypeAdapter,
    model_validator,
)

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict, Token
from cyberlab_jobs.memory import OsHint
from cyberlab_jobs.messages import PresignedPost, Url
from cyberlab_jobs.results import (
    NO_NUL,
    Count,
    FindingRecord,
    Ip,
    IocRecord,
    ResultTrailer,
    Text64,
    Text128,
    Text255,
    Timestamp,
    ToolVersions,
)

DISK_SCHEMA = "disk.v1"
DISK_EXPORT_SCHEMA = "disk-export.v1"

MIB = 1024**2
GIB = 1024**3
TIB = 1024**4
# Hard ceilings of the contract; the API's settings may only lower them (plan "Resources").
MAX_SEGMENTS = 64
MAX_IMAGE_BYTES = 64 * GIB  # the sum of a segment set (DISK_MAX_IMAGE_BYTES ≤ this, RT21)
MAX_MEDIA_BYTES = 16 * TIB  # the claimed EWF media size (DISK_MAX_MEDIA_BYTES ≤ this, RT6)
MAX_RESULT_BYTES = 256 * MIB
MAX_EXPORT_FILES = 20
MAX_EXPORT_FILE_BYTES = 64 * MIB
CAP_PARTITIONS = 128
CAP_FILESYSTEMS = 32
CAP_FILES = 2_000_000
CAP_STREAMS_PER_FILE = 16
CAP_EVENTS_STORED = 1_000_000
CAP_EVENTS_READ = 100_000_000
CAP_FINDINGS = 5_000
CAP_IOCS = 20_000
CAP_TIMELINE = 5_000
DEADLINE_RESERVE_S = 900  # kept back from every stage for assembly and upload (RT5)
STAGE_NPROC = 64  # RLIMIT_NPROC of every stage (threads count; RT3)

MAX_PATH_BYTES = 4096
MAX_NAME_BYTES = 1024


# --- enums ----------------------------------------------------------------------------------


class DiskProfile(enum.StrEnum):
    TRIAGE = "triage"
    FULL = "full"
    EXTRACT = "extract"  # a file export job (`disk-export.v1`), never an analysis


AnalysisProfile = Literal["triage", "full"]
DiskOs = Literal["windows", "linux"]
PartitionOs = Literal["windows", "linux", "none"]


class ImageFormat(enum.StrEnum):
    RAW = "raw"
    SPLIT_RAW = "split_raw"
    EWF = "ewf"


class DiskStage(enum.StrEnum):
    DOWNLOAD = "download"
    VERIFY = "verify"
    LAYOUT = "layout"
    WALK = "walk"
    COLLECT = "collect"
    SCAN = "scan"
    TIMELINE = "timeline"
    EXTRACT = "extract"


class StageStatus(enum.StrEnum):
    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"  # with a `reason`, e.g. `deadline` (RT5)
    TRUNCATED = "truncated"
    UNSUPPORTED = "unsupported"


class FsType(enum.StrEnum):
    """The allow-listed file systems (no autodetection; APFS / HFS+ / ISO / UFS never tried)."""

    NTFS = "ntfs"
    FAT12 = "fat12"
    FAT16 = "fat16"
    FAT32 = "fat32"
    EXFAT = "exfat"
    EXT2 = "ext2"
    EXT3 = "ext3"
    EXT4 = "ext4"


CASE_INSENSITIVE_FS: frozenset[FsType] = frozenset(
    {FsType.NTFS, FsType.FAT12, FsType.FAT16, FsType.FAT32, FsType.EXFAT}
)


class DiskArtifact(enum.StrEnum):
    """The artifact categories the collect stage may copy and Plaso may parse."""

    EVTX = "evtx"
    REGISTRY_SYSTEM = "registry_system"
    REGISTRY_USER = "registry_user"
    PREFETCH = "prefetch"
    LNK = "lnk"
    MFT = "mft"
    AMCACHE = "amcache"
    BROWSER = "browser"
    RECYCLE_BIN = "recycle_bin"
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    UTMP = "utmp"
    SHELL_HISTORY = "shell_history"
    CRON = "cron"
    SYSTEMD_JOURNAL = "systemd_journal"
    PACKAGES = "packages"
    PREPROCESS = "preprocess"


_A = DiskArtifact
_WINDOWS_TRIAGE = (
    _A.EVTX,
    _A.REGISTRY_SYSTEM,
    _A.REGISTRY_USER,
    _A.AMCACHE,  # triage, RT28
    _A.PREFETCH,
    _A.LNK,
)
_LINUX_TRIAGE = (
    _A.PREPROCESS,
    _A.SYSLOG,
    _A.AUTH_LOG,
    _A.UTMP,
    _A.SHELL_HISTORY,
    _A.CRON,
    _A.PACKAGES,
)
# The artifact categories per (OS, analysis profile) (plan "Scope"); `extract` collects none.
ARTIFACTS_BY_PROFILE: Mapping[tuple[DiskOs, DiskProfile], tuple[DiskArtifact, ...]] = (
    MappingProxyType(
        {
            ("windows", DiskProfile.TRIAGE): _WINDOWS_TRIAGE,
            ("windows", DiskProfile.FULL): (*_WINDOWS_TRIAGE, _A.MFT, _A.BROWSER, _A.RECYCLE_BIN),
            ("linux", DiskProfile.TRIAGE): _LINUX_TRIAGE,
            ("linux", DiskProfile.FULL): (*_LINUX_TRIAGE, _A.SYSTEMD_JOURNAL, _A.BROWSER),
            ("windows", DiskProfile.EXTRACT): (),
            ("linux", DiskProfile.EXTRACT): (),
        }
    )
)

# Share of the stored-event cap per category, in percent (sum 100; `preprocess` files feed
# Plaso's preprocessing only and keep no events). See `split_event_quotas`.
EVENT_QUOTA_PERCENT: Mapping[DiskArtifact, int] = MappingProxyType(
    {
        _A.EVTX: 30,
        _A.REGISTRY_SYSTEM: 5,
        _A.REGISTRY_USER: 5,
        _A.PREFETCH: 3,
        _A.LNK: 3,
        _A.MFT: 10,
        _A.AMCACHE: 2,
        _A.BROWSER: 5,
        _A.RECYCLE_BIN: 1,
        _A.SYSLOG: 12,
        _A.AUTH_LOG: 8,
        _A.UTMP: 2,
        _A.SHELL_HISTORY: 3,
        _A.CRON: 2,
        _A.SYSTEMD_JOURNAL: 7,
        _A.PACKAGES: 2,
        _A.PREPROCESS: 0,
    }
)


def split_event_quotas(total: int) -> dict[DiskArtifact, int]:
    """Per-category stored-event quotas summing exactly to `total` (remainder to `evtx`)."""
    quotas = {a: total * pct // 100 for a, pct in EVENT_QUOTA_PERCENT.items()}
    quotas[_A.EVTX] += total - sum(quotas.values())
    return quotas


# YARA candidates: the M3 baseline rules are file rules anchored on `pe.*` / `MZ` (RT8). Widen
# this constant when ELF or script rules exist.
YARA_MAGIC_CLASSES: frozenset[str] = frozenset({"pe"})

# Every code the disk analyzer, its ingest and the API may store or answer (classified in the
# API's ops/error_classes.py; its test fails on a missing one). The segment download keeps the
# kit's `integrity_mismatch` (RT22).
DiskErrorCode = Literal[
    "not_implemented",
    "unsupported_disk_format",
    "no_supported_filesystem",
    "disk_image_too_large",
    "disk_image_set_too_large",
    "disk_segments_invalid",
    "disk_image_empty",
    "disk_parse_failed",
    "timeline_failed",
    "walk_memory",
    "insufficient_disk",
    "stage_timeout",
    "engine_unavailable",
    "integrity_mismatch",
    "export_hash_mismatch",
    "disk_export_not_allowed",
]
DISK_ERROR_CODES: tuple[str, ...] = get_args(DiskErrorCode)


# --- never collected, never exported (RT7) --------------------------------------------------

# By class (plan "Scope"). Patterns are lowercase globs over the '/'-separated path relative to
# the file system root: `**/` any directories, `*` within one name, `/**` everything below.
NEVER_COLLECT_PATTERNS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "hives": (
            "**/system32/config/sam",
            "**/system32/config/sam.log*",
            "**/system32/config/security",
            "**/system32/config/security.log*",
            "**/config/regback/**",
            "**/windows/repair/**",
            "**/ntds.dit",
        ),
        "credential_stores": (
            "**/microsoft/protect/**",
            "**/microsoft/credentials/**",
            "**/microsoft/vault/**",
            "**/etc/shadow",
            "**/etc/shadow-",
            "**/etc/gshadow",
            "**/etc/gshadow-",
            "**/etc/krb5.keytab",
            "**/*.keytab",
            "**/keyrings/**",
            "**/.gnupg/private-keys-v1.d/**",
            "**/.gnupg/secring.gpg",
            "**/networkmanager/system-connections/**",
            "**/wpa_supplicant*.conf",
        ),
        "browser_secrets": (
            "**/login data*",
            "**/cookies",
            "**/cookies-journal",
            "**/web data*",
            "**/local state",
            "**/logins.json",
            "**/key3.db",
            "**/key4.db",
            "**/cookies.sqlite*",
        ),
        "keys_and_tokens": (
            "**/ssh_host_*_key",
            "**/.ssh/id_*",
            "**/*.pfx",
            "**/*.p12",
            "**/*.pem",
            "**/*.key",
            "**/etc/ssl/private/**",
            "**/.netrc",
            "**/.git-credentials",
            "**/.pgpass",
            "**/.my.cnf",
            "**/.aws/credentials",
            "**/.azure/**",
            "**/.kube/config",
            "**/.docker/config.json",
            "**/*.kdbx",
        ),
        "plaintext_secret_configs": (
            "**/unattend.xml",
            "**/autounattend.xml",
            "**/sysprep.xml",
            "**/sysprep.inf",
            "**/groups.xml",
        ),
        "memory_on_disk": (
            "**/pagefile.sys",
            "**/hiberfil.sys",
            "**/swapfile.sys",
            "**/memory.dmp",
            "**/*.dmp",
        ),
    }
)


def _glob_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]*/)*")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("/.*")
            i += 3
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.DOTALL)


_NEVER_REGEXES: tuple[re.Pattern[str], ...] = tuple(
    _glob_regex(p) for patterns in NEVER_COLLECT_PATTERNS.values() for p in patterns
)


def _normalize(name: str, fs_case_insensitive: bool) -> str:
    parts = [p for p in name.replace("\\", "/").split("/") if p]
    if fs_case_insensitive:
        # Win32 ignores trailing dots and spaces: `SAM.` and `SAM ` name the same file.
        parts = [p.rstrip(". ") or p for p in parts]
    return "/".join(parts).casefold()


def never_collect(names: Iterable[str], fs_case_insensitive: bool) -> bool:
    """True when **any** name of an inode (every hard-link path; for a named stream, its
    file's names) matches the never-collected list (RT7).

    Matching is always case-folded (a refusal list errs toward refusing: a Linux Chrome
    profile's `Login Data` is refused on ext too); `fs_case_insensitive` (NTFS / FAT / exFAT)
    also strips Win32's ignored trailing dots and spaces from every component.
    """
    for name in names:
        path = _normalize(name, fs_case_insensitive)
        if any(rx.match(path) for rx in _NEVER_REGEXES):
            return True
    return False


# --- value types ----------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PRINTABLE = frozenset(string.printable) - frozenset("\t\n\r\x0b\x0c")


def _utf8_bounded(limit: int) -> Callable[[str], str]:
    def check(value: str) -> str:
        if _CONTROL.search(value):
            raise ValueError("control characters are escaped by the probe, never stored")
        if len(value.encode("utf-8", "surrogatepass")) > limit:
            raise ValueError(f"longer than {limit} UTF-8 bytes")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("lone surrogates are not valid UTF-8") from exc
        return value

    return check


def _printable(value: str) -> str:
    if any(ch not in _PRINTABLE for ch in value):
        raise ValueError("printable ASCII only")
    return value


DiskPath = Annotated[str, AfterValidator(_utf8_bounded(MAX_PATH_BYTES))]
DiskName = Annotated[str, AfterValidator(_utf8_bounded(MAX_NAME_BYTES))]
StreamName = Annotated[str, Field(min_length=1), AfterValidator(_utf8_bounded(255))]
EventPath = Annotated[str, AfterValidator(_utf8_bounded(1024))]
Message = Annotated[str, Field(max_length=2048, pattern=NO_NUL)]
Printable64 = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_printable)]
Text256 = Annotated[str, Field(max_length=256, pattern=NO_NUL)]
Address = Annotated[int, Field(ge=0, le=2**64 - 1)]  # numeric(20,0)
PartitionIndex = Annotated[int, Field(ge=0, lt=CAP_PARTITIONS)]
Md5 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Sha1 = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Uint32 = Annotated[int, Field(ge=0, le=2**32 - 1)]

_DISK_EARLIEST = datetime(1601, 1, 1, tzinfo=UTC)  # the NTFS epoch
_DISK_LATEST = datetime(2200, 1, 1, tzinfo=UTC)


def _disk_window(value: datetime) -> datetime:
    # An out-of-range time is sent as null by the probe (with a flag); here it is refused.
    if not _DISK_EARLIEST <= value < _DISK_LATEST:
        raise ValueError("timestamp outside 1601..2200")
    return value.astimezone(UTC)


DiskTimestamp = Annotated[AwareDatetime, AfterValidator(_disk_window)]


def _bigint(value: object) -> object:
    if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**63:
        raise ValueError("integer attribute outside the bigint range")
    return value


# Scalars only (bool first; no float, no nested value): 0017's jsonb check (M8's
# `memory_attributes_scalar`) agrees.
AttributeValue = Annotated[
    StrictBool | StrictInt | Annotated[str, Field(max_length=1024, pattern=NO_NUL)] | None,
    BeforeValidator(_bigint),
]
MAX_ATTRIBUTES_BYTES = 4096  # `disk_events.attributes`: octet_length(attributes::text) ≤ 4096


# --- file flags -----------------------------------------------------------------------------

FILE_FLAG_BITS: Mapping[str, int] = MappingProxyType(
    {
        "allocated": 1,
        "deleted": 2,
        "orphan": 4,
        "reallocated": 8,
        "name_lossy": 16,  # the original name bytes were not UTF-8 (replaced)
        "path_truncated": 32,  # the probe cut a longer path on a UTF-8 boundary (RT13)
        "hard_linked": 64,  # the inode has more than one name (RT7)
    }
)
FILE_FLAGS_MAX = sum(FILE_FLAG_BITS.values())

MediaHashStatus = Literal["matched", "mismatch", "absent", "not_verified"]
MEDIA_HASH_STATUSES: tuple[str, ...] = get_args(MediaHashStatus)
FsStatus = Literal["ok", "unsupported", "encrypted", "undetermined", "error", "truncated"]
FileType = Literal["reg", "dir", "lnk", "other"]
MagicClass = Literal["pe", "elf", "script", "archive", "document", "other", "empty"]
HashStatus = Literal["hashed", "too_large", "budget", "not_allocated", "not_regular", "error"]
KnownKind = Literal["good", "bad", "notable"]
TimeBasis = Literal["utc", "local_unknown"]
HashSetName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
YaraRuleName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]{1,128}$")]


# --- limits ---------------------------------------------------------------------------------

StageLimitKey = Literal[
    "verify", "layout", "walk", "collect", "scan", "log2timeline", "event_export", "extract"
]
STAGE_LIMIT_KEYS: tuple[str, ...] = get_args(StageLimitKey)


class StageLimits(Strict):
    """One sandboxed stage process (plan "Per stage"). `timeout_s` is a cap: the worker uses
    min(cap, time left before the deadline − the reserve) (RT5)."""

    rlimit_as: int = Field(gt=0, le=8 * GIB)
    rlimit_fsize: int = Field(gt=0, le=16 * GIB)
    write_budget: int = Field(gt=0, le=64 * GIB)  # the statvfs watchdog (RT4)
    timeout_s: int = Field(gt=0, le=6 * 3600)
    rlimit_nproc: int = Field(default=STAGE_NPROC, gt=0, le=STAGE_NPROC)


class DiskLimits(Strict):
    """Resource limits the API attaches to every disk job; the worker enforces them."""

    max_image_bytes: int = Field(gt=0, le=MAX_IMAGE_BYTES)
    max_media_bytes: int = Field(gt=0, le=MAX_MEDIA_BYTES)
    timeout_s: int = Field(gt=0, le=6 * 3600)
    deadline_reserve_s: int = Field(default=DEADLINE_RESERVE_S, ge=0)
    min_free_bytes: int = Field(default=4 * GIB, ge=0)
    verify_bytes_per_s: int = Field(default=100_000_000, gt=0)  # verify cap = size / this + base
    stages: dict[StageLimitKey, StageLimits]
    # budgets
    hash_budget_bytes: int = Field(ge=0)
    hash_max_file_bytes: int = Field(ge=0)
    yara_max_file_bytes: int = Field(ge=0)
    yara_max_files: int = Field(ge=0, le=1_000_000)
    yara_max_bytes: int = Field(ge=0)
    artifact_max_bytes: int = Field(ge=0)
    artifact_max_files: int = Field(ge=0, le=1_000_000)
    artifact_max_file_bytes: int = Field(ge=0)
    max_plaso_partitions: int = Field(ge=0, le=4)
    # caps
    max_partitions: int = Field(gt=0, le=CAP_PARTITIONS)
    max_filesystems: int = Field(gt=0, le=CAP_FILESYSTEMS)
    max_files: int = Field(gt=0, le=CAP_FILES)
    max_streams_per_file: int = Field(gt=0, le=CAP_STREAMS_PER_FILE)
    max_events_stored: int = Field(ge=0, le=CAP_EVENTS_STORED)
    max_events_read: int = Field(ge=0, le=CAP_EVENTS_READ)
    max_findings: int = Field(gt=0, le=CAP_FINDINGS)
    max_iocs: int = Field(gt=0, le=CAP_IOCS)
    max_timeline: int = Field(gt=0, le=CAP_TIMELINE)
    max_result_bytes: int = Field(gt=0, le=MAX_RESULT_BYTES)
    event_quotas: dict[DiskArtifact, Annotated[int, Field(ge=0)]]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if set(self.stages) != set(STAGE_LIMIT_KEYS):
            raise ValueError("every stage has limits")
        if any(s.timeout_s >= self.timeout_s for s in self.stages.values()):
            raise ValueError("every stage timeout is below the job timeout")
        if self.deadline_reserve_s >= self.timeout_s:
            raise ValueError("the deadline reserve is below the job timeout")
        if set(self.event_quotas) != set(DiskArtifact):
            raise ValueError("every artifact category has an event quota")
        if sum(self.event_quotas.values()) != self.max_events_stored:
            raise ValueError("the event quotas sum to max_events_stored")
        if self.max_events_read < self.max_events_stored:
            raise ValueError("max_events_read is at least max_events_stored")
        return self

    def max_lines(self) -> int:
        """Upper bound of a stream's lines at these caps (header + trailer + records + 1)."""
        return 3 + sum(
            (
                self.max_partitions,
                self.max_files,
                self.max_events_stored,
                self.max_findings,
                self.max_iocs,
                self.max_timeline,
            )
        )


# The per-profile budgets of plan "Profiles" (the API's settings may only lower them).
PROFILE_BUDGETS: Mapping[DiskProfile, Mapping[str, int]] = MappingProxyType(
    {
        DiskProfile.TRIAGE: MappingProxyType(
            {
                "hash_budget_bytes": 16 * GIB,
                "hash_max_file_bytes": 64 * MIB,
                "yara_max_file_bytes": 32 * MIB,
                "yara_max_files": 20_000,
                "yara_max_bytes": 4 * GIB,
                "artifact_max_bytes": 2 * GIB,
                "artifact_max_files": 20_000,
                "artifact_max_file_bytes": 512 * MIB,
                "max_plaso_partitions": 2,
            }
        ),
        DiskProfile.FULL: MappingProxyType(
            {
                "hash_budget_bytes": MAX_IMAGE_BYTES,  # "the image size": capped by the image
                "hash_max_file_bytes": GIB,
                "yara_max_file_bytes": 64 * MIB,
                "yara_max_files": 100_000,
                "yara_max_bytes": 16 * GIB,
                "artifact_max_bytes": 8 * GIB,
                "artifact_max_files": 20_000,
                "artifact_max_file_bytes": GIB,
                "max_plaso_partitions": 4,
            }
        ),
        DiskProfile.EXTRACT: MappingProxyType(
            {
                "hash_budget_bytes": MAX_EXPORT_FILES * MAX_EXPORT_FILE_BYTES,
                "hash_max_file_bytes": MAX_EXPORT_FILE_BYTES,
                "yara_max_file_bytes": 0,
                "yara_max_files": 0,
                "yara_max_bytes": 0,
                "artifact_max_bytes": 0,
                "artifact_max_files": 0,
                "artifact_max_file_bytes": 0,
                "max_plaso_partitions": 0,
            }
        ),
    }
)


def default_stage_limits(artifact_max_bytes: int, artifact_max_file_bytes: int) -> dict[
    str, StageLimits
]:
    """The plan's stage table (timeouts are caps; RT5 budgets them against the deadline)."""
    return {
        "verify": StageLimits(
            rlimit_as=GIB, rlimit_fsize=64 * MIB, write_budget=64 * MIB, timeout_s=600
        ),
        "layout": StageLimits(
            rlimit_as=GIB, rlimit_fsize=64 * MIB, write_budget=64 * MIB, timeout_s=600
        ),
        "walk": StageLimits(
            rlimit_as=2 * GIB, rlimit_fsize=2 * GIB, write_budget=2 * GIB, timeout_s=3600
        ),
        "collect": StageLimits(
            rlimit_as=GIB,
            rlimit_fsize=max(artifact_max_file_bytes, 1),
            write_budget=artifact_max_bytes + 64 * MIB,
            timeout_s=1800,
        ),
        "scan": StageLimits(
            rlimit_as=2 * GIB, rlimit_fsize=256 * MIB, write_budget=256 * MIB, timeout_s=3600
        ),
        "log2timeline": StageLimits(
            rlimit_as=5 * GIB // 2,
            rlimit_fsize=8 * GIB,
            write_budget=max(3 * artifact_max_bytes, 64 * MIB),
            timeout_s=5400,
        ),
        "event_export": StageLimits(
            rlimit_as=2 * GIB, rlimit_fsize=4 * GIB, write_budget=4 * GIB, timeout_s=1800
        ),
        "extract": StageLimits(
            rlimit_as=GIB,
            rlimit_fsize=MAX_EXPORT_FILE_BYTES,
            write_budget=MAX_EXPORT_FILES * MAX_EXPORT_FILE_BYTES,
            timeout_s=600,
        ),
    }


# --- jobs -----------------------------------------------------------------------------------


class DiskSegment(Strict):
    """One evidence item of the ordered segment set (`analysis_job_segments`)."""

    ordinal: Annotated[int, Field(ge=0, lt=MAX_SEGMENTS)]
    evidence_id: uuid.UUID
    expected_sha256: Sha256
    size_bytes: int = Field(gt=0)
    url: Url  # presigned GET of the exact object version


def _check_segments(segments: Sequence[DiskSegment], max_bytes: int) -> None:
    if [s.ordinal for s in segments] != list(range(len(segments))):
        raise ValueError("segment ordinals are contiguous from 0, in order")
    if len({s.evidence_id for s in segments}) != len(segments):
        raise ValueError("a segment's evidence is listed twice")
    if sum(s.size_bytes for s in segments) > max_bytes:
        raise ValueError("the segment set is larger than limits.max_image_bytes")


class DiskJobV1(Strict):
    """API -> disk analyzer (queue `disk`, task `disk.analyze`). No image cache key (RT1)."""

    schema_version: Literal["disk.v1"] = DISK_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    segments: Annotated[list[DiskSegment], Field(min_length=1, max_length=MAX_SEGMENTS)]
    profile: AnalysisProfile
    os_hint: OsHint
    result_post: PresignedPost
    ingest_token: Token
    limits: DiskLimits
    deadline_at: AwareDatetime  # the job's deadline: the worker's stage budget (RT5)

    @model_validator(mode="after")
    def _segments(self) -> Self:
        _check_segments(self.segments, self.limits.max_image_bytes)
        return self


class DiskExportFile(Strict):
    export_id: uuid.UUID
    partition_index: PartitionIndex
    meta_addr: Address
    meta_seq: Uint32 | None = None
    stream: StreamName | None = None
    expected_size: int = Field(gt=0, le=MAX_EXPORT_FILE_BYTES)


class DiskExportJobV1(Strict):
    """API -> disk analyzer (queue `disk`, task `disk.export`, job profile `extract`).

    `result_posts[i]` receives `files[i]`; the last entry receives the result stream."""

    schema_version: Literal["disk-export.v1"] = DISK_EXPORT_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    source_job_id: uuid.UUID
    segments: Annotated[list[DiskSegment], Field(min_length=1, max_length=MAX_SEGMENTS)]
    files: Annotated[list[DiskExportFile], Field(min_length=1, max_length=MAX_EXPORT_FILES)]
    result_posts: Annotated[
        list[PresignedPost], Field(min_length=2, max_length=MAX_EXPORT_FILES + 1)
    ]
    ingest_token: Token
    limits: DiskLimits
    deadline_at: AwareDatetime

    @model_validator(mode="after")
    def _shape(self) -> Self:
        _check_segments(self.segments, self.limits.max_image_bytes)
        if len({f.export_id for f in self.files}) != len(self.files):
            raise ValueError("an export id is listed twice")
        if len(self.result_posts) != len(self.files) + 1:
            raise ValueError("one result post per file plus one for the result stream")
        return self


# --- result lines ---------------------------------------------------------------------------


class EwfInfo(Strict):
    """Worker-reported (RT17): consistent with the hash stored at acquisition, never "verified"."""

    stored_md5: Md5 | None = None
    stored_sha1: Sha1 | None = None
    media_hash_status: MediaHashStatus
    # Acquirer-chosen text (case number, examiner, notes, acquiry date): bounded, inert.
    meta: Annotated[dict[Text64, Text256], Field(max_length=8)] = {}

    @model_validator(mode="after")
    def _status(self) -> Self:
        stored = self.stored_md5 is not None or self.stored_sha1 is not None
        if (self.media_hash_status == "absent") == stored:
            raise ValueError("`absent` exactly when no hash is stored")
        return self


class ImageInfo(Strict):
    format: ImageFormat
    segments: Annotated[int, Field(ge=1, le=MAX_SEGMENTS)]
    media_size: Count
    sector_size: Annotated[int, Field(ge=1, le=65_536)]
    media_sha256: Sha256 | None = None  # worker-computed over the media (split raw / EWF)
    ewf: EwfInfo | None = None

    @model_validator(mode="after")
    def _ewf_iff(self) -> Self:
        if (self.format == ImageFormat.EWF) != (self.ewf is not None):
            raise ValueError("EWF details exactly for an EWF image")
        if self.format == ImageFormat.RAW and self.segments != 1:
            raise ValueError("a raw image is one segment")
        return self


HashSetKind = Literal["known_good", "known_bad", "notable"]
HashAlgo = Literal["sha256", "sha1", "md5"]


class HashSetRef(Strict):
    name: HashSetName
    kind: HashSetKind
    count: Count
    manifest_sha256: Sha256


class StageReport(Strict):
    stage: DiskStage
    partition_index: PartitionIndex | None = None
    status: StageStatus
    reason: Text64 | None = None  # e.g. `deadline` for `skipped`
    rows: Count = 0
    truncated: bool = False
    duration_ms: Count = 0
    error_code: ErrorCode | None = None
    # PEP 578 audit-hook refusals per event family (socket, subprocess, ...): zero expected.
    audit_counts: Annotated[dict[Text64, Count], Field(max_length=16)] = {}


class ArtifactStat(Strict):
    artifact: DiskArtifact
    files: Count = 0
    bytes: Count = 0
    events_read: Count = 0
    events_stored: Count = 0


class DiskResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["disk.v1"] = DISK_SCHEMA
    job_id: uuid.UUID
    profile: AnalysisProfile
    engine: Literal["tsk"]
    # `replay` is the test-profile-only timeline engine (hand-written rows, never real analysis).
    timeline_engine: Literal["plaso", "replay", "none"]
    tool_versions: ToolVersions
    image: ImageInfo
    hashsets: Annotated[list[HashSetRef], Field(max_length=32)] = []
    stages: Annotated[list[StageReport], Field(max_length=512)] = []
    artifacts: Annotated[list[ArtifactStat], Field(max_length=len(DiskArtifact))] = []
    engine_errors: Annotated[list[ErrorCode], Field(max_length=32)] = []
    truncated: Annotated[dict[ShortText, bool], Field(max_length=32)] = {}

    @model_validator(mode="after")
    def _unique(self) -> Self:
        names = [a.artifact for a in self.artifacts]
        if len(set(names)) != len(names):
            raise ValueError("an artifact category is reported twice")
        sets = [h.name for h in self.hashsets]
        if len(set(sets)) != len(sets):
            raise ValueError("a hash set is reported twice")
        return self


class DiskPartitionRecord(Strict):
    kind: Literal["partition"] = "partition"
    index: PartitionIndex
    start_sector: Address
    length_sectors: Address
    description: Text128 | None = None
    vs_flags: Literal["alloc", "unalloc", "meta", "none"] = "alloc"
    fs_type: FsType | None = None
    fs_status: FsStatus
    fs_label: Text128 | None = None
    fs_uuid: Text64 | None = None
    block_size: Annotated[int, Field(ge=1, le=2**31 - 1)] | None = None
    os: PartitionOs = "none"
    os_name: Text128 | None = None  # inert text from the image
    counts: Annotated[dict[Text64, Count], Field(max_length=16)] = {}
    error_code: ErrorCode | None = None

    @model_validator(mode="after")
    def _fs(self) -> Self:
        if self.fs_status == "ok" and self.fs_type is None:
            raise ValueError("an opened file system names its type")
        return self


class DiskFileRecord(Strict):
    """One directory entry (one name; a hard-linked inode appears once per name with
    `hard_linked` set). Natural key: partition_index + meta_addr + meta_seq + stream +
    parent_addr + name."""

    kind: Literal["file"] = "file"
    partition_index: PartitionIndex
    meta_addr: Address
    meta_seq: Uint32 | None = None
    stream: StreamName | None = None  # NTFS named stream
    path: DiskPath
    parent_addr: Address | None = None  # the walked directory's meta_addr (RT13)
    name: DiskName
    ext: Annotated[str, Field(max_length=32, pattern=NO_NUL)] | None = None
    type: FileType
    flags: Annotated[int, Field(ge=0, le=FILE_FLAGS_MAX)]
    size: Count | None = None
    mode: Annotated[int, Field(ge=0, le=0o177777)] | None = None
    uid: Uint32 | None = None
    gid: Uint32 | None = None
    mtime: DiskTimestamp | None = None
    atime: DiskTimestamp | None = None
    ctime: DiskTimestamp | None = None
    crtime: DiskTimestamp | None = None
    time_basis: TimeBasis = "utc"
    magic: MagicClass | None = None
    hash_status: HashStatus | None = None
    md5: Md5 | None = None
    sha1: Sha1 | None = None
    sha256: Sha256 | None = None
    known: KnownKind | None = None
    known_set: HashSetName | None = None
    yara_rules: Annotated[list[YaraRuleName], Field(max_length=16)] = []

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        hashed = self.md5 is not None or self.sha1 is not None or self.sha256 is not None
        if hashed != (self.hash_status == "hashed"):
            raise ValueError("hashes exactly when hash_status is `hashed`")
        if hashed and self.flags & FILE_FLAG_BITS["deleted"]:
            raise ValueError("deleted entries are never hashed")
        if (self.known is None) != (self.known_set is None):
            raise ValueError("`known` and `known_set` go together")
        if self.flags & FILE_FLAG_BITS["deleted"] and self.flags & FILE_FLAG_BITS["allocated"]:
            raise ValueError("an entry is either allocated or deleted")
        return self

    def has_flag(self, name: str) -> bool:
        return bool(self.flags & FILE_FLAG_BITS[name])


class FileKey(Strict):
    """An event's optional link to a listed file (resolved to `disk_files.id` at ingest)."""

    partition_index: PartitionIndex
    meta_addr: Address
    meta_seq: Uint32 | None = None
    stream: StreamName | None = None


class DiskEventRecord(Strict):
    kind: Literal["event"] = "event"
    ordinal: Count  # position in the worker's event export (findings cite it, RT10)
    ts: DiskTimestamp
    ts_desc: Printable64
    artifact: DiskArtifact
    parser: Printable64
    data_type: Printable64
    partition_index: PartitionIndex
    path: EventPath
    file: FileKey | None = None
    message: Message
    attributes: Annotated[dict[Text64, AttributeValue], Field(max_length=32)] = {}

    @model_validator(mode="after")
    def _fits_the_column(self) -> Self:
        compact = json.dumps(self.attributes, ensure_ascii=False, separators=(",", ":"))
        if len(compact.encode()) + 2 * len(self.attributes) > MAX_ATTRIBUTES_BYTES:
            raise ValueError("event attributes exceed 4 KiB")
        return self


# `analysis_timeline.event` holds ≤ 16 characters.
DiskTimelineKind = Literal[
    "image_acquired",
    "finding",
    "file_created",
    "file_modified",
    "file_executed",
    "logon",
    "service_install",
    "log_cleared",
    "account_change",
    "persistence",
]


class DiskTimelineEvent(Strict):
    kind: Literal["timeline"] = "timeline"
    ts: Timestamp
    event: DiskTimelineKind
    title: Text255
    severity: Literal["info", "low", "medium", "high"] | None = None
    ref: Text64 | None = None  # finding id, event ordinal or file id
    src_ip: Ip | None = None


DiskRecordLine = Annotated[
    DiskPartitionRecord
    | DiskFileRecord
    | DiskEventRecord
    | FindingRecord
    | IocRecord
    | DiskTimelineEvent,
    Field(discriminator="kind"),
]
DiskAnyLine = Annotated[
    DiskResultHeader
    | DiskPartitionRecord
    | DiskFileRecord
    | DiskEventRecord
    | FindingRecord
    | IocRecord
    | DiskTimelineEvent
    | ResultTrailer,
    Field(discriminator="kind"),
]
DISK_RECORD_ADAPTER: TypeAdapter[DiskRecordLine] = TypeAdapter(DiskRecordLine)
DISK_LINE_ADAPTER: TypeAdapter[DiskAnyLine] = TypeAdapter(DiskAnyLine)

# The order of line kinds in a full stream (ingest checks it; equal kinds are contiguous).
LINE_ORDER: tuple[str, ...] = (
    "header",
    "partition",
    "file",
    "event",
    "finding",
    "ioc",
    "timeline",
    "trailer",
)
DIAGNOSTIC_ERROR_CODES: frozenset[str] = frozenset(
    {"no_supported_filesystem", "unsupported_disk_format"}
)


def check_line_order(kinds: Iterable[str]) -> None:
    """Kinds appear in `LINE_ORDER` order: header first, trailer last, never going back."""
    rank = {k: i for i, k in enumerate(LINE_ORDER)}
    seq = list(kinds)
    if len(seq) < 2 or seq[0] != "header" or seq[-1] != "trailer":
        raise ValueError("a stream is header first, trailer last")
    if seq.count("header") != 1 or seq.count("trailer") != 1:
        raise ValueError("one header and one trailer")
    last = 0
    for kind in seq:
        if rank[kind] < last:
            raise ValueError(f"`{kind}` line out of order")
        last = rank[kind]


def check_diagnostic_kinds(kinds: Iterable[str]) -> None:
    """The diagnostic-stream rule: header, at most the partitions, trailer."""
    seq = list(kinds)
    if len(seq) < 2 or seq[0] != "header" or seq[-1] != "trailer":
        raise ValueError("a diagnostic stream is header, partition*, trailer")
    if any(k != "partition" for k in seq[1:-1]):
        raise ValueError("a diagnostic stream carries only partition lines")


# --- export result (`disk-export.v1`) -------------------------------------------------------


class ExportedFile(Strict):
    export_id: uuid.UUID
    status: Literal["ok", "failed"]
    size: Annotated[int, Field(ge=0, le=MAX_EXPORT_FILE_BYTES)] | None = None
    sha256: Sha256 | None = None  # worker-computed: untrusted, display only
    error_code: ErrorCode | None = None

    @model_validator(mode="after")
    def _status(self) -> Self:
        ok = self.status == "ok"
        if ok != (self.size is not None and self.sha256 is not None):
            raise ValueError("an exported file has its size and sha256, a failed one neither")
        if ok == (self.error_code is not None):
            raise ValueError("a failed file has an error code, an exported one none")
        return self


class DiskExportResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["disk-export.v1"] = DISK_EXPORT_SCHEMA
    job_id: uuid.UUID
    tool_versions: ToolVersions
    files: Annotated[list[ExportedFile], Field(min_length=1, max_length=MAX_EXPORT_FILES)]

    @model_validator(mode="after")
    def _unique(self) -> Self:
        if len({f.export_id for f in self.files}) != len(self.files):
            raise ValueError("an export id is reported twice")
        return self


DiskExportAnyLine = Annotated[DiskExportResultHeader | ResultTrailer, Field(discriminator="kind")]
DISK_EXPORT_LINE_ADAPTER: TypeAdapter[DiskExportAnyLine] = TypeAdapter(DiskExportAnyLine)


# --- hash-set store manifest (the worker and the trusted `disk-hashsets` tool) --------------


def _relative(value: str) -> str:
    parts = value.split("/")
    if value.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError("a manifest path is relative, without empty, . or .. segments")
    return value


ManifestPath = Annotated[
    str,
    Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$"),
    AfterValidator(_relative),
]


class HashSetFile(Strict):
    algo: HashAlgo
    path: ManifestPath  # `<name>/<algo>.bin`: sorted unique fixed-width records
    sha256: Sha256
    count: Count


class HashSet(Strict):
    name: HashSetName
    kind: HashSetKind
    algorithms: Annotated[list[HashAlgo], Field(min_length=1, max_length=3)]
    files: Annotated[list[HashSetFile], Field(min_length=1, max_length=3)]
    source_sha256: Sha256
    imported_at: Timestamp
    tool_version: ShortText

    @model_validator(mode="after")
    def _files(self) -> Self:
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("an algorithm is listed twice")
        if sorted(f.algo for f in self.files) != sorted(self.algorithms):
            raise ValueError("exactly one file per algorithm")
        return self


class HashSetManifestV1(Strict):
    """`/hashsets/manifest.json`: written only by the `disk-hashsets` tool."""

    version: Literal[1] = 1
    sets: Annotated[list[HashSet], Field(max_length=64)] = []

    @model_validator(mode="after")
    def _unique(self) -> Self:
        names = [s.name for s in self.sets]
        if len(set(names)) != len(names):
            raise ValueError("a hash set is listed twice")
        paths = [f.path for s in self.sets for f in s.files]
        if len(set(paths)) != len(paths):
            raise ValueError("a manifest path is listed twice")
        return self


# --- detection input / output (phase 6 builds against these; phase 2 calls them) -------------


@dataclass(frozen=True)
class DiskView:
    """The frozen detection input. `events` is a factory: each call returns a fresh iterator
    over every event (two passes, RT10: pass 1 detections, pass 2 storage selection)."""

    profile: AnalysisProfile
    image: ImageInfo
    partitions: tuple[DiskPartitionRecord, ...]
    files: Sequence[DiskFileRecord]
    events: Callable[[], Iterator[DiskEventRecord]]
    hashsets: tuple[HashSetRef, ...] = ()
    truncated: Mapping[str, bool] = field(default_factory=dict)


@dataclass
class DetectionOutput:
    findings: list[FindingRecord] = field(default_factory=list)
    iocs: list[IocRecord] = field(default_factory=list)
    timeline: list[DiskTimelineEvent] = field(default_factory=list)
    # Event ordinals cited by findings: always stored (RT10).
    cited_events: set[int] = field(default_factory=set)
    truncated: bool = False


__all__ = [
    "ARTIFACTS_BY_PROFILE",
    "CASE_INSENSITIVE_FS",
    "DIAGNOSTIC_ERROR_CODES",
    "DISK_ERROR_CODES",
    "DISK_EXPORT_LINE_ADAPTER",
    "DISK_EXPORT_SCHEMA",
    "DISK_LINE_ADAPTER",
    "DISK_RECORD_ADAPTER",
    "DISK_SCHEMA",
    "EVENT_QUOTA_PERCENT",
    "FILE_FLAG_BITS",
    "LINE_ORDER",
    "MAX_EXPORT_FILES",
    "MAX_EXPORT_FILE_BYTES",
    "MAX_IMAGE_BYTES",
    "MAX_MEDIA_BYTES",
    "MAX_SEGMENTS",
    "MEDIA_HASH_STATUSES",
    "NEVER_COLLECT_PATTERNS",
    "PROFILE_BUDGETS",
    "STAGE_LIMIT_KEYS",
    "YARA_MAGIC_CLASSES",
    "ArtifactStat",
    "DetectionOutput",
    "DiskAnyLine",
    "DiskArtifact",
    "DiskErrorCode",
    "DiskEventRecord",
    "DiskExportFile",
    "DiskExportJobV1",
    "DiskExportResultHeader",
    "DiskFileRecord",
    "DiskJobV1",
    "DiskLimits",
    "DiskOs",
    "DiskPartitionRecord",
    "DiskProfile",
    "DiskRecordLine",
    "DiskResultHeader",
    "DiskSegment",
    "DiskStage",
    "DiskTimelineEvent",
    "DiskView",
    "EwfInfo",
    "ExportedFile",
    "FileKey",
    "FsType",
    "HashSet",
    "HashSetFile",
    "HashSetManifestV1",
    "HashSetRef",
    "ImageFormat",
    "ImageInfo",
    "OsHint",
    "StageLimits",
    "StageReport",
    "StageStatus",
    "check_diagnostic_kinds",
    "check_line_order",
    "default_stage_limits",
    "never_collect",
    "split_event_quotas",
]
