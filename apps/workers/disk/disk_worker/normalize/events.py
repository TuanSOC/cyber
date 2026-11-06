"""Plaso events → `DiskEventRecord` (M9 phase 3; root side, streaming, two passes, RT10).

Input: the root-written **sources manifest** (`write_sources`; `TimelineOutput.events_path`)
listing, per Plaso run, the exported `events.jsonl` (psort `json_line` shape; sealed,
root-owned, on disk), the collect stage's `collected.jsonl` and root's own collect arguments
(`input/collect-p<i>.json`). Everything in the event files is attacker-influenced (Plaso parsed
image content), so every value is re-checked here:
- **reading:** line by line through `reader.read_jsonl` (64 KiB line cap: a longer line is
  dropped and counted), at most `limits.max_events_read` rows over all sources;
- **`ts`:** `timestamp` (µs since the epoch, an int); a `NotSet` date or a time outside
  1601..2200 is dropped and counted; `ts_desc` from `timestamp_desc` (printable, <= 64);
- **`path`:** `filename` / `display_name` / the path spec's location, rewritten from the
  mirrored tree back to the original path through `collected.jsonl` **and** root's collect
  arguments (the target comes from the probe, the original path, the natural key and the
  category from root's own plan); unknown → dropped and counted;
- **`artifact`:** the collect plan's category of that file;
- **attributes:** a per-`data_type` allow-list of scalar fields (`FIELD_MAPS`); lists are
  flattened to `<name>.<i>` + `<name>_count`, EVTX `strings` through phase 6's
  `evtx_fields.flatten_strings`; strings <= 1 024 characters, NUL removed; integers outside
  the JavaScript-safe range, and NTFS file references always, become decimal strings; at most
  32 attributes within the 4 KiB column budget (long strings are shortened first);
- `message`: Plaso's formatted message, NUL removed, <= 2 048 characters.

Ordinals are the position of each **accepted** event in this deterministic order (sources in
manifest order, lines in file order), so every pass assigns the same ordinal to the same event
and findings can cite it (`event:<ordinal>`).

Two passes (RT10), through `EventSource`:
1. `events()`: every normalized event, in order, for the detections (`Detector.observe`); while
   it streams, a bounded min-heap per category keeps the (ts, ordinal) of the most recent events
   within the `DiskLimits.event_quotas`, and one byte per event records its category;
2. `select(cited)`: the stored set = the heaps ∪ every cited ordinal (so no finding loses its
   evidence to eviction, even when it was raised after the quota was full); the per-category
   `events_read` / `events_stored` are known **before** the stream is written, and
   `Selection.records()` re-reads the files and yields only the stored events.

Memory: the heaps (<= `max_events_stored` tuples), the cited set (<= findings cap × refs) and
one byte per event read (<= `max_events_read`); never the events themselves.
"""

import heapq
import json
import os
import re
import stat
from array import array
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, cast

from cyberlab_jobs.disk import (
    AnalysisProfile,
    DiskArtifact,
    DiskEventRecord,
    DiskLimits,
    DiskOs,
    FileKey,
)
from pydantic import ValidationError

from disk_worker.detections.evtx_fields import MAX_STRING_CHARS, flatten_strings
from disk_worker.normalize.models import CollectedRow
from disk_worker.normalize.reader import ReadStats, read_jsonl
from disk_worker.timeline import catalog

SOURCES_VERSION = 1
MAX_SOURCES = 64
MAX_SOURCES_BYTES = 1024 * 1024
MAX_PLAN_BYTES = 64 * 1024**2
MAX_COLLECTED_BYTES = 256 * 1024**2
MAX_EVENTS_BYTES = 4 * 1024**3 + 64 * 1024**2  # the export stage's RLIMIT_FSIZE + slack
MAX_MESSAGE = 2048
MAX_TEXT = MAX_STRING_CHARS  # 1 024 characters per string attribute
MAX_ATTRIBUTES = 32
MAX_ATTRIBUTE_BYTES = 4096
MAX_LIST_ITEMS = 16
MAX_PATH_BYTES = 1024  # `EventPath`
MAX_PATH_DEPTH = 8  # nested path specs followed for a location
SAFE_INT = 2**53 - 1
U32 = 2**32 - 1
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MIN_US = (datetime(1601, 1, 1, tzinfo=UTC) - _EPOCH) // timedelta(microseconds=1)
MAX_US = (datetime(2200, 1, 1, tzinfo=UTC) - _EPOCH) // timedelta(microseconds=1)
_TYPE_PREFIX = re.compile(r"^[A-Z][A-Z0-9_]{1,31}:")
_ARTIFACTS: tuple[DiskArtifact, ...] = tuple(DiskArtifact)
_ARTIFACT_CODE = {a: i for i, a in enumerate(_ARTIFACTS)}
EVTX = "windows:evtx:record"

# --- per-data_type allow-lists -----------------------------------------------------------------

# (attribute, kind): `s` a scalar, `l` a list flattened to `<name>.<i>`.
FieldSpec = tuple[str, str]
_REGISTRY: tuple[FieldSpec, ...] = (("key_path", "s"),)
_SYSLOG: tuple[FieldSpec, ...] = (
    ("hostname", "s"),
    ("reporter", "s"),
    ("pid", "s"),
    ("severity", "s"),
    ("facility", "s"),
    ("body", "s"),
)
FIELD_MAPS: Mapping[str, tuple[FieldSpec, ...]] = {
    # Windows registry (winreg plugins)
    "windows:registry:key_value": _REGISTRY,
    "windows:registry:run": (*_REGISTRY, ("entries", "l")),
    "windows:registry:service": (
        *_REGISTRY,
        ("name", "s"),
        ("image_path", "s"),
        ("service_dll", "s"),
        ("start_type", "s"),
        ("service_type", "s"),
        ("object_name", "s"),
    ),
    "windows:registry:userassist": (
        *_REGISTRY,
        ("value_name", "s"),
        ("number_of_executions", "s"),
        ("application_focus_count", "s"),
    ),
    "windows:registry:bam": (("binary_path", "s"), ("user_sid", "s")),
    "windows:registry:amcache": (
        ("full_path", "s"),
        ("sha1", "s"),
        ("product_name", "s"),
        ("company_name", "s"),
        ("file_description", "s"),
        ("file_version", "s"),
        ("file_size", "s"),
        ("file_reference", "s"),
    ),
    "windows:registry:appcompatcache": (*_REGISTRY, ("path", "s"), ("entry_index", "s")),
    # Windows files
    "windows:prefetch:execution": (
        ("executable", "s"),
        ("run_count", "s"),
        ("prefetch_hash", "s"),
        ("path_hints", "l"),
    ),
    "windows:lnk:link": (
        ("local_path", "s"),
        ("network_path", "s"),
        ("relative_path", "s"),
        ("working_directory", "s"),
        ("command_line_arguments", "s"),
        ("env_var_location", "s"),
        ("icon_location", "s"),
        ("description", "s"),
        ("file_size", "s"),
        ("drive_serial_number", "s"),
        ("volume_label", "s"),
    ),
    "windows:metadata:deleted_item": (
        ("original_filename", "s"),
        ("file_size", "s"),
        ("drive_number", "s"),
    ),
    "fs:stat:ntfs": (
        ("name", "s"),
        ("file_reference", "s"),
        ("parent_file_reference", "s"),
        ("attribute_type", "s"),
        ("is_allocated", "s"),
    ),
    # Browsers
    "chrome:history:page_visited": (
        ("url", "s"),
        ("title", "s"),
        ("visit_count", "s"),
        ("typed_count", "s"),
    ),
    "chrome:history:file_downloaded": (
        ("url", "s"),
        ("full_path", "s"),
        ("received_bytes", "s"),
        ("total_bytes", "s"),
    ),
    "firefox:places:page_visited": (
        ("url", "s"),
        ("title", "s"),
        ("visit_count", "s"),
        ("visit_type", "s"),
    ),
    "firefox:downloads:download": (("url", "s"), ("full_path", "s"), ("total_bytes", "s")),
    # Linux text logs
    "syslog:line": _SYSLOG,
    "syslog:cron:task_run": (*_SYSLOG, ("command", "s"), ("username", "s")),
    "syslog:ssh:login": (
        *_SYSLOG,
        ("username", "s"),
        ("address", "s"),
        ("port", "s"),
        ("authentication_method", "s"),
        ("protocol", "s"),
    ),
    "syslog:ssh:failed_connection": (
        *_SYSLOG,
        ("username", "s"),
        ("address", "s"),
        ("port", "s"),
        ("authentication_method", "s"),
    ),
    "syslog:ssh:opened_connection": (*_SYSLOG, ("address", "s"), ("port", "s")),
    "linux:utmp:event": (
        ("username", "s"),
        ("hostname", "s"),
        ("terminal", "s"),
        ("terminal_identifier", "s"),
        ("pid", "s"),
        ("type", "s"),
        ("ip_address", "s"),
        ("exit_status", "s"),
    ),
    "bash:history:command": (("command", "s"),),
    "shell:zsh:history": (("command", "s"), ("elapsed_seconds", "s")),
    "dpkg:line": (("body", "s"),),
    "apt:history:line": (
        ("command_line", "s"),
        ("command", "s"),
        ("packages", "s"),
        ("requester", "s"),
        ("error", "s"),
    ),
    "systemd:journal": (("hostname", "s"), ("reporter", "s"), ("pid", "s"), ("body", "s")),
}
# Integer fields that are 64-bit by nature: always strings (JS-safe, the "64-bit as strings"
# convention), whatever their value.
WIDE_FIELDS = frozenset({"file_reference", "parent_file_reference"})
# EVTX: identifiers first, then the positional strings (phase 6 reads them by index), then the
# record details while slots are left (32 at most).
EVTX_HEAD: tuple[str, ...] = ("event_identifier", "source_name")
EVTX_TAIL: tuple[str, ...] = ("record_number", "computer_name", "user_sid", "event_level")


def _scalar(name: str, value: object) -> str | int | bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if name in WIDE_FIELDS or not -SAFE_INT <= value <= SAFE_INT:
            return str(value)
        return value
    if isinstance(value, str):
        text = value.replace("\x00", "")[:MAX_TEXT]
        return text or None
    return None  # floats, objects and lists are never stored as scalars


def _flatten(name: str, value: object) -> dict[str, str | int | bool]:
    if not isinstance(value, list):
        single = _scalar(name, value)
        return {} if single is None else {name: single}
    out: dict[str, str | int | bool] = {f"{name}_count": len(value)}
    for i, item in enumerate(value[:MAX_LIST_ITEMS]):
        scalar = _scalar(name, item)
        out[f"{name}.{i}"] = "" if scalar is None else str(scalar)[:MAX_TEXT]
    return out


def _evtx(raw: Mapping[str, Any]) -> dict[str, str | int | bool]:
    out: dict[str, str | int | bool] = {}
    for name in EVTX_HEAD:
        value = _scalar(name, raw.get(name))
        if value is not None:
            out[name] = value
    strings = raw.get("strings")
    if isinstance(strings, list):
        out.update(flatten_strings(strings))
    for name in EVTX_TAIL:
        value = _scalar(name, raw.get(name))
        if value is not None and len(out) < MAX_ATTRIBUTES:
            out[name] = value
    return out


def _size(attributes: Mapping[str, object]) -> int:
    compact = json.dumps(attributes, ensure_ascii=False, separators=(",", ":"))
    return len(compact.encode()) + 2 * len(attributes)  # the contract's own measure


def _fit(attributes: dict[str, str | int | bool]) -> dict[str, str | int | bool]:
    """At most 32 attributes within the 4 KiB column budget: long strings are shortened first
    (EVTX positions stay intact), trailing attributes dropped last."""
    out = dict(list(attributes.items())[:MAX_ATTRIBUTES])
    cap = MAX_TEXT
    while _size(out) > MAX_ATTRIBUTE_BYTES and cap > 16:
        cap //= 2
        out = {k: v[:cap] if isinstance(v, str) else v for k, v in out.items()}
    while out and _size(out) > MAX_ATTRIBUTE_BYTES:
        out.popitem()
    return out


def attributes_of(data_type: str, raw: Mapping[str, Any]) -> dict[str, str | int | bool]:
    """The allow-listed attributes of one exported event (unknown data types keep none)."""
    if data_type == EVTX:
        return _fit(_evtx(raw))
    out: dict[str, str | int | bool] = {}
    for name, kind in FIELD_MAPS.get(data_type, ()):
        if name not in raw:
            continue
        value = raw[name]
        out.update(_flatten(name, value) if kind == "l" else _single(name, value))
    return _fit(out)


def _single(name: str, value: object) -> dict[str, str | int | bool]:
    scalar = _scalar(name, value)
    return {} if scalar is None else {name: scalar}


# --- sources -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """One Plaso run (or one replayed fixture file) of one partition."""

    partition_index: int
    events: Path
    os: DiskOs
    profile: AnalysisProfile
    # The prefixes Plaso reports for the mirrored tree (the path root passed and its realpath).
    mirror_roots: tuple[str, ...]
    collected: Path | None = None  # the collect stage's `collected.jsonl` (sealed)
    plan: Path | None = None  # root's own collect arguments (`input/collect-p<i>.json`)
    # Replay only (test profile): a path no collected file maps is classified by the catalog
    # itself (the fixtures name files the generated image may not hold).
    replay: bool = False


def write_sources(path: Path, engine: str, sources: Sequence[Source]) -> Path:
    """Root writes the manifest once (O_EXCL, 0400)."""
    doc = {
        "version": SOURCES_VERSION,
        "engine": engine,
        "sources": [
            {
                "partition_index": s.partition_index,
                "events": str(s.events),
                "os": s.os,
                "profile": s.profile,
                "mirror_roots": list(s.mirror_roots),
                "collected": None if s.collected is None else str(s.collected),
                "plan": None if s.plan is None else str(s.plan),
                "replay": s.replay,
            }
            for s in sources[:MAX_SOURCES]
        ],
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o400)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=True, allow_nan=False)
    return path


def read_sources(path: Path) -> list[Source]:
    with _open_regular(path) as f:
        raw = f.read(MAX_SOURCES_BYTES + 1)
    if len(raw) > MAX_SOURCES_BYTES:
        raise ValueError("the sources manifest is too large")
    doc = json.loads(raw)
    if not isinstance(doc, dict) or doc.get("version") != SOURCES_VERSION:
        raise ValueError("unknown sources manifest")
    out: list[Source] = []
    for s in doc["sources"][:MAX_SOURCES]:
        out.append(
            Source(
                partition_index=int(s["partition_index"]),
                events=Path(s["events"]),
                os=cast(DiskOs, s["os"]),
                profile=cast(AnalysisProfile, s["profile"]),
                mirror_roots=tuple(str(r) for r in s["mirror_roots"]),
                collected=Path(s["collected"]) if s.get("collected") else None,
                plan=Path(s["plan"]) if s.get("plan") else None,
                replay=bool(s.get("replay", False)),
            )
        )
    return out


def _open_regular(path: Path) -> BinaryIO:
    """A regular file opened without following a final symlink (sealed dirs hold none)."""
    nonblock = getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | nonblock)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path.name} is not a regular file")
        if nonblock:
            os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


# --- the collect manifest -------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """A file of the mirrored tree: its original path, category and natural key."""

    path: str
    artifact: DiskArtifact
    file: FileKey | None = None


def _cut_utf8(text: str, limit: int) -> str:
    raw = text.encode("utf-8", "surrogatepass")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", "ignore")


def _file_key(partition_index: int, item: Mapping[str, Any]) -> FileKey | None:
    try:
        seq = item.get("meta_seq")
        return FileKey(
            partition_index=partition_index,
            meta_addr=item["meta_addr"],
            meta_seq=seq if isinstance(seq, int) and 0 <= seq <= U32 else None,
            stream=item.get("stream") or None,
        )
    except (KeyError, ValidationError):
        return None


def _plan_items(path: Path | None) -> dict[int, Mapping[str, Any]] | None:
    """Root's collect arguments by item number (None: no plan to check against)."""
    if path is None:
        return None
    with _open_regular(path) as f:
        raw = f.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        return {}
    doc = json.loads(raw)
    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        return {}
    return {int(i["n"]): i for i in items if isinstance(i, dict) and isinstance(i.get("n"), int)}


def load_targets(source: Source, max_rows: int = 1_000_000) -> dict[str, Target]:
    """`target → Target` from `collected.jsonl`, each row checked against root's own plan item
    (same number, natural key and category; the original path and key come from the plan)."""
    if source.collected is None:
        return {}
    try:
        items = _plan_items(source.plan)
    except (OSError, ValueError):
        return {}
    targets: dict[str, Target] = {}
    stats = ReadStats()
    try:
        f = _open_regular(source.collected)
    except (OSError, ValueError):
        return {}
    with f:
        for raw in read_jsonl(f, stats, max_rows=max_rows, max_bytes=MAX_COLLECTED_BYTES):
            try:
                row = CollectedRow.model_validate(raw)
            except ValidationError:
                continue
            if row.status != "ok" or not row.target or row.artifact not in DiskArtifact:
                continue
            item: Mapping[str, Any] = row.model_dump()
            if items is not None:
                planned = items.get(row.n)
                if planned is None or planned.get("meta_addr") != row.meta_addr:
                    continue
                if planned.get("artifact") != row.artifact:
                    continue
                item = planned
            path = item.get("path")
            if not isinstance(path, str) or not path:
                continue
            targets[row.target] = Target(
                path=_cut_utf8(path, MAX_PATH_BYTES),
                artifact=DiskArtifact(item["artifact"]),
                file=_file_key(source.partition_index, item),
            )
    return targets


# --- one event ---------------------------------------------------------------------------------


def _printable(value: object, default: str) -> str:
    if not isinstance(value, str):
        return default
    cleaned = "".join(ch for ch in value[:256] if " " <= ch <= "~").strip()[:64]
    return cleaned or default


def timestamp_us(raw: Mapping[str, Any]) -> int | None:
    """Plaso's `timestamp` (µs since the epoch) when set and inside 1601..2200."""
    value = raw.get("timestamp")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    date_time = raw.get("date_time")
    if isinstance(date_time, dict) and date_time.get("__class_name__") == "NotSet":
        return None
    if not MIN_US <= value < MAX_US:
        return None
    return value


def _locations(raw: Mapping[str, Any]) -> Iterator[str]:
    filename = raw.get("filename")
    if isinstance(filename, str):
        yield filename
    display = raw.get("display_name")
    if isinstance(display, str):
        for _ in range(4):
            display, n = _TYPE_PREFIX.subn("", display, count=1)
            if not n:
                break
        yield display
    spec = raw.get("pathspec")
    for _ in range(MAX_PATH_DEPTH):
        if not isinstance(spec, dict):
            break
        location = spec.get("location")
        if isinstance(location, str):
            yield location
        spec = spec.get("parent")


def _relative(value: str, roots: Sequence[str]) -> str | None:
    if not value or len(value) > 8192:
        return None
    value = value.replace("\\", "/")
    for root in roots:
        prefix = root.replace("\\", "/").rstrip("/") + "/"
        if root and value.startswith(prefix):
            value = value[len(prefix) :]
            break
    rel = value.lstrip("/")
    parts = rel.split("/")
    if not rel or any(p in ("", ".", "..") for p in parts):
        return None
    return rel


@dataclass
class Counts:
    rows: int = 0  # JSON objects read (the `events_read` cap counts these)
    accepted: int = 0
    bad_lines: int = 0  # over-long or invalid lines (`read_jsonl`)
    dropped: Counter[str] = field(default_factory=Counter)
    truncated: bool = False


class _Normalizer:
    def __init__(self, source: Source) -> None:
        self.source = source
        self.targets = load_targets(source)

    def target(self, raw: Mapping[str, Any]) -> Target | None:
        roots = self.source.mirror_roots
        for location in _locations(raw):
            rel = _relative(location, roots)
            if rel is None:
                continue
            hit = self.targets.get(rel)
            if hit is not None:
                return hit
            if self.source.replay:
                entry = catalog.classify(rel, self.source.os, self.source.profile)
                if entry is not None:
                    return Target(path=_cut_utf8(rel, MAX_PATH_BYTES), artifact=entry.artifact)
        return None

    def record(
        self, raw: Mapping[str, Any], ordinal: int
    ) -> tuple[DiskEventRecord | None, int, str | None]:
        """(the record, its µs time, None) or (None, 0, the drop reason)."""
        container = raw.get("__container_type__")
        if container is not None and container != "event":
            return None, 0, "not_event"
        ts = timestamp_us(raw)
        if ts is None:
            return None, 0, "bad_timestamp"
        target = self.target(raw)
        if target is None:
            return None, 0, "unknown_path"
        data_type = _printable(raw.get("data_type"), "unknown")
        message = raw.get("message")
        text = message.replace("\x00", "")[:MAX_MESSAGE] if isinstance(message, str) else ""
        try:
            record = DiskEventRecord(
                ordinal=ordinal,
                ts=_EPOCH + timedelta(microseconds=ts),
                ts_desc=_printable(raw.get("timestamp_desc"), "Unknown Time"),
                artifact=target.artifact,
                parser=_printable(raw.get("parser"), "unknown"),
                data_type=data_type,
                partition_index=self.source.partition_index,
                path=target.path,
                file=target.file,
                message=text,
                attributes=attributes_of(data_type, raw),
            )
        except ValidationError:
            return None, 0, "invalid"
        return record, ts, None


def _is_fixture_comment(raw: Mapping[str, Any]) -> bool:
    return "__fixture__" in raw and "timestamp" not in raw


def scan(
    sources: Sequence[Source], max_rows: int, counts: Counts
) -> Iterator[tuple[DiskEventRecord, int]]:
    """Every accepted event of every source, in the deterministic ordinal order."""
    for source in sources:
        normalizer = _Normalizer(source)
        stats = ReadStats()
        left = max_rows - counts.rows
        if left <= 0:
            counts.truncated = True
            return
        try:
            f = _open_regular(source.events)
        except (OSError, ValueError):
            counts.dropped["source_unreadable"] += 1
            continue
        with f:
            for raw in read_jsonl(f, stats, max_rows=left, max_bytes=MAX_EVENTS_BYTES):
                counts.rows += 1
                if source.replay and _is_fixture_comment(raw):
                    continue
                record, ts, reason = normalizer.record(raw, counts.accepted)
                if record is None:
                    counts.dropped[reason or "invalid"] += 1
                    continue
                counts.accepted += 1
                yield record, ts
        counts.bad_lines += stats.bad
        if stats.truncated:
            counts.truncated = True
            if counts.rows >= max_rows:
                return


# --- the two passes ------------------------------------------------------------------------


@dataclass
class Selection:
    """Pass 2's stored set and the per-category counts for the header."""

    kept: frozenset[int]
    read: dict[DiskArtifact, int]
    stored: dict[DiskArtifact, int]
    counts: Counts
    records: Callable[[], Iterator[DiskEventRecord]]


class EventSource:
    """The two passes over one job's exported events (see the module docstring)."""

    def __init__(self, path: Path, limits: DiskLimits) -> None:
        self.path = path
        self.limits = limits
        self.sources = read_sources(path)
        self.counts = Counts()
        self._heaps: dict[DiskArtifact, list[tuple[int, int]]] = {}
        self._categories = array("B")
        self._complete = False

    def events(self) -> Iterator[DiskEventRecord]:
        """Pass 1: every normalized event (and the bounded per-category heaps)."""
        self.counts = Counts()
        self._heaps = {a: [] for a in DiskArtifact}
        self._categories = array("B")
        self._complete = False
        quotas = self.limits.event_quotas
        for record, ts in scan(self.sources, self.limits.max_events_read, self.counts):
            self._categories.append(_ARTIFACT_CODE[record.artifact])
            quota = quotas.get(record.artifact, 0)
            if quota > 0:
                heap = self._heaps[record.artifact]
                item = (ts, record.ordinal)
                if len(heap) < quota:
                    heapq.heappush(heap, item)
                else:
                    heapq.heappushpop(heap, item)
            yield record
        self._complete = True

    def select(self, cited: set[int]) -> Selection:
        """Pass 2: the stored subset (the quotas' most recent events plus every cited one)."""
        if not self._complete:
            for _ in self.events():
                pass
        total = len(self._categories)
        kept = {ordinal for heap in self._heaps.values() for _, ordinal in heap}
        kept.update(o for o in cited if 0 <= o < total)
        read = {a: n for i, a in enumerate(_ARTIFACTS) if (n := self._categories.count(i))}
        stored: Counter[DiskArtifact] = Counter(_ARTIFACTS[self._categories[o]] for o in kept)
        frozen = frozenset(kept)
        sources, max_rows = self.sources, self.limits.max_events_read

        def records() -> Iterator[DiskEventRecord]:
            if not frozen:
                return
            last = max(frozen)
            for record, _ in scan(sources, max_rows, Counts()):
                if record.ordinal in frozen:
                    yield record
                if record.ordinal >= last:
                    return

        return Selection(
            kept=frozen,
            read=read,
            stored=dict(stored),
            counts=self.counts,
            records=records,
        )


def iter_events(path: Path, limits: DiskLimits) -> Iterator[DiskEventRecord]:
    """Pass 1 alone (every event)."""
    return EventSource(path, limits).events()


def select_events(path: Path, limits: DiskLimits, cited: set[int]) -> Iterator[DiskEventRecord]:
    """Pass 2 alone (it reads the events once more to build the quotas first)."""
    return EventSource(path, limits).select(cited).records()


__all__ = [
    "FIELD_MAPS",
    "Counts",
    "EventSource",
    "Selection",
    "Source",
    "Target",
    "attributes_of",
    "iter_events",
    "load_targets",
    "read_sources",
    "select_events",
    "timestamp_us",
    "write_sources",
]
