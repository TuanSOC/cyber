"""Imports into the hash-set store (the trusted `disk-hashsets` tool; M9 phase 5).

Two sources, both supplied by the operator in the read-only import dir (nothing is ever
downloaded; the service runs with `network_mode: none`):

- **NSRL RDSv3 SQLite** (`import-nsrl`). Schema per NIST's RDSv3 documentation (`NSRL_DOCS`;
  each release also ships `RDS_<ver>_<set>.schema.sql`): the `FILE` view has the columns
  `sha256, sha1, md5, crc32, file_name, file_size, package_id`; the minimal set adds the
  `DISTINCT_HASH` view (`sha256, sha1, md5`: the distinct hash values), used when present.
  Hashes are hex text (upper case in NIST's files). Any other layout is refused.
  The database is opened read-only and immutable (`file:...?mode=ro&immutable=1`), with
  `trusted_schema=OFF`, `query_only`, no extensions and an authorizer allowing reads only.
- **Plain hash lists** (`import-list`): one digest per line, an optional md5sum-style suffix
  (`<digest>  name` / `<digest> *name`), `#` comments and blank lines ignored.

Every digest is checked as hex of the exact length (others are counted and skipped). The parse
and the external sort run in a forked child (`RLIMIT_AS` 2 GiB, a 4 h timeout, the kit's
seccomp network filter) **without a uid change**: the tool already runs as uid 10008 with no
capabilities, so `sandbox.run_tool` (which switches to the analyzer tool uid) is not used
(RT25). The parent then re-reads every output file (count, strict order, sha256), moves the set
directory into place with one rename and only then lists it in the manifest, so an interrupted
import never leaves a matched partial set.
"""

import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import stat
import time
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Literal
from urllib.parse import quote

from cyberlab_jobs.disk import HashSet, HashSetFile, HashSetManifestV1

from disk_worker.hashsets import manifest as mf
from disk_worker.hashsets.extsort import DEFAULT_CHUNK_RECORDS, ExternalSorter

TOOL_VERSION = "disk-hashsets/1.0.0"
NSRL_DOCS = (
    "https://www.nist.gov/itl/ssd/software-quality-group/"
    "national-software-reference-library-nsrl/nsrl-download/current-rds",
    "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/RDSv3_Docs/RDSv3_FAQs.pdf",
)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
RESERVED_NAMES = frozenset({mf.MANIFEST_NAME})
NSRL_FILE_VIEW = "FILE"
NSRL_DISTINCT_VIEW = "DISTINCT_HASH"
NSRL_FILE_COLUMNS = frozenset({"sha256", "sha1", "md5", "file_name", "file_size", "package_id"})
MAX_SETS = 64  # HashSetManifestV1.sets
CHILD_RLIMIT_AS = 2 * 1024**3
CHILD_TIMEOUT_S = 4 * 3600
MAX_LINE_BYTES = 4096
MAX_SCHEMA_ROWS = 10_000
HEX = frozenset("0123456789abcdef")

Kind = Literal["known_good", "known_bad", "notable"]
Algo = Literal["sha256", "sha1", "md5"]


class ImportRefused(Exception):
    """The import cannot go ahead; nothing was installed. `code` is a short machine word."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass
class ImportStats:
    rows: int = 0
    invalid: int = 0  # not hex of the exact length (skipped)
    missing: int = 0  # NULL / empty column values
    counts: dict[str, int] = field(default_factory=dict)  # distinct digests per algorithm


# --- input safety ----------------------------------------------------------------------------


def check_name(name: str) -> str:
    if not NAME_RE.fullmatch(name) or name in RESERVED_NAMES:
        raise ImportRefused("bad_name", "names match ^[a-z0-9][a-z0-9._-]{0,63}$")
    return name


def resolve_import(import_dir: Path, arg: str) -> Path:
    """`--file` is `/import/<f>` (the mount point as the operator sees it), `<import dir>/<f>`
    or `<f>`: exactly one path component under the import dir."""
    leaf = arg
    for prefix in (import_dir.as_posix().rstrip("/") + "/", "/import/"):
        if arg.startswith(prefix):
            leaf = arg[len(prefix) :]
            break
    if (
        not leaf
        or leaf in (".", "..")
        or "/" in leaf
        or "\\" in leaf
        or "\x00" in leaf
        or len(leaf.encode("utf-8", "surrogateescape")) > 255
    ):
        raise ImportRefused("bad_import_path", "--file is a single file name under the import dir")
    return import_dir / leaf


def open_import(path: Path) -> int:
    """A read-only fd on a regular, non-symlink file (lstat, then `O_NOFOLLOW`, then the same
    inode re-checked through fstat)."""
    try:
        before = os.lstat(path)
    except FileNotFoundError as exc:
        raise ImportRefused("import_not_found", path.name) from exc
    if stat.S_ISLNK(before.st_mode):
        raise ImportRefused("import_symlink", path.name)
    if not stat.S_ISREG(before.st_mode):
        raise ImportRefused("import_not_regular", path.name)
    try:
        fd = os.open(path, mf.READ_FLAGS)
    except OSError as exc:  # ELOOP: swapped for a symlink in between
        raise ImportRefused("import_open_failed", exc.strerror or "") from exc
    after = os.fstat(fd)
    if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (
        before.st_dev,
        before.st_ino,
    ):
        os.close(fd)
        raise ImportRefused("import_changed", path.name)
    return fd


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024**2):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def fd_path(fd: int, path: Path) -> str:
    """The opened file itself where /proc exists (no second path lookup), else the path."""
    proc = f"/proc/self/fd/{fd}"
    return proc if os.path.exists(proc) else str(path)


# --- digests ---------------------------------------------------------------------------------


def parse_digest(value: object, algo: str) -> bytes | None:
    """Raw digest bytes of a hex string of the exact length, else None."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if len(text) != 2 * mf.WIDTH[algo] or not HEX.issuperset(text):
        return None
    return bytes.fromhex(text)


# --- sources ---------------------------------------------------------------------------------

# Reads only (no PRAGMA, ATTACH, writes or DDL once the connection is set up). Functions stay
# allowed for views that use them; `trusted_schema=OFF` already limits a view to innocuous ones.
_READ_ACTIONS = frozenset({sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION})


def _authorizer(
    action: int, arg1: str | None, arg2: str | None, db: str | None, src: str | None
) -> int:
    return sqlite3.SQLITE_OK if action in _READ_ACTIONS else sqlite3.SQLITE_DENY


def open_nsrl(fd: int, path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(fd_path(fd, path))}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=True)
    except sqlite3.Error as exc:
        raise ImportRefused("nsrl_open_failed", str(exc)[:200]) from exc
    try:
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA query_only=ON")
        if hasattr(conn, "enable_load_extension"):
            conn.enable_load_extension(False)
        if hasattr(conn, "setlimit"):
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024**2)
            conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        conn.set_authorizer(_authorizer)
    except sqlite3.Error as exc:
        conn.close()
        raise ImportRefused("nsrl_open_failed", str(exc)[:200]) from exc
    return conn


def _columns(conn: sqlite3.Connection, view: str) -> set[str]:
    cursor = conn.execute(f'SELECT * FROM "{view}" LIMIT 0')  # noqa: S608 - fixed names
    return {str(d[0]).lower() for d in cursor.description or ()}


def nsrl_layout(conn: sqlite3.Connection) -> tuple[str, list[str]]:
    """(view, algorithms) to read, or `ImportRefused("nsrl_schema")` for an unknown layout."""
    try:
        rows = conn.execute("SELECT type, name FROM sqlite_master").fetchmany(MAX_SCHEMA_ROWS)
        objects = {str(name).upper(): str(kind) for kind, name in rows}
        if objects.get(NSRL_FILE_VIEW) not in ("table", "view"):
            raise ImportRefused("nsrl_schema", "no FILE view (not an RDSv3 database)")
        missing = NSRL_FILE_COLUMNS - _columns(conn, NSRL_FILE_VIEW)
        if missing:
            raise ImportRefused("nsrl_schema", f"FILE lacks {', '.join(sorted(missing))}")
        if objects.get(NSRL_DISTINCT_VIEW) in ("table", "view"):
            columns = _columns(conn, NSRL_DISTINCT_VIEW)
            if "sha256" not in columns:
                raise ImportRefused("nsrl_schema", "DISTINCT_HASH lacks sha256")
            algos = [a for a in mf.ALGO_ORDER if a in columns]
            return NSRL_DISTINCT_VIEW, algos
    except sqlite3.Error as exc:
        raise ImportRefused("nsrl_schema", str(exc)[:200]) from exc
    return NSRL_FILE_VIEW, list(mf.ALGO_ORDER)


def nsrl_rows(
    conn: sqlite3.Connection, view: str, algos: Sequence[str]
) -> Iterator[tuple[Any, ...]]:
    columns = ", ".join(algos)  # fixed names from nsrl_layout
    cursor = conn.execute(f'SELECT {columns} FROM "{view}"')  # noqa: S608
    while batch := cursor.fetchmany(10_000):
        yield from batch


def list_rows(f: BinaryIO) -> Iterator[tuple[str | None]]:
    """The first token of every non-comment line (lines longer than 4 KiB yield an invalid
    marker so they are counted, never buffered whole)."""
    while True:
        line = f.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
            while (rest := f.readline(MAX_LINE_BYTES)) and not rest.endswith(b"\n"):
                pass
            yield ("<overlong>",)
            continue
        text = line.decode("utf-8", "replace").strip()
        if not text or text.startswith("#"):
            continue
        yield (text.split()[0],)


# --- build (child) ---------------------------------------------------------------------------


def build(
    out_dir: Path,
    tmp_dir: Path,
    algos: Sequence[str],
    rows: Iterator[tuple[Any, ...]],
    chunk_records: int = DEFAULT_CHUNK_RECORDS,
) -> ImportStats:
    """Validate, external-sort and write `<out_dir>/<algo>.bin` for every algorithm with at
    least one digest."""
    stats = ImportStats()
    per_algo = max(1, chunk_records // max(1, len(algos)))
    sorters = {a: ExternalSorter(mf.WIDTH[a], tmp_dir, per_algo) for a in algos}
    try:
        for row in rows:
            stats.rows += 1
            for algo, value in zip(algos, row, strict=True):
                if value is None or value == "":
                    stats.missing += 1
                    continue
                digest = parse_digest(value, algo)
                if digest is None:
                    stats.invalid += 1
                    continue
                sorters[algo].add(digest)
        for algo, sorter in sorters.items():
            if not sorter.added:
                continue
            count = 0
            with open(out_dir / f"{algo}.bin", "xb") as f:
                batch: list[bytes] = []
                for record in sorter.finish():
                    batch.append(record)
                    count += 1
                    if len(batch) >= 8192:
                        f.write(b"".join(batch))
                        batch.clear()
                f.write(b"".join(batch))
                f.flush()
                os.fsync(f.fileno())
            stats.counts[algo] = count
    finally:
        for sorter in sorters.values():
            sorter.discard()
    return stats


def check_file(path: Path, width: int) -> tuple[int, str]:
    """(count, sha256) of a store file, refusing a partial record or a non-ascending step."""
    digest = hashlib.sha256()
    count = 0
    previous = b""
    try:
        fd = os.open(path, mf.READ_FLAGS)
    except OSError as exc:  # ELOOP: a symlink
        raise ImportRefused("store_open_failed", f"{path.name}: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ImportRefused("store_not_regular", path.name)
        while block := f.read(width * 8192):
            if len(block) % width:
                raise ImportRefused("store_partial_record", path.name)
            digest.update(block)
            for i in range(0, len(block), width):
                record = block[i : i + width]
                if record <= previous and count:
                    raise ImportRefused("store_not_sorted", path.name)
                previous = record
                count += 1
    return count, digest.hexdigest()


# --- isolation -------------------------------------------------------------------------------


def _run_isolated(job: Any, result_path: Path, timeout_s: int) -> ImportStats:
    """Run `job()` (returning ImportStats) in a forked child with RLIMIT_AS, no core dumps and
    the kit's seccomp network filter; no uid change (RT25). Raises ImportRefused on failure."""
    import resource

    from cyberlab_worker import seccomp  # loads libseccomp in the parent, before the fork

    pid = os.fork()
    if pid == 0:  # child
        code = 3
        try:
            resource.setrlimit(resource.RLIMIT_AS, (CHILD_RLIMIT_AS, CHILD_RLIMIT_AS))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            seccomp.deny_network(deny_io_uring=True)
            stats = job()
            result_path.write_text(json.dumps({"ok": True, "stats": asdict(stats)}))
            code = 0
        except ImportRefused as exc:
            with contextlib.suppress(Exception):
                result_path.write_text(
                    json.dumps({"ok": False, "code": exc.code, "detail": exc.detail[:200]})
                )
            code = 1
        except BaseException:  # noqa: BLE001 - the child never returns into the parent's stack
            code = 3
        finally:
            os._exit(code)
    deadline = time.monotonic() + timeout_s
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise ImportRefused("import_timeout", f"over {timeout_s} s")
        time.sleep(0.2)
    try:
        result = json.loads(result_path.read_text()[:4096])
    except (OSError, ValueError):
        result = {}
    if os.waitstatus_to_exitcode(status) == 0 and result.get("ok"):
        raw = result.get("stats") if isinstance(result.get("stats"), dict) else {}
        counts = {k: raw[k] for k in ("rows", "invalid", "missing") if isinstance(raw.get(k), int)}
        return ImportStats(**counts)
    if result.get("ok") is False:
        code = str(result.get("code", "import_failed"))[:64]
        raise ImportRefused(code, str(result.get("detail", "")))
    raise ImportRefused("import_failed", f"child exit status {os.waitstatus_to_exitcode(status)}")


# --- store operations ------------------------------------------------------------------------


@contextlib.contextmanager
def store_lock(root: Path) -> Iterator[None]:
    """One writer at a time (flock on `<root>/.lock` where available)."""
    try:
        import fcntl
    except ImportError:  # Windows host tests
        yield
        return
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(root / ".lock", flags, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ImportRefused("store_busy", "another disk-hashsets command is running") from exc
        yield
    finally:
        os.close(fd)


def _load_for_write(root: Path) -> HashSetManifestV1:
    try:
        return mf.load(root)
    except mf.ManifestInvalid as exc:
        raise ImportRefused("manifest_invalid", str(exc)) from exc


def _clean_staging(root: Path) -> None:
    shutil.rmtree(root / mf.STAGING_DIR, ignore_errors=True)


def import_set(
    root: Path,
    import_dir: Path,
    file_arg: str,
    name: str,
    kind: Kind,
    source: Literal["nsrl", "list"],
    algo: Algo | None = None,
    *,
    isolate: bool = True,
    chunk_records: int = DEFAULT_CHUNK_RECORDS,
    timeout_s: int = CHILD_TIMEOUT_S,
    now: datetime | None = None,
) -> tuple[HashSet, ImportStats]:
    """Import one set and list it in the manifest. Raises ImportRefused (nothing installed)."""
    check_name(name)
    if source == "list" and algo is None:
        raise ImportRefused("bad_algo", "--algo is required for a list")
    path = resolve_import(import_dir, file_arg)
    with store_lock(root):
        sets = _load_for_write(root).sets
        if any(s.name == name for s in sets):
            raise ImportRefused("set_exists", f"{name} (remove it first)")
        if len(sets) >= MAX_SETS:
            raise ImportRefused("store_full", f"at most {MAX_SETS} sets")
        _clean_staging(root)  # leftovers of an interrupted import
        fd = open_import(path)
        staging = root / mf.STAGING_DIR / secrets.token_hex(8)
        out_dir, tmp_dir = staging / "set", staging / "tmp"
        try:
            out_dir.mkdir(parents=True, mode=0o755)
            tmp_dir.mkdir(mode=0o700)
            source_sha256 = sha256_fd(fd)
            if source == "nsrl":

                def job() -> ImportStats:
                    # Every SQLite call (schema check included) happens in the child.
                    conn = open_nsrl(fd, path)
                    try:
                        view, algos = nsrl_layout(conn)
                        rows = nsrl_rows(conn, view, algos)
                        return build(out_dir, tmp_dir, algos, rows, chunk_records)
                    except sqlite3.Error as exc:
                        raise ImportRefused("nsrl_read_failed", str(exc)[:200]) from exc
                    finally:
                        conn.close()

            else:
                list_algos: list[str] = [str(algo)]

                def job() -> ImportStats:
                    with os.fdopen(os.dup(fd), "rb") as reader:
                        return build(out_dir, tmp_dir, list_algos, list_rows(reader), chunk_records)

            if isolate:
                stats = _run_isolated(job, staging / "result.json", timeout_s)
            else:
                stats = job()
            expected = {f"{a}.bin" for a in mf.ALGO_ORDER}
            if any(p.name not in expected for p in out_dir.iterdir()):
                raise ImportRefused("import_unexpected_output", "the child wrote other files")
            files = []
            for a in mf.ALGO_ORDER:
                out = out_dir / f"{a}.bin"
                if not out.exists():
                    continue
                count, digest = check_file(out, mf.WIDTH[a])
                files.append(
                    HashSetFile(
                        algo=a,
                        path=mf.file_path(name, a),
                        sha256=digest,
                        count=count,
                    )
                )
            if not files:
                raise ImportRefused("empty_set", "no valid digest in the import file")
            hash_set = HashSet(
                name=name,
                kind=kind,
                algorithms=[f.algo for f in files],
                files=files,
                source_sha256=source_sha256,
                imported_at=now or datetime.now(UTC),
                tool_version=TOOL_VERSION,
            )
            shutil.rmtree(tmp_dir, ignore_errors=True)
            target = root / name
            if target.exists() or target.is_symlink():  # an orphan of an interrupted import
                _remove_path(target)
            os.rename(out_dir, target)
            mf.fsync_dir(root)
            current = _load_for_write(root)
            mf.write(root, HashSetManifestV1(sets=[*current.sets, hash_set]))
        finally:
            os.close(fd)
            _clean_staging(root)
    stats.counts = {f.algo: f.count for f in files}
    return hash_set, stats


def _remove_path(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def remove_set(root: Path, name: str) -> None:
    """Manifest first (the set stops matching), then its files."""
    check_name(name)
    with store_lock(root):
        current = _load_for_write(root)
        if not any(s.name == name for s in current.sets):
            raise ImportRefused("unknown_set", name)
        mf.write(root, HashSetManifestV1(sets=[s for s in current.sets if s.name != name]))
        target = root / name
        if target.exists() or target.is_symlink():
            _remove_path(target)


def verify_store(root: Path) -> list[str]:
    """Re-hash every listed file against the manifest; the problems found (empty: all good)."""
    try:
        manifest = mf.load(root)
    except mf.ManifestInvalid as exc:
        return [f"manifest: {exc}"]
    problems = []
    for s in manifest.sets:
        for f in s.files:
            try:
                count, digest = check_file(root / f.path, mf.WIDTH[f.algo])
            except ImportRefused as exc:
                problems.append(f"{f.path}: {exc.code}")
                continue
            except OSError as exc:
                problems.append(f"{f.path}: {exc.strerror}")
                continue
            if digest != f.sha256:
                problems.append(f"{f.path}: sha256 mismatch")
            if count != f.count:
                problems.append(f"{f.path}: {count} records, manifest says {f.count}")
    return problems
