"""Symbol store layout, manifest I/O and the write transaction (M8 phase 5).

Layout (`SymbolManifestV1`, frozen in phase 1):

    windows/<pdb>/<GUID>-<AGE>.json.xz      Volatility's own lookup path (AGE in decimal)
    linux/<sha256(banner)>.json.xz          found through the manifest / identifier cache
    manifest.json                           written only by the `memory-symbols` tool
    changes.jsonl                           append-only record of every manifest change
    .cache/volatility3/identifier.cache     prebuilt by `reindex` (file:///symbols/... URLs)

Files are 0444 and directories 0555 (owned by the tool's uid 10005; the worker mounts the
volume read-only). Only `StoreWriter` writes, and only through a staging dir inside the store
(same filesystem) followed by a verified, atomic move.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import shutil
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from cyberlab_jobs.memory import (
    KernelIdentity,
    SymbolFile,
    SymbolManifestV1,
    WindowsPdb,
    identity_os,
)

TOOL_VERSION = "memory-symbols/0.1.0"
MANIFEST = "manifest.json"
CHANGES = "changes.jsonl"
CACHE_DIR = ".cache/volatility3"
CACHE_FILE = f"{CACHE_DIR}/identifier.cache"
STAGING = ".staging"
LOCK = ".lock"
OS_DIRS = ("windows", "linux")
MAX_MANIFEST_BYTES = 128 * 1024**2
FILE_MODE = 0o444
DIR_MODE = 0o555
OPEN_DIR_MODE = 0o755
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)

Logger = Callable[..., None]


class ManifestInvalid(ValueError):
    pass


class StoreError(RuntimeError):
    """A store write was refused (conflict, unsafe path, failed verification)."""


def banner_key(banner: str) -> str:
    return hashlib.sha256(banner.encode("ascii")).hexdigest()


def isf_relpath(identity: KernelIdentity) -> str:
    """The store path of an identity, built from validated fields only."""
    if isinstance(identity, WindowsPdb):
        return f"windows/{identity.name}/{identity.guid}-{identity.age}.json.xz"
    return f"linux/{banner_key(identity.banner)}.json.xz"


def identity_label(identity: KernelIdentity) -> dict[str, Any]:
    """Identity for a log line or `list` (JSON-encoded by the caller: a banner is inert text,
    never part of a suggested command, RT12)."""
    return identity.model_dump()


def sha256_file(path: Path) -> str:
    """Hash a regular file, refusing symlinks."""
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise StoreError(f"{path.name} is not a regular file")
        digest = hashlib.sha256()
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_manifest(root: Path) -> SymbolManifestV1:
    path = root / MANIFEST
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    except OSError as exc:
        raise ManifestInvalid(f"cannot open {MANIFEST} ({exc.strerror})") from exc
    with os.fdopen(fd, "rb") as fh:
        info = os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise ManifestInvalid(f"{MANIFEST} is not a regular file of at most 128 MiB")
        data = fh.read(MAX_MANIFEST_BYTES + 1)
    try:
        return SymbolManifestV1.model_validate_json(data)
    except ValueError as exc:
        raise ManifestInvalid(f"{MANIFEST} does not validate") from exc


def volatility_version() -> str:
    from importlib import metadata

    try:
        return metadata.version("volatility3")
    except metadata.PackageNotFoundError:
        return "not-installed"


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _chmod(path: Path, mode: int) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, mode, follow_symlinks=False)


def _chmod_dir(path: Path, mode: int) -> None:
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, mode)


def seal(root: Path) -> None:
    """Directories 0555, files 0444 (the store layout; owner = the tool's uid)."""
    for top in (*OS_DIRS, ".cache"):
        base = root / top
        if not base.is_dir() or base.is_symlink():
            continue
        for dirpath, dirnames, filenames in os.walk(base, topdown=False):
            for name in filenames:
                _chmod(Path(dirpath) / name, FILE_MODE)
            for name in dirnames:
                _chmod_dir(Path(dirpath) / name, DIR_MODE)
        _chmod_dir(base, DIR_MODE)
    for name in (MANIFEST, CHANGES):
        if (root / name).is_file():
            _chmod(root / name, FILE_MODE)
    _chmod_dir(root, DIR_MODE)


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _replace(src: Path, dst: Path) -> None:
    if dst.exists():  # Windows (host test runs) cannot replace a read-only file
        _chmod(dst, 0o644)
    os.replace(src, dst)


@dataclass
class Change:
    action: str  # added | replaced | repaired | unchanged
    path: str
    identity: dict[str, Any]
    sha256: str
    source: str
    old_sha256: str | None = None

    def record(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def no_log(*_: object, **__: object) -> None:
    return None


@dataclass
class StoreWriter:
    """One locked write session: `with StoreWriter(root) as w: ...; w.commit()`.

    Uncommitted changes are rolled back (new files removed, replaced files are not touched
    before commit since replacement happens at commit time). The staging dir is always removed.
    """

    root: Path
    log: Logger = no_log
    changes: list[Change] = field(default_factory=list)
    _files: dict[str, SymbolFile] = field(default_factory=dict)
    _staging: Path | None = None
    _lock_fd: int | None = None
    _pending: list[tuple[Path, Path, bool]] = field(default_factory=list)

    def __enter__(self) -> StoreWriter:
        self.root = Path(os.path.abspath(self.root))
        if self.root.is_symlink() or not self.root.is_dir():
            raise StoreError("the symbol store root is not a directory")
        _chmod_dir(self.root, OPEN_DIR_MODE)
        self._lock()
        if (self.root / MANIFEST).exists():
            manifest = read_manifest(self.root)
            self._files = {f.path: f for f in manifest.files}
        staging = self.root / STAGING
        if staging.exists():  # a crashed earlier run (we hold the lock): never reuse it
            shutil.rmtree(staging, onexc=_force_remove)
        staging.mkdir(mode=0o700)
        self._staging = staging / secrets.token_hex(8)
        self._staging.mkdir(mode=0o700)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            for staged, _final, _replace_it in self._pending:
                staged.unlink(missing_ok=True)
            shutil.rmtree(self.root / STAGING, onexc=_force_remove)
            seal(self.root)
        finally:
            self._unlock()

    # -- locking (POSIX advisory lock; host test runs on Windows skip it) --------------------

    def _lock(self) -> None:
        try:
            import fcntl
        except ImportError:
            return
        fd = os.open(self.root / LOCK, os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise StoreError("another memory-symbols run holds the store lock") from exc
        self._lock_fd = fd

    def _unlock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    # -- API -----------------------------------------------------------------------------------

    @property
    def staging(self) -> Path:
        if self._staging is None:
            raise StoreError("the writer is not open")
        return self._staging

    def work_dir(self, name: str) -> Path:
        path = self.staging / name
        path.mkdir(mode=0o700)
        return path

    @property
    def files(self) -> dict[str, SymbolFile]:
        return dict(self._files)

    def stage(
        self,
        staged: Path,
        identity: KernelIdentity,
        sha256: str,
        source: str,
        *,
        replace: bool = False,
    ) -> Change:
        """Register a produced file (inside this session's staging dir) for `identity`.
        It is re-hashed now (the child's report is not trusted) and moved at `commit`."""
        staged = Path(os.path.abspath(staged))
        if staged.parent.parent != self.staging and staged.parent != self.staging:
            raise StoreError("a staged file must come from this session's staging dir")
        actual = sha256_file(staged)
        if actual != sha256:
            raise StoreError("a produced file changed after the child hashed it")
        rel = isf_relpath(identity)
        final = self.root / rel
        label = identity_label(identity)
        existing = self._files.get(rel)
        pending = {final for _s, final, _r in self._pending}
        if final in pending:
            raise StoreError(f"two inputs produce the same identity ({rel})")
        on_disk = os.path.lexists(final)
        if existing is not None and existing.sha256 == actual:
            if on_disk and not final.is_symlink() and final.is_file():
                if sha256_file(final) == actual:
                    staged.unlink()
                    change = Change("unchanged", rel, label, actual, existing.source)
                    self.changes.append(change)
                    return change
            # The manifest already names this content but the disk differs: restore it.
            self._pending.append((staged, final, on_disk))
            change = Change("repaired", rel, label, actual, existing.source)
            self.changes.append(change)
            return change
        if (existing is not None or on_disk) and not replace:
            what = "a different file" if existing is not None else "an unlisted file"
            raise StoreError(f"{rel}: the store already holds {what} for this identity")
        self._pending.append((staged, final, existing is not None or on_disk))
        self._files[rel] = SymbolFile(
            path=rel,
            sha256=actual,
            os=identity_os(identity),
            identity=identity,
            source=source,
            imported_at=now(),
            tool_version=TOOL_VERSION,
        )
        old = existing.sha256 if existing is not None else None
        change = Change("replaced" if old or on_disk else "added", rel, label, actual, source, old)
        self.changes.append(change)
        return change

    def commit(self) -> list[Change]:
        """Move every staged file into place (O_EXCL placeholder, then rename; a replacement
        renames over the old file), then write the manifest atomically and log the changes."""
        manifest = SymbolManifestV1(
            volatility_version=volatility_version(),
            files=sorted(self._files.values(), key=lambda f: f.path),
        )
        placed: list[Path] = []
        try:
            for staged, final, replace_it in self._pending:
                self._ensure_dirs(final.parent)
                _chmod(staged, FILE_MODE)
                if replace_it:
                    if final.is_symlink() or (final.exists() and not final.is_file()):
                        raise StoreError(f"{final.name}: not a regular file in the store")
                    _replace(staged, final)
                else:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY
                    os.close(os.open(final, flags, 0o644))  # refuses an existing name
                    placed.append(final)
                    _replace(staged, final)
            self._write_manifest(manifest)
        except BaseException:
            for path in placed:  # roll back new files; the old manifest stays in force
                _chmod(path, 0o644)
                path.unlink(missing_ok=True)
            raise
        self._pending.clear()
        recorded = [c for c in self.changes if c.action != "unchanged"]
        if recorded:
            self._append_changes(recorded)
        for change in self.changes:
            self.log("manifest_change", **change.record())
        return list(self.changes)

    def install_cache(self, built: Path) -> None:
        cache_dir = self.root / CACHE_DIR
        self._ensure_dirs(cache_dir)
        _chmod(built, FILE_MODE)
        _replace(built, self.root / CACHE_FILE)

    def _ensure_dirs(self, directory: Path) -> None:
        rel = directory.relative_to(self.root)
        current = self.root
        for part in rel.parts:
            current = current / part
            if current.is_symlink():
                raise StoreError(f"{part}: a symlink in the store")
            if not current.exists():
                current.mkdir(mode=OPEN_DIR_MODE)
            _chmod_dir(current, OPEN_DIR_MODE)

    def _write_manifest(self, manifest: SymbolManifestV1) -> None:
        data = (json.dumps(manifest.model_dump(mode="json"), indent=1) + "\n").encode()
        if len(data) > MAX_MANIFEST_BYTES:
            raise StoreError("the manifest would exceed 128 MiB")
        tmp = self.staging / f"manifest-{secrets.token_hex(4)}.json"
        _write_new(tmp, data)
        _chmod(tmp, FILE_MODE)
        _replace(tmp, self.root / MANIFEST)

    def _append_changes(self, changes: list[Change]) -> None:
        path = self.root / CHANGES
        if path.is_symlink():
            raise StoreError(f"{CHANGES} is a symlink")
        _chmod(path, 0o644)
        at = now()
        lines = "".join(
            json.dumps({"at": at, "tool_version": TOOL_VERSION, **c.record()}) + "\n"
            for c in changes
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | _NOFOLLOW | _BINARY, 0o644)
        with os.fdopen(fd, "ab") as fh:
            fh.write(lines.encode())
            fh.flush()
            os.fsync(fh.fileno())


def _force_remove(func: Callable[..., Any], path: str, _exc: BaseException) -> None:
    """rmtree onexc: our own read-only staging files (0444) on hosts that care."""
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)
        func(path)


def iter_store_files(root: Path) -> Iterator[str]:
    """Every file under `windows/` and `linux/` as a manifest-style relative path."""
    for top in OS_DIRS:
        base = root / top
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                yield (Path(dirpath) / name).relative_to(root).as_posix()
            for name in list(dirnames):
                if (Path(dirpath) / name).is_symlink():
                    yield (Path(dirpath) / name).relative_to(root).as_posix()


__all__ = [
    "CACHE_FILE",
    "Change",
    "ManifestInvalid",
    "StoreError",
    "StoreWriter",
    "TOOL_VERSION",
    "banner_key",
    "identity_label",
    "isf_relpath",
    "iter_store_files",
    "read_manifest",
    "seal",
    "sha256_file",
]
