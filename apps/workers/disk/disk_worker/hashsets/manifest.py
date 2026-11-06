"""The hash-set store manifest (`<root>/manifest.json`, `HashSetManifestV1`; M9 phase 5).

Layout: `<root>/<name>/{sha256,sha1,md5}.bin` (sorted, unique, fixed-width raw digests, no
header) and `<root>/manifest.json`, which is the only truth: a directory the manifest does not
list is an interrupted import (never matched, removed by the next import of that name).
The manifest is written atomically (temp file in the root, fsync, rename, fsync of the root).
"""

import contextlib
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

from cyberlab_jobs.disk import HashSet, HashSetManifestV1, HashSetRef
from pydantic import ValidationError

MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 1024**2
WIDTH: dict[str, int] = {"sha256": 32, "sha1": 20, "md5": 16}
ALGO_ORDER: tuple[str, ...] = ("sha256", "sha1", "md5")
# Matching precedence (first hit wins): a known-bad listing outranks a reference listing.
KIND_ORDER: tuple[str, ...] = ("known_bad", "notable", "known_good")
STAGING_DIR = ".staging"

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)  # Windows host tests only
READ_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY


class ManifestInvalid(ValueError):
    """The manifest cannot be read, does not validate, or lists a path outside its layout."""


def file_path(name: str, algo: str) -> str:
    return f"{name}/{algo}.bin"


def check_layout(manifest: HashSetManifestV1) -> None:
    """Every listed file sits at `<name>/<algo>.bin` (never another set's or a parent path)."""
    for s in manifest.sets:
        for f in s.files:
            if f.path != file_path(s.name, f.algo):
                raise ManifestInvalid(f"set {s.name}: unexpected file path {f.path!r}")


def load(root: Path) -> HashSetManifestV1:
    """The store's manifest; a missing manifest is an empty store. Raises `ManifestInvalid`."""
    try:
        fd = os.open(root / MANIFEST_NAME, READ_FLAGS)
    except FileNotFoundError:
        return HashSetManifestV1()
    except OSError as exc:  # ELOOP (a symlink), EACCES, ...
        raise ManifestInvalid(f"cannot open the manifest: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ManifestInvalid("the manifest is not a regular file")
        data = f.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestInvalid("the manifest exceeds 1 MiB")
    try:
        manifest = HashSetManifestV1.model_validate_json(data)
    except ValidationError as exc:
        errors = exc.error_count()
        raise ManifestInvalid(f"the manifest does not validate ({errors} errors)") from exc
    check_layout(manifest)
    return manifest


def dump(manifest: HashSetManifestV1) -> bytes:
    body = json.dumps(manifest.model_dump(mode="json"), sort_keys=True, indent=2)
    return body.encode() + b"\n"


def fsync_dir(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(root: Path, manifest: HashSetManifestV1) -> None:
    """Replace `<root>/manifest.json` atomically."""
    check_layout(manifest)
    data = dump(manifest)
    tmp = root / f".manifest.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY
    fd = os.open(tmp, flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, root / MANIFEST_NAME)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    fsync_dir(root)


def set_digest(hash_set: HashSet) -> str:
    """`HashSetRef.manifest_sha256`: sha256 of the set's canonical manifest entry (its file
    sha256s, counts, source sha256, import time and tool version), so a header pins exactly
    the set contents a job matched against."""
    body = json.dumps(hash_set.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def set_count(hash_set: HashSet) -> int:
    return max(f.count for f in hash_set.files)


def refs(manifest: HashSetManifestV1) -> list[HashSetRef]:
    """What the result header records for every set (name, kind, count, entry digest)."""
    return [
        HashSetRef(name=s.name, kind=s.kind, count=set_count(s), manifest_sha256=set_digest(s))
        for s in manifest.sets
    ]
