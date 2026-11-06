"""The read-only symbol store as the worker sees it (M8 phase 5; signatures frozen in phase 1).

`SymbolStore(root).lookup(identity) -> SymbolHit | None`: resolve a `WindowsPdb` by path
(`windows/<pdb>/<GUID>-<AGE>.json.xz`) and a `LinuxBanner` through the manifest's banner index,
verify the file's sha256 against the manifest (a tampered store raises `SymbolsCorrupt`, job
code `symbols_corrupt`) and return its path and sha256 for the result header.
`SymbolStore(root).manifest() -> SymbolManifestV1` reads and validates `manifest.json`.

The store is never written here and never fetched into: a missing identity is `None` (the
worker then emits the `symbols_missing` diagnostic). Banner normalization for the probe:
`normalize_banner` (trailing NUL / newline stripped, printable ASCII, <= 512 chars).
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cyberlab_jobs.memory import KernelIdentity, SymbolFile, SymbolManifestV1

from memory_worker.symbols.isolate import normalize_banner
from memory_worker.symbols.manifest import (
    ManifestInvalid,
    StoreError,
    isf_relpath,
    read_manifest,
    sha256_file,
)


class SymbolsCorrupt(Exception):
    """A store file does not match its manifest entry (or the manifest is invalid)."""


@dataclass(frozen=True)
class SymbolHit:
    path: Path  # absolute, inside the store root
    sha256: str
    identity: KernelIdentity


class SymbolStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._manifest: SymbolManifestV1 | None = None
        self._index: dict[KernelIdentity, SymbolFile] | None = None

    def manifest(self) -> SymbolManifestV1:
        if self._manifest is None:
            try:
                self._manifest = read_manifest(Path(self.root))
            except ManifestInvalid as exc:
                raise SymbolsCorrupt(str(exc)) from exc
        return self._manifest

    def _identity_index(self) -> dict[KernelIdentity, SymbolFile]:
        """Identity -> manifest entry (the banner index for Linux; Windows too, so a manifest
        that names one identity twice is caught)."""
        if self._index is None:
            index: dict[KernelIdentity, SymbolFile] = {}
            for entry in self.manifest().files:
                if entry.identity in index:
                    raise SymbolsCorrupt("the manifest lists one kernel identity twice")
                if entry.path != isf_relpath(entry.identity):
                    raise SymbolsCorrupt(f"{entry.path}: not the store path of its identity")
                index[entry.identity] = entry
            self._index = index
        return self._index

    def _checked_path(self, rel: str) -> Path:
        """`root/rel` with no symlink on the way and the file a regular file."""
        current = Path(os.path.abspath(self.root))
        for part in rel.split("/"):
            current = current / part
            try:
                info = os.lstat(current)
            except FileNotFoundError as exc:
                raise SymbolsCorrupt(f"{rel}: listed in the manifest but missing") from exc
            if stat.S_ISLNK(info.st_mode):
                raise SymbolsCorrupt(f"{rel}: a symlink in the store")
        if not stat.S_ISREG(os.lstat(current).st_mode):
            raise SymbolsCorrupt(f"{rel}: not a regular file")
        return current

    def lookup(self, identity: KernelIdentity) -> SymbolHit | None:
        rel = isf_relpath(identity)
        entry = self._identity_index().get(identity)
        if entry is None:
            if os.path.lexists(Path(self.root) / rel):
                # Volatility would load it (by path, or through the identifier cache) although
                # the manifest does not vouch for it.
                raise SymbolsCorrupt(f"{rel}: present but not in the manifest")
            return None
        path = self._checked_path(rel)
        try:
            digest = sha256_file(path)
        except (OSError, StoreError) as exc:
            raise SymbolsCorrupt(f"{rel}: unreadable") from exc
        if digest != entry.sha256:
            raise SymbolsCorrupt(f"{rel}: sha256 does not match the manifest")
        return SymbolHit(path=path, sha256=digest, identity=identity)


__all__ = ["SymbolHit", "SymbolStore", "SymbolsCorrupt", "normalize_banner"]
