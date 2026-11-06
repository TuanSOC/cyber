"""The read-only symbol store as the worker sees it (phase-1 STUB; phase 5 owns this file,
never the signatures).

`SymbolStore(root).lookup(identity) -> SymbolHit | None`: resolve a `WindowsPdb` by path
(`windows/<pdb>/<GUID-AGE>.json.xz`) and a `LinuxBanner` through the manifest's banner index,
verify the file's sha256 against the manifest (a tampered store raises `SymbolsCorrupt`, job
code `symbols_corrupt`) and return its path and sha256 for the result header.
`SymbolStore(root).manifest() -> SymbolManifestV1` reads and validates `manifest.json`.
"""

from dataclasses import dataclass
from pathlib import Path

from cyberlab_jobs.memory import KernelIdentity, SymbolManifestV1


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

    def manifest(self) -> SymbolManifestV1:
        raise NotImplementedError("the symbol store lands in M8 phase 5")

    def lookup(self, identity: KernelIdentity) -> SymbolHit | None:
        raise NotImplementedError("the symbol store lands in M8 phase 5")
