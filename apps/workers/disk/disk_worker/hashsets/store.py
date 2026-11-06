"""The read-only hash-set store (M9 phase 1 stubs; phase 5 owns the bodies).

`HashSetStore(root).match(sha256, sha1, md5) -> HashSetHit | None` (mmap + binary search over
`<name>/{sha256,sha1,md5}.bin`) and `.manifest() -> HashSetManifestV1` (verified against the
file hashes it lists).
"""

from dataclasses import dataclass
from pathlib import Path

from cyberlab_jobs.disk import HashSetManifestV1


@dataclass(frozen=True)
class HashSetHit:
    name: str
    kind: str  # known_good | known_bad | notable
    algo: str  # the algorithm that matched


class HashSetsCorrupt(RuntimeError):
    """A store file does not match its manifest entry."""


class HashSetStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def manifest(self) -> HashSetManifestV1:
        raise NotImplementedError("the hash-set store lands with M9 phase 5")

    def match(self, sha256: str | None, sha1: str | None, md5: str | None) -> HashSetHit | None:
        raise NotImplementedError("the hash-set store lands with M9 phase 5")
