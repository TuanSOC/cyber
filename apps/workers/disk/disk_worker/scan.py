"""YARA candidates and the scan stage output (M9 phase 1 stubs; phase 5 owns the bodies).

- `build_candidates(files, profile, limits) -> list[Candidate]`: allocated PE files
  (`YARA_MAGIC_CLASSES`, RT8) within the profile's per-file / count / byte budgets; a `known =
  good` file in a user-writable path class is still a candidate (RT18).
- `parse_scan_output(path) -> list[YaraHit]`: the probe's bounded JSONL, re-validated by root.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberlab_jobs.disk import AnalysisProfile, DiskFileRecord, DiskLimits


@dataclass(frozen=True)
class Candidate:
    partition_index: int
    meta_addr: int
    meta_seq: int | None
    stream: str | None
    size: int


@dataclass(frozen=True)
class YaraHit:
    partition_index: int
    meta_addr: int
    stream: str | None
    namespace: str
    rule: str
    severity_meta: str | None


def build_candidates(
    files: Sequence[DiskFileRecord], profile: AnalysisProfile, limits: DiskLimits
) -> list[Candidate]:
    raise NotImplementedError("YARA candidates land with M9 phase 5")


def parse_scan_output(path: Path) -> list[YaraHit]:
    raise NotImplementedError("the scan output parser lands with M9 phase 5")
