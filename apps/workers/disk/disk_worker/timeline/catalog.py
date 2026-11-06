"""The artifact catalog (M9 phase 1 stub; phase 3 owns the body).

`match(files, os, profile) -> CollectPlan`: the listed files to copy into the mirrored tree per
`ARTIFACTS_BY_PROFILE`, never a file any of whose names is on `NEVER_COLLECT_PATTERNS` (RT7).
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from cyberlab_jobs.disk import AnalysisProfile, DiskArtifact, DiskFileRecord, DiskOs


@dataclass
class CollectPlan:
    files: list[tuple[DiskArtifact, DiskFileRecord]] = field(default_factory=list)
    bytes: int = 0
    refused_never_collect: int = 0


def match(files: Sequence[DiskFileRecord], os: DiskOs, profile: AnalysisProfile) -> CollectPlan:
    raise NotImplementedError("the artifact catalog lands with M9 phase 3")
