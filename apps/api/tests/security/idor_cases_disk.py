"""IDOR cases owned by M9 phase 8 (the disk read API).

The victim extender seeds a succeeded disk job in the victim org
(`tests/disk_helpers.seed_disk_job`, the phase-1 Windows fixture) and every route of this
module points `{job_id}` at it through `PATH_OVERRIDES` (the default `{job_id}` is the
victim's pcap job); `{file_id}` is one of its listed files (a hard-linked name) and `{name}`
the body file export. The routes are reads (the exports' audit row is written only on
success), so no state hook is needed. The pcap / memory / extract-job, unknown-file and
other-job-file cases are in `tests/integration/test_disk_reads.py`.
"""

import uuid

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.disk_forensics.models import DiskFile
from tests.disk_helpers import seed_disk_job
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/disk"
_FILE_PATH = "Users/alice/link_a.txt"  # windows_triage.ndjson: one name of a hard-link pair

ROUTE_CASES: RouteCases = {
    ("GET", _JOB): lambda v: {},
    ("GET", f"{_JOB}/partitions"): lambda v: {},
    ("GET", f"{_JOB}/files"): lambda v: {"params": {"q": "alice", "flag": "hard_linked"}},
    ("GET", f"{_JOB}/files/{{file_id}}"): lambda v: {},
    ("GET", f"{_JOB}/dirs"): lambda v: {"params": {"partition": 1}},
    ("GET", f"{_JOB}/events"): lambda v: {"params": {"artifact": "evtx"}},
    ("GET", f"{_JOB}/timeline"): lambda v: {"params": {"source": "file", "time": "mtime"}},
    ("GET", f"{_JOB}/exports/{{name}}"): lambda v: {},
}


def _disk_job(victim: Victim) -> dict[str, str]:
    return {
        "job_id": victim.extra["disk_job_id"],
        "file_id": victim.extra["disk_file_id"],
        "name": "bodyfile",
    }


PATH_OVERRIDES: PathOverrides = {template: _disk_job for _, template in ROUTE_CASES}
RESOURCE_PARAMS: tuple[str, ...] = ("{file_id}",)


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    job_id = await seed_disk_job(tenant)
    async with tenant_session(victim.org_id, owner.user_id) as s:
        file_id = await s.scalar(
            select(DiskFile.id).where(DiskFile.job_id == job_id, DiskFile.path == _FILE_PATH)
        )
    assert file_id is not None
    return {"disk_job_id": str(job_id), "disk_file_id": str(file_id)}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = []
# Every route of this module has its case (phase 13 asserts the set stays empty).
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
