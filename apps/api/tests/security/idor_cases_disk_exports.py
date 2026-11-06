"""IDOR cases owned by M9 phase 10 (file exports to derived evidence; RT29).

The victim extender uploads one real disk segment (`kind=disk`: the API's own hashes) into the
victim case, seeds a succeeded disk job over it (the phase-1 Windows listing), and a `ready`
export of `updater.exe` whose object really is in the results bucket (so the owner's promote,
the positive control, succeeds). Every route of this module points `{job_id}` at that disk job
and `{export_id}` at that export through `PATH_OVERRIDES`. The state hook snapshots the
victim's export (state, evidence) and the job's export list: a cross-org request (a foreign
job / file / export id, promoting another org's export) must change nothing. A file of
another job of the same org is covered in `tests/integration/test_disk_export_request.py`.
"""

import hashlib
import io
import uuid
from typing import Any

from sqlalchemy import select

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.disk_forensics.dispatch import export_key
from app.modules.disk_forensics.models import DiskExport, DiskFile
from tests import disk_results as dr
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

_ORG = "/api/v1/orgs/{org_id}"
_FILES = f"{_ORG}/analyses/{{job_id}}/disk/file-exports"
_EXPORT = f"{_ORG}/disk-exports/{{export_id}}"
_UPDATER = "Users/alice/AppData/Local/Temp/updater.exe"
_CONTENT = b"MZ victim export" + b"\0" * 1008

ROUTE_CASES: RouteCases = {
    ("POST", _FILES): lambda v: {"json": {"file_ids": [v.extra["export_file_id"]]}},
    ("GET", _FILES): lambda v: {},
    ("GET", _EXPORT): lambda v: {},
    ("POST", f"{_EXPORT}/promote"): lambda v: {},
}


def _ids(victim: Victim) -> dict[str, str]:
    return {
        "job_id": victim.extra["export_source_job_id"],
        "export_id": victim.extra["disk_export_id"],
    }


PATH_OVERRIDES: PathOverrides = {template: _ids for _, template in ROUTE_CASES}
RESOURCE_PARAMS: tuple[str, ...] = ("{export_id}",)


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    upload = await dr.upload_disk(
        owner, victim.investigation_id, dr.SEGMENT + b"victim", "victim-export.E01"
    )
    assert upload.status_code == 201, upload.text
    segment = uuid.UUID(upload.json()["id"])
    source = await seed_disk_job(tenant, [segment])
    export_job = await seed_disk_job(tenant, [segment], profile="extract", fixture=None)
    async with tenant_session(victim.org_id, owner.user_id) as s:
        file_id = await s.scalar(
            select(DiskFile.id).where(DiskFile.job_id == source, DiskFile.path == _UPDATER)
        )
    assert file_id is not None
    export_id = uuid.uuid4()
    key = export_key(export_job, export_id)
    stored = get_minio().put_object(
        get_settings().results_bucket, key, io.BytesIO(_CONTENT), len(_CONTENT)
    )
    async with tenant_session(victim.org_id, owner.user_id) as s:
        s.add(
            DiskExport(
                id=export_id,
                organization_id=victim.org_id,
                export_job_id=export_job,
                source_job_id=source,
                file_id=file_id,
                path=_UPDATER,
                state="ready",
                object_key=key,
                object_version_id=str(stored.version_id),
                size=len(_CONTENT),
                worker_sha256=hashlib.sha256(_CONTENT).hexdigest(),
                requested_by=owner.user_id,
            )
        )
    return {
        "export_source_job_id": str(source),
        "export_file_id": str(file_id),
        "disk_export_id": str(export_id),
    }


async def _exports_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    base = f"/api/v1/orgs/{victim.org_id}"
    one = await owner.client.get(f"{base}/disk-exports/{victim.extra['disk_export_id']}")
    assert one.status_code == 200, one.text
    listed = await owner.client.get(
        f"{base}/analyses/{victim.extra['export_source_job_id']}/disk/file-exports"
    )
    assert listed.status_code == 200, listed.text
    body = one.json()
    return {
        "disk_export": (body["state"], body["evidence_id"], body["error_code"]),
        "disk_exports": sorted((i["id"], i["state"]) for i in listed.json()["items"]),
    }


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_exports_state]
# Every route of this module has its case (phase 13 asserts the set stays empty).
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
