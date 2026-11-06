"""M9 phase 10: the custody and audit trail of a file export, on both sides, and the listing of a
job's exports.

- request: custody `export_requested` on every source segment, audit `disk.export_requested`;
- promote: custody `derived_from` on the new evidence (source job, segments, partition, path,
  meta_addr, the trusted sha256) after its `uploaded`, `export_promoted` on every source
  segment, audit `disk.export_promoted` (with the inherited flags);
- `GET /analyses/{job}/disk/file-exports` lists a job's exports, newest first; 404 for an
  `extract` job or an unknown one;
- the dirs route takes `parent` as decimal text (a u64 above 2**53).
"""

import hashlib
import uuid
from typing import Any

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent
from tests import disk_export_helpers as dx
from tests.analysis_helpers import SentJobs
from tests.disk_export_helpers import Captured
from tests.disk_export_helpers import exports as exports  # noqa: F401 (fixture)
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)


async def _custody(org_id: uuid.UUID, evidence_id: uuid.UUID | str) -> list[EvidenceCustodyEvent]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == uuid.UUID(str(evidence_id)))
            .order_by(EvidenceCustodyEvent.occurred_at, EvidenceCustodyEvent.id)
        )
        return list(rows)


async def _audit(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog).where(AuditLog.organization_id == org_id, AuditLog.action == action)
        )
        return list(rows)


async def test_custody_records_the_derivation_on_both_sides(
    exports: Captured, handoffs: HandOffs, sent: SentJobs
) -> None:
    src, item, export_id = await dx.ready_export(exports, handoffs, segments=2)
    org = src.reg.org_id
    response = await dx.promote(src.reg, export_id)
    assert response.status_code == 200, response.text
    evidence_id = response.json()["evidence_id"]

    for segment in src.segments:
        actions = [e.action for e in await _custody(org, segment)]
        assert CustodyAction.EXPORT_REQUESTED in actions
        assert actions[-1] == CustodyAction.EXPORT_PROMOTED
        promoted = (await _custody(org, segment))[-1]
        assert promoted.details["derived_evidence_id"] == evidence_id
        assert promoted.details["export_id"] == export_id

    derived = {e.action: e for e in await _custody(org, evidence_id)}  # one transaction
    assert set(derived) == {CustodyAction.UPLOADED, CustodyAction.DERIVED_FROM}
    details: dict[str, Any] = derived[CustodyAction.DERIVED_FROM].details
    assert details["source_job_id"] == str(src.job_id)
    assert details["export_job_id"] == str(item.job_id)
    assert details["segments"] == [str(s) for s in src.segments]
    assert (details["partition_index"], details["path"]) == (1, dx.UPDATER)
    assert details["meta_addr"] == "357" and details["stream"] is None
    assert details["sha256"] == hashlib.sha256(dx.CONTENT).hexdigest()

    [requested] = await _audit(org, "disk.export_requested")
    assert requested.details["export_ids"] == [export_id]
    [audited] = await _audit(org, "disk.export_promoted")
    assert str(audited.target_id) == evidence_id
    assert audited.details["restricted"] is True


async def test_a_job_lists_its_exports(
    exports: Captured, handoffs: HandOffs, sent: SentJobs
) -> None:
    src, item, ready = await dx.ready_export(exports, handoffs)
    org = src.reg.org_id
    stream = await dx.file_id(org, src.job_id, dx.NOTES, "payload")
    second = await dx.request(src.reg, src.job_id, [stream])
    assert second.status_code == 202, second.text
    url = f"/api/v1/orgs/{org}/analyses/{src.job_id}/disk/file-exports"
    listed = await src.reg.client.get(url)
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    assert [i["id"] for i in items] == [second.json()["items"][0]["id"], ready]
    assert [i["state"] for i in items] == ["pending", "ready"]
    extract = f"/api/v1/orgs/{org}/analyses/{item.job_id}/disk/file-exports"
    assert (await src.reg.client.get(extract)).status_code == 404
    unknown = f"/api/v1/orgs/{org}/analyses/{uuid.uuid4()}/disk/file-exports"
    assert (await src.reg.client.get(unknown)).status_code == 404


async def test_the_dirs_route_takes_a_u64_parent_as_text(sent: SentJobs) -> None:
    src = await dx.source_job()
    base = f"/api/v1/orgs/{src.reg.org_id}/analyses/{src.job_id}/disk/dirs"
    big = str(2**64 - 1)
    ok = await src.reg.client.get(base, params={"partition": 1, "parent": big})
    assert ok.status_code == 200, ok.text
    assert ok.json()["parent_addr"] == big
    for bad in (str(2**64), "-1", "0x10"):
        refused = await src.reg.client.get(base, params={"partition": 1, "parent": bad})
        assert refused.status_code == 422, (bad, refused.text)
