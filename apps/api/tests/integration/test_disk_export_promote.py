"""M9 phase 10: promotion of a `ready` export to derived evidence (`POST …/promote`).

The API streams the exact object version through the evidence pipeline (its own sha256 / sha1 /
md5, sniff, quota, object lock), refuses a worker-hash mismatch (`failed` /
`export_hash_mismatch`, nothing promoted), inherits the restriction (source `derived`) and the
share flags of the source segments (never loosening) and triggers the normal static job.
"""

import hashlib
import uuid
from typing import Any

from sqlalchemy import func, select

from app.core.tenancy import tenant_session
from app.modules.analysis.models import Analyzer
from app.modules.evidence.models import Evidence
from tests import disk_export_helpers as dx
from tests.analysis_helpers import SentJobs
from tests.disk_export_helpers import Captured
from tests.disk_export_helpers import exports as exports  # noqa: F401 (fixture)
from tests.disk_results import HandOffs
from tests.disk_results import handoffs as handoffs  # noqa: F401 (fixture)
from tests.disk_results import sent as sent  # noqa: F401 (fixture)


async def _evidence_count(org_id: uuid.UUID) -> int:
    async with tenant_session(org_id, None) as s:
        return int(await s.scalar(select(func.count()).select_from(Evidence)) or 0)


async def test_a_promoted_file_is_restricted_derived_evidence_with_its_static_job(
    exports: Captured, handoffs: HandOffs, sent: SentJobs
) -> None:
    src, _, export_id = await dx.ready_export(exports, handoffs, segments=2)
    org = src.reg.org_id
    before = len(sent)
    response = await dx.promote(src.reg, export_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "promoted" and body["promoted_at"] is not None
    evidence_id = body["evidence_id"]

    got = await src.reg.client.get(f"/api/v1/orgs/{org}/evidence/{evidence_id}")
    evidence: dict[str, Any] = got.json()
    assert evidence["investigation_id"] == src.case_id
    assert evidence["original_filename"] == "updater.exe"
    assert evidence["size_bytes"] == len(dx.CONTENT)
    assert evidence["hashes"]["sha256"] == hashlib.sha256(dx.CONTENT).hexdigest()  # the API's
    assert evidence["hashes"]["md5"] == hashlib.md5(dx.CONTENT).hexdigest()  # noqa: S324
    assert evidence["derived_from"] == str(src.segments[0])
    assert evidence["sensitivity"] == {"state": "restricted", "source": "derived"}
    assert evidence["ai_excluded"] and evidence["ti_excluded"]
    assert (
        f"disk job {src.job_id}" in evidence["description"]
        and dx.UPDATER in evidence["description"]
    )
    # The normal automatic static run (after commit; `av` here: the bytes are no real PE).
    static = [i for i in sent[before:] if str(i.evidence_id) == evidence_id]
    assert [i.analyzer for i in static] == [Analyzer.STATIC]

    again = await dx.promote(src.reg, export_id)
    assert (again.status_code, again.json()["error"]["code"]) == (
        409,
        "disk_export_already_promoted",
    )


async def test_an_unrestricted_source_gives_unrestricted_evidence(
    exports: Captured, handoffs: HandOffs, sent: SentJobs
) -> None:
    src, _, export_id = await dx.ready_export(exports, handoffs, kind=None)
    response = await dx.promote(src.reg, export_id)
    assert response.status_code == 200, response.text
    got = await src.reg.client.get(
        f"/api/v1/orgs/{src.reg.org_id}/evidence/{response.json()['evidence_id']}"
    )
    evidence = got.json()
    assert evidence["sensitivity"] is None
    assert (evidence["ai_excluded"], evidence["ti_excluded"]) == (False, False)


async def test_a_worker_hash_mismatch_promotes_nothing(
    exports: Captured, handoffs: HandOffs, sent: SentJobs
) -> None:
    src, item, export_id = await dx.ready_export(exports, handoffs)
    # A second version under the key does not matter: the exact recorded version is read.
    # Here the recorded version itself lies: reported sha256 of other bytes.
    row = await dx.export_row(src.reg.org_id, export_id)
    async with tenant_session(src.reg.org_id, None) as s:
        stored = await s.get(type(row), row.id)
        assert stored is not None
        stored.worker_sha256 = "0" * 64
    count = await _evidence_count(src.reg.org_id)
    response = await dx.promote(src.reg, export_id)
    assert (response.status_code, response.json()["error"]["code"]) == (
        409,
        "export_hash_mismatch",
    )
    after = await dx.export_row(src.reg.org_id, export_id)
    assert (after.state, after.error_code, after.evidence_id) == (
        "failed",
        "export_hash_mismatch",
        None,
    )
    assert await _evidence_count(src.reg.org_id) == count
    again = await dx.promote(src.reg, export_id)
    assert again.json()["error"]["code"] == "disk_export_not_ready"


async def test_pending_failed_and_unknown_exports_are_refused(
    exports: Captured, handoffs: HandOffs, sent: SentJobs
) -> None:
    src = await dx.source_job()
    updater = await dx.file_id(src.reg.org_id, src.job_id, dx.UPDATER)
    response = await dx.request(src.reg, src.job_id, [updater])
    export_id = response.json()["items"][0]["id"]
    pending = await dx.promote(src.reg, export_id)
    assert (pending.status_code, pending.json()["error"]["code"]) == (409, "disk_export_not_ready")
    assert (await dx.promote(src.reg, uuid.uuid4())).status_code == 404
    got = await src.reg.client.get(f"/api/v1/orgs/{src.reg.org_id}/disk-exports/{export_id}")
    assert got.status_code == 200 and got.json()["state"] == "pending"
