"""Memory sensitivity (M8 phase 8): TLP:RED by default, admin release once, audited.

- `apply_memory_default` marks evidence `restricted` and sets both share-policy flags (never
  loosening), audits `memory.sensitivity_defaulted` once and is idempotent; a released row
  stays released;
- the first memory job request applies it (phase-1 call site); a `kind=memory` upload is
  restricted before any job exists (phase-6 call site, skipped until it lands);
- `GET /evidence/{id}/memory-sensitivity` (`none` / `restricted` / `released`) and
  `EvidenceOut.memory_sensitivity`;
- `POST …/release`: `org.update`, `422 acknowledgement_required`, once (`409
  memory_sensitivity_released`), audited, and it leaves the share-policy flags set.

The module also holds the M8 phase-8 test helpers used by the other `test_memory_*` modules.
"""

import inspect
import secrets
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.evidence import uploads
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis import sensitivity
from app.modules.memory_analysis.models import MemorySensitivity
from app.modules.organizations.models import MemberRole
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from tests.ai_api_helpers import tenant_of
from tests.analysis_helpers import new_case, upload
from tests.case_helpers import seed_evidence, set_evidence_policy
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email
from tests.integration.seed import Tenant
from tests.memory_helpers import seed_memory_job

API = "/api/v1/orgs"
REASON = "Legal approved the triage of this image for case work"
# A phase-3 masked secret as it lands in a finding (first 2 characters and the length kept).
MASKED_TITLE = "Credential on a command line: password=hu******"
RAW_SECRET = "hunter22"

# --- helpers (shared with the other test_memory_* modules) ----------------------------------


async def apply_default(t: Tenant, evidence_id: uuid.UUID) -> bool:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return await sensitivity.apply_memory_default(s, t.org_id, evidence_id, t.owner_id)


async def memory_evidence(t: Tenant, investigation_id: uuid.UUID | None = None) -> uuid.UUID:
    """Evidence of the case defaulted to restricted through the phase-8 entry point."""
    evidence_id = await seed_evidence(t, investigation_id, filename="host.mem")
    assert await apply_default(t, evidence_id)
    return evidence_id


async def seed_memory_results(
    t: Tenant,
    job_id: uuid.UUID,
    *,
    findings: Sequence[tuple[str, str]] = (("high", MASKED_TITLE),),
    iocs: Sequence[tuple[str, str]] = (("ip", "203.0.113.77"),),
) -> list[uuid.UUID]:
    """Findings (severity, title) and IOCs (type, value) of a job, as an ingest writes them.
    Returns the finding row ids."""
    now = datetime.now(UTC)
    rows: list[AnalysisFinding] = []
    async with tenant_session(t.org_id, t.owner_id) as s:
        for severity, title in findings:
            row = AnalysisFinding(
                organization_id=t.org_id,
                job_id=job_id,
                finding_id=uuid.uuid4(),
                ts=now,
                type="memory_credential_cmdline",
                title=title,
                description=f"{title} (process 4242)",
                severity=severity,
                confidence=0.6,
                detection_method="heuristic:memory@1",
                evidence_refs=[],
                attributes={},
            )
            s.add(row)
            rows.append(row)
        for ioc_type, value in iocs:
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=now,
                    last_seen=now,
                    count=1,
                    source="memory",
                )
            )
        await s.flush()
        ids = [r.id for r in rows]
    return ids


async def release(
    client: AsyncClient, org_id: uuid.UUID, evidence_id: uuid.UUID | str, **body: object
) -> Response:
    payload: dict[str, object] = {"acknowledge": True, "reason": REASON, **body}
    return await client.post(
        f"{API}/{org_id}/evidence/{evidence_id}/memory-sensitivity/release",
        json=payload,
        headers=csrf(client),
    )


async def get_sensitivity(
    client: AsyncClient, org_id: uuid.UUID, evidence_id: uuid.UUID | str
) -> Response:
    return await client.get(f"{API}/{org_id}/evidence/{evidence_id}/memory-sensitivity")


async def put_flags(
    client: AsyncClient, org_id: uuid.UUID, evidence_id: uuid.UUID | str, *, ai: bool, ti: bool
) -> Response:
    return await client.put(
        f"{API}/{org_id}/evidence/{evidence_id}/share-policy",
        json={"ai_excluded": ai, "ti_excluded": ti},
        headers=csrf(client),
    )


async def release_and_clear(reg: Registered, evidence_id: uuid.UUID) -> None:
    """The two explicit steps of the plan: the admin release, then the M6 PUT."""
    released = await release(reg.client, reg.org_id, evidence_id)
    assert released.status_code == 200, released.text
    cleared = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
    assert cleared.status_code == 200, cleared.text


async def member(reg: Registered, role: MemberRole) -> AsyncClient:
    email = unique_email(role.value)
    await add_member(reg.org_id, await make_user(email), role)
    return await login(email)


async def audit_rows(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.action == action)
            .order_by(AuditLog.occurred_at, AuditLog.id)
        )
        return list(rows)


async def flags(t: Tenant, evidence_id: uuid.UUID) -> tuple[bool, bool] | None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(EvidenceSharePolicy, evidence_id)
        return None if row is None else (row.ai_excluded, row.ti_excluded)


async def state(t: Tenant, evidence_id: uuid.UUID) -> str | None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(MemorySensitivity, evidence_id)
        return None if row is None else row.state


# --- the default ----------------------------------------------------------------------------


async def test_the_default_restricts_and_excludes_once() -> None:
    reg = await register(org_name="Sensitivity Default Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="host.mem")
    assert await state(t, evidence_id) is None and await flags(t, evidence_id) is None

    assert await apply_default(t, evidence_id) is True
    assert await state(t, evidence_id) == "restricted"
    assert await flags(t, evidence_id) == (True, True)
    [row] = await audit_rows(t.org_id, "memory.sensitivity_defaulted")
    assert (row.target_id, row.actor_id) == (evidence_id, t.owner_id)
    assert row.details["share_policy"] == {
        "from": {"ai_excluded": False, "ti_excluded": False},
        "to": {"ai_excluded": True, "ti_excluded": True},
    }

    # A later memory job on the same evidence changes nothing (no second audit row).
    assert await apply_default(t, evidence_id) is False
    assert len(await audit_rows(t.org_id, "memory.sensitivity_defaulted")) == 1


async def test_the_default_never_loosens_an_existing_policy() -> None:
    reg = await register(org_name="Sensitivity Strict Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="host.mem")
    await set_evidence_policy(t, evidence_id, ai_excluded=True, ti_excluded=False)
    assert await apply_default(t, evidence_id)
    assert await flags(t, evidence_id) == (True, True)
    [row] = await audit_rows(t.org_id, "memory.sensitivity_defaulted")
    assert row.details["share_policy"]["from"] == {"ai_excluded": True, "ti_excluded": False}


async def test_a_released_row_stays_released() -> None:
    reg = await register(org_name="Sensitivity Released Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    await release_and_clear(reg, evidence_id)
    # Another memory job on the released evidence: no new restriction, the flags stay off.
    assert await apply_default(t, evidence_id) is False
    assert await state(t, evidence_id) == "released"
    assert await flags(t, evidence_id) == (False, False)


async def test_the_first_memory_job_request_applies_the_default() -> None:
    reg = await register(org_name="Sensitivity Job Org")
    case_id = await new_case(reg)
    # Uploaded without `kind=memory` (real hashes): the memory job applies the default.
    uploaded = await upload(reg.client, reg.org_id, case_id, b"\0" * 4096, "workstation.raw")
    evidence_id = uploaded["id"]
    before = await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}")
    assert before.json()["memory_sensitivity"] is None
    job = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "memory"},
        headers=csrf(reg.client),
    )
    assert job.status_code == 201, job.text
    body = (await get_sensitivity(reg.client, reg.org_id, evidence_id)).json()
    assert body["state"] == "restricted" and body["defaulted_at"] is not None
    assert body["released_at"] is None and body["release_reason"] is None
    evidence = (await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}")).json()
    assert evidence["memory_sensitivity"] == "restricted"
    assert (evidence["ai_excluded"], evidence["ti_excluded"]) == (True, True)
    assert len(await audit_rows(reg.org_id, "memory.sensitivity_defaulted")) == 1


async def test_a_memory_upload_is_restricted_before_any_job() -> None:
    if "apply_memory_default" not in inspect.getsource(uploads):
        pytest.skip("the upload-time default is phase 6's call site (not merged in this lane)")
    reg = await register(org_name="Sensitivity Upload Org")
    case_id = await new_case(reg)
    response = await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{case_id}/evidence",
        params={"filename": "server.mem", "kind": "memory"},
        content=secrets.token_bytes(64 * 1024),
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert response.status_code == 201, response.text
    evidence_id = response.json()["id"]
    jobs = await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses")
    assert jobs.json()["items"] == []
    assert (await get_sensitivity(reg.client, reg.org_id, evidence_id)).json()["state"] == (
        "restricted"
    )
    policy = (
        await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy")
    ).json()
    assert (policy["ai_excluded"], policy["ti_excluded"]) == (True, True)


# --- the read and the release ---------------------------------------------------------------


async def test_plain_evidence_reads_none_and_cannot_be_released() -> None:
    reg = await register(org_name="Sensitivity None Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t)
    response = await get_sensitivity(reg.client, reg.org_id, evidence_id)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "evidence_id": str(evidence_id),
        "state": "none",
        "defaulted_at": None,
        "released_at": None,
        "released_by_name": None,
        "release_reason": None,
    }
    assert (await release(reg.client, reg.org_id, evidence_id)).status_code == 404
    unknown = uuid.uuid4()
    assert (await get_sensitivity(reg.client, reg.org_id, unknown)).status_code == 404
    assert (await release(reg.client, reg.org_id, unknown)).status_code == 404


async def test_release_needs_the_acknowledgement_and_a_reason() -> None:
    reg = await register(org_name="Sensitivity Ack Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    refused = await release(reg.client, reg.org_id, evidence_id, acknowledge=False)
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"]["code"] == "acknowledgement_required"
    for reason in ("", "x" * 501):
        bad = await release(reg.client, reg.org_id, evidence_id, reason=reason)
        assert bad.status_code == 422, (reason[:10], bad.text)
    assert await state(t, evidence_id) == "restricted"
    assert await audit_rows(reg.org_id, "memory.sensitivity_released") == []


@pytest.mark.parametrize("role", [MemberRole.ANALYST, MemberRole.VIEWER])
async def test_release_needs_org_update(role: MemberRole) -> None:
    reg = await register(org_name=f"Sensitivity {role.value} Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    client = await member(reg, role)
    # Every member with evidence.read sees the state; only an admin releases.
    assert (await get_sensitivity(client, reg.org_id, evidence_id)).json()["state"] == (
        "restricted"
    )
    response = await release(client, reg.org_id, evidence_id)
    assert response.status_code == 403, response.text
    assert await state(t, evidence_id) == "restricted"


async def test_release_happens_once_is_audited_and_keeps_the_flags() -> None:
    reg = await register(org_name="Sensitivity Release Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    admin = await member(reg, MemberRole.ADMIN)

    response = await release(admin, reg.org_id, evidence_id, reason=f"  {REASON}  ")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "released"
    assert body["release_reason"] == REASON
    assert body["released_at"] is not None and body["released_by_name"]
    assert (await get_sensitivity(reg.client, reg.org_id, evidence_id)).json() == body
    evidence = (await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}")).json()
    assert evidence["memory_sensitivity"] == "released"
    # Two explicit steps: the flags stay set until the M6 PUT clears them.
    assert await flags(t, evidence_id) == (True, True)
    [row] = await audit_rows(reg.org_id, "memory.sensitivity_released")
    assert row.target_id == evidence_id
    assert row.details == {
        "from": "restricted",
        "to": "released",
        "reason": REASON,
        "acknowledged": True,
    }

    again = await release(reg.client, reg.org_id, evidence_id)
    assert again.status_code == 409, again.text
    assert again.json()["error"]["code"] == "memory_sensitivity_released"
    assert len(await audit_rows(reg.org_id, "memory.sensitivity_released")) == 1


async def test_another_orgs_evidence_is_404() -> None:
    reg = await register(org_name="Sensitivity Victim Org")
    other = await register(org_name="Sensitivity Attacker Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    for org_id in (other.org_id, reg.org_id):
        assert (await get_sensitivity(other.client, org_id, evidence_id)).status_code in (403, 404)
        assert (await release(other.client, org_id, evidence_id)).status_code in (403, 404)
    assert await state(t, evidence_id) == "restricted"


async def test_seed_memory_job_on_restricted_evidence_keeps_its_rows() -> None:
    """The helper chain the other modules use: a memory job with results on defaulted
    evidence."""
    reg = await register(org_name="Sensitivity Helper Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    job_id = await seed_memory_job(t, evidence_id)
    [finding] = await seed_memory_results(t, job_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(AnalysisFinding, finding)
    assert row is not None and row.job_id == job_id and RAW_SECRET not in row.title
