import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthEvent, AuthEventType
from app.modules.evidence.models import (
    CustodyAction,
    Evidence,
    EvidenceCustodyEvent,
    EvidenceHash,
    HashAlgorithm,
)
from tests.integration.seed import Tenant, seed_tenant


async def _seed_evidence(t: Tenant) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=t.investigation_id,
            original_filename="capture.pcap",
            detected_mime="application/vnd.tcpdump.pcap",
            detected_description="pcap capture file",
            size_bytes=1024,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        s.add_all(
            [
                EvidenceHash(
                    organization_id=t.org_id,
                    evidence_id=evidence.id,
                    algorithm=HashAlgorithm.SHA256,
                    value="0" * 64,
                ),
                EvidenceCustodyEvent(
                    organization_id=t.org_id,
                    evidence_id=evidence.id,
                    action=CustodyAction.UPLOADED,
                    actor_id=t.owner_id,
                ),
                AuditLog(organization_id=t.org_id, actor_id=t.owner_id, action="evidence.uploaded"),
            ]
        )
    async with tenant_session(None, None) as s:
        s.add(AuthEvent(user_id=t.owner_id, event=AuthEventType.LOGIN_SUCCESS))
    return evidence.id


APPEND_ONLY = ["audit_logs", "evidence_hashes", "evidence_custody_events", "auth_events"]


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET id = id", "DELETE FROM {t}"])
async def test_app_role_cannot_mutate_append_only_tables(table: str, statement: str) -> None:
    t = await seed_tenant("alpha")
    await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(text(statement.format(t=table)))


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["UPDATE {t} SET id = id", "DELETE FROM {t}"])
async def test_trigger_blocks_owner_mutations_too(
    table: str, statement: str, owner_engine: AsyncEngine
) -> None:
    t = await seed_tenant("alpha")
    await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(t.org_id)}
            )
            await conn.execute(text(statement.format(t=table)))


@pytest.mark.parametrize(
    "assignment",
    [
        "id = gen_random_uuid()",
        "organization_id = gen_random_uuid()",
        "investigation_id = gen_random_uuid()",
        "original_filename = 'renamed.pcap'",
        "detected_mime = 'text/plain'",
        "detected_description = 'other'",
        "size_bytes = 1",
        "storage_bucket = 'other'",
        "storage_key = 'other'",
        "storage_version_id = 'v2'",
        "uploaded_by = gen_random_uuid()",
        "uploaded_at = now() - interval '1 day'",
    ],
)
async def test_evidence_identity_columns_are_immutable(assignment: str) -> None:
    t = await seed_tenant("alpha")
    evidence_id = await _seed_evidence(t)
    with pytest.raises(DBAPIError, match="immutable"):
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                text(f"UPDATE evidence SET {assignment} WHERE id = :id"), {"id": evidence_id}
            )


async def test_evidence_status_and_description_are_mutable() -> None:
    t = await seed_tenant("alpha")
    evidence_id = await _seed_evidence(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        result = await s.execute(
            text("UPDATE evidence SET status = 'archived', description = 'note' WHERE id = :id"),
            {"id": evidence_id},
        )
    assert result.rowcount == 1
