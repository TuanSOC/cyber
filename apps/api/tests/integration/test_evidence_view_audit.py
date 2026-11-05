"""Evidence view audit (M7 phase 6, §10 auditable access): `evidence.viewed` (detail) and
`evidence.custody_viewed` (custody list), one row per (user, evidence, action) per 15 min
(Redis SET NX EX), committed in the request's tenant session; never for another org's 404."""

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.audit_dedupe import PREFIX
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.users.models import User
from tests.factories import Registered, csrf, register
from tests.integration.test_orgs_members import org_with_roles

VIEW_ACTIONS = ("evidence.viewed", "evidence.custody_viewed")


async def _evidence(reg: Registered) -> str:
    case = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "View case", "severity": "low"},
        headers=csrf(reg.client),
    )
    upload = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case.json()['id']}/evidence",
        params={"filename": "notes.txt"},
        content=b"viewed evidence\n",
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert upload.status_code == 201, upload.text
    return str(upload.json()["id"])


async def _views(org_id: uuid.UUID) -> list[tuple[str, uuid.UUID | None, uuid.UUID | None]]:
    async with tenant_session(org_id, None) as s:
        stmt = (
            select(AuditLog.action, AuditLog.actor_id, AuditLog.target_id)
            .where(AuditLog.action.in_(VIEW_ACTIONS))
            .order_by(AuditLog.occurred_at, AuditLog.action)
        )
        return [tuple(r) for r in (await s.execute(stmt)).all()]


async def _get(client: AsyncClient, org_id: uuid.UUID, evidence_id: str, suffix: str = "") -> Any:
    return await client.get(f"/api/v1/orgs/{org_id}/evidence/{evidence_id}{suffix}")


async def test_detail_and_custody_views_are_audited_once_per_window() -> None:
    reg = await register()
    evidence_id = await _evidence(reg)
    for _ in range(3):
        assert (await _get(reg.client, reg.org_id, evidence_id)).status_code == 200
        assert (await _get(reg.client, reg.org_id, evidence_id, "/custody")).status_code == 200
    views = await _views(reg.org_id)
    target = uuid.UUID(evidence_id)
    assert sorted(views) == sorted(
        [("evidence.viewed", reg.user_id, target), ("evidence.custody_viewed", reg.user_id, target)]
    )
    async with tenant_session(reg.org_id, None) as s:
        log = (
            await s.execute(select(AuditLog).where(AuditLog.action == "evidence.viewed"))
        ).scalar_one()
    assert log.target_type == "evidence"
    assert log.details == {}  # nothing beyond the ids
    assert log.ip is None and log.user_agent is None


async def test_window_expiry_writes_a_new_row() -> None:
    reg = await register()
    evidence_id = await _evidence(reg)
    await _get(reg.client, reg.org_id, evidence_id)
    # The dedupe key expires after EVIDENCE_VIEW_AUDIT_DEDUPE_S: simulate the end of the window.
    await get_redis().delete(f"{PREFIX}{reg.user_id}:{evidence_id}:evidence.viewed")
    await _get(reg.client, reg.org_id, evidence_id)
    assert [v[0] for v in await _views(reg.org_id)] == ["evidence.viewed", "evidence.viewed"]


async def test_dedupe_key_has_the_configured_ttl() -> None:
    reg = await register()
    evidence_id = await _evidence(reg)
    await _get(reg.client, reg.org_id, evidence_id, "/custody")
    ttl = await get_redis().ttl(f"{PREFIX}{reg.user_id}:{evidence_id}:evidence.custody_viewed")
    assert 0 < ttl <= get_settings().evidence_view_audit_dedupe_s == 900


async def test_each_user_gets_their_own_row_and_a_viewer_is_audited() -> None:
    org = await org_with_roles()
    owner = org.clients["owner"]
    case = await owner.post(
        f"/api/v1/orgs/{org.org_id}/investigations",
        json={"title": "Shared case", "severity": "low"},
        headers=csrf(owner),
    )
    upload = await owner.post(
        f"/api/v1/orgs/{org.org_id}/investigations/{case.json()['id']}/evidence",
        params={"filename": "notes.txt"},
        content=b"shared\n",
        headers={"Content-Type": "application/octet-stream", **csrf(owner)},
    )
    evidence_id = str(upload.json()["id"])
    for role in ("owner", "viewer", "viewer", "analyst"):
        assert (await _get(org.clients[role], org.org_id, evidence_id)).status_code == 200
    actors = [actor for _, actor, _ in await _views(org.org_id)]
    async with tenant_session(None, None) as s:
        emails = dict(
            (await s.execute(select(User.id, User.email).where(User.id.in_(actors)))).all()
        )
    assert sorted(emails[a] for a in actors) == sorted(
        org.emails[r] for r in ("owner", "viewer", "analyst")
    )


async def test_another_orgs_404_writes_no_row() -> None:
    victim = await register()
    evidence_id = await _evidence(victim)
    attacker = await register()
    for suffix in ("", "/custody"):
        # Through the attacker's own org (RLS hides the row) and the victim's (not a member).
        assert (
            await _get(attacker.client, attacker.org_id, evidence_id, suffix)
        ).status_code == 404
        assert (await _get(attacker.client, victim.org_id, evidence_id, suffix)).status_code == 404
    assert await _views(victim.org_id) == []
    assert await _views(attacker.org_id) == []
    keys = [k async for k in get_redis().scan_iter(match=f"{PREFIX}{attacker.user_id}:*")]
    assert keys == []


async def test_list_routes_are_not_audited() -> None:
    reg = await register()
    await _evidence(reg)
    cases = (await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")).json()["items"]
    listed = await reg.client.get(
        f"/api/v1/orgs/{reg.org_id}/investigations/{cases[0]['id']}/evidence"
    )
    assert listed.status_code == 200 and listed.json()["total"] == 1
    assert await _views(reg.org_id) == []


async def test_failed_commit_gives_the_dedupe_slot_back(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()
    evidence_id = await _evidence(reg)

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit insert failed")

    monkeypatch.setattr("app.modules.evidence.router.audit.record", broken)
    # The 500 handler answers; ServerErrorMiddleware may also re-raise into the test client.
    try:
        failed = await _get(reg.client, reg.org_id, evidence_id)
    except RuntimeError:
        pass
    else:
        assert failed.status_code == 500
    monkeypatch.undo()
    assert (await _get(reg.client, reg.org_id, evidence_id)).status_code == 200
    assert [v[0] for v in await _views(reg.org_id)] == ["evidence.viewed"]
