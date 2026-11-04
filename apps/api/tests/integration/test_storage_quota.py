"""Per-organization storage quota and the owned-org limit (M3 RT8)."""

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import Response
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import storage
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.core.upload_slots import slot_key
from app.modules.evidence import uploads
from app.modules.organizations.models import MemberRole
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email
from tests.integration.test_evidence import _evidence_rows, _new_case, _tmp_files, _upload
from tests.storage_helpers import all_entries

GIB = 1024**3


async def _set_quota(owner_engine: AsyncEngine, org_id: uuid.UUID, quota: int | None) -> None:
    """Operator action: only the database owner may set a quota (FORCE RLS: org context)."""
    async with owner_engine.begin() as conn:
        await conn.execute(
            text("SELECT set_config('app.org_id', :org, true)"), {"org": str(org_id)}
        )
        await conn.execute(
            text("UPDATE organizations SET storage_quota_bytes = :quota WHERE id = :org"),
            {"quota": quota, "org": org_id},
        )


async def _storage(reg: Registered) -> dict[str, int]:
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/storage")
    assert response.status_code == 200, response.text
    body: dict[str, int] = response.json()
    return body


async def _chunked(data: bytes) -> AsyncIterator[bytes]:
    """No Content-Length: only the authoritative (post-spool) check can catch it."""
    for start in range(0, len(data), 16):
        yield data[start : start + 16]


def _code(response: Response) -> tuple[int, str]:
    return response.status_code, response.json()["error"]["code"]


async def test_default_quota_override_and_usage(owner_engine: AsyncEngine) -> None:
    reg = await register()
    assert await _storage(reg) == {"used_bytes": 0, "quota_bytes": 20 * GIB, "evidence_count": 0}

    case_id = await _new_case(reg)
    assert (await _upload(reg.client, reg.org_id, case_id, b"a" * 100)).status_code == 201
    assert (await _upload(reg.client, reg.org_id, case_id, b"b" * 50)).status_code == 201
    await _set_quota(owner_engine, reg.org_id, 5000)
    assert await _storage(reg) == {"used_bytes": 150, "quota_bytes": 5000, "evidence_count": 2}

    await _set_quota(owner_engine, reg.org_id, None)  # back to the deployment default
    assert (await _storage(reg))["quota_bytes"] == 20 * GIB


async def test_usage_is_per_org() -> None:
    a, b = await register(), await register()
    case_id = await _new_case(a)
    assert (await _upload(a.client, a.org_id, case_id, b"x" * 64)).status_code == 201
    assert (await _storage(a))["used_bytes"] == 64
    assert (await _storage(b))["used_bytes"] == 0


async def test_declared_length_over_quota_is_rejected_before_reading(
    monkeypatch: pytest.MonkeyPatch, owner_engine: AsyncEngine
) -> None:
    reg = await register()
    case_id = await _new_case(reg)
    await _set_quota(owner_engine, reg.org_id, 1000)
    assert (await _upload(reg.client, reg.org_id, case_id, b"a" * 600)).status_code == 201

    async def must_not_spool(*args: object, **kwargs: object) -> None:
        raise AssertionError("the body must not be read")

    monkeypatch.setattr(uploads, "spool", must_not_spool)
    response = await _upload(reg.client, reg.org_id, case_id, b"b" * 401)
    assert _code(response) == (413, "storage_quota_exceeded")
    assert "storage quota" in response.json()["error"]["message"]
    assert len(await _evidence_rows(reg.org_id)) == 1


async def test_undeclared_length_over_quota_discards_the_stored_version(
    owner_engine: AsyncEngine,
) -> None:
    reg = await register()
    case_id = await _new_case(reg)
    await _set_quota(owner_engine, reg.org_id, 100)

    response = await _upload(reg.client, reg.org_id, case_id, _chunked(os.urandom(101)))

    assert _code(response) == (413, "storage_quota_exceeded")
    assert await _evidence_rows(reg.org_id) == []
    # Exact version removed, not merely hidden behind a delete marker.
    assert all_entries(prefix=f"{reg.org_id}/") == []
    assert _tmp_files() == []
    assert await get_redis().zcard(slot_key("upload", reg.user_id)) == 0
    # Exactly at the quota still fits.
    ok = await _upload(reg.client, reg.org_id, case_id, _chunked(os.urandom(100)))
    assert ok.status_code == 201, ok.text


async def test_concurrent_uploads_cannot_overshoot_the_quota(
    monkeypatch: pytest.MonkeyPatch, owner_engine: AsyncEngine
) -> None:
    """Each fits alone, not both: both are stored before either inserts, exactly one wins."""
    reg = await register()
    case_id = await _new_case(reg)
    await _set_quota(owner_engine, reg.org_id, 150)

    real_put = storage.put_file
    stored = 0
    both_stored = asyncio.Event()

    async def put_then_wait(key: str, path: Path) -> str:
        nonlocal stored
        version_id = await real_put(key, path)
        stored += 1
        if stored == 2:
            both_stored.set()
        await asyncio.wait_for(both_stored.wait(), timeout=10)
        return version_id

    monkeypatch.setattr(storage, "put_file", put_then_wait)
    responses = await asyncio.gather(
        _upload(reg.client, reg.org_id, case_id, _chunked(os.urandom(100))),
        _upload(reg.client, reg.org_id, case_id, _chunked(os.urandom(100))),
    )

    assert sorted(r.status_code for r in responses) == [201, 413]
    [loser] = [r for r in responses if r.status_code == 413]
    assert loser.json()["error"]["code"] == "storage_quota_exceeded"
    [row] = await _evidence_rows(reg.org_id)
    # Only the winner's version is left; the loser's was deleted outright.
    assert all_entries(prefix=f"{reg.org_id}/") == [
        (row.storage_key, row.storage_version_id, False)
    ]
    assert (await _storage(reg))["used_bytes"] == 100


async def test_archived_evidence_still_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "default_storage_quota_bytes", 150)
    reg = await register()
    case_id = await _new_case(reg)
    evidence = (await _upload(reg.client, reg.org_id, case_id, b"a" * 100)).json()
    archived = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/archive", headers=csrf(reg.client)
    )
    assert archived.json()["status"] == "archived"

    assert await _storage(reg) == {"used_bytes": 100, "quota_bytes": 150, "evidence_count": 1}
    response = await _upload(reg.client, reg.org_id, case_id, _chunked(b"b" * 51))
    assert _code(response) == (413, "storage_quota_exceeded")


async def test_lowered_quota_blocks_even_undeclared_uploads_early(
    monkeypatch: pytest.MonkeyPatch, owner_engine: AsyncEngine
) -> None:
    reg = await register()
    case_id = await _new_case(reg)
    assert (await _upload(reg.client, reg.org_id, case_id, b"a" * 100)).status_code == 201
    await _set_quota(owner_engine, reg.org_id, 50)  # operator shrank it below current usage

    async def must_not_spool(*args: object, **kwargs: object) -> None:
        raise AssertionError("the body must not be read")

    monkeypatch.setattr(uploads, "spool", must_not_spool)
    response = await _upload(reg.client, reg.org_id, case_id, _chunked(b"b"))
    assert _code(response) == (413, "storage_quota_exceeded")


async def test_storage_route_rbac() -> None:
    owner = await register()
    viewer_email = unique_email("viewer")
    viewer_id = await make_user(viewer_email)
    await add_member(owner.org_id, viewer_id, MemberRole.VIEWER)
    viewer = await login(viewer_email)
    response = await viewer.get(f"/api/v1/orgs/{owner.org_id}/storage")
    assert response.status_code == 200  # org.read: every member sees the org's usage

    outsider = await register()
    assert (await outsider.client.get(f"/api/v1/orgs/{owner.org_id}/storage")).status_code == 404


async def test_org_patch_cannot_change_the_quota(owner_engine: AsyncEngine) -> None:
    reg = await register()
    await _set_quota(owner_engine, reg.org_id, 1000)
    response = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}",
        json={"name": "Renamed", "storage_quota_bytes": 10 * 1024**4},
        headers=csrf(reg.client),
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Renamed"
    assert "storage_quota_bytes" not in response.json()
    assert (await _storage(reg))["quota_bytes"] == 1000


async def test_app_role_cannot_write_the_quota_column(owner_engine: AsyncEngine) -> None:
    reg = await register()
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(reg.org_id, reg.user_id) as session:
            await session.execute(
                text("UPDATE organizations SET storage_quota_bytes = 1 WHERE id = :org"),
                {"org": reg.org_id},
            )
    new_org = uuid.uuid4()
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(new_org, reg.user_id) as session:
            await session.execute(
                text(
                    "INSERT INTO organizations (id, name, slug, created_by, storage_quota_bytes) "
                    "VALUES (:id, 'Big', :slug, :user, 1)"
                ),
                {"id": new_org, "slug": f"big-{new_org}", "user": reg.user_id},
            )

    query = text(
        "SELECT column_name, privilege_type FROM information_schema.column_privileges "
        "WHERE grantee = 'cyberlab_app' AND table_name = 'organizations' "
        "AND privilege_type IN ('INSERT', 'UPDATE')"
    )
    async with owner_engine.connect() as conn:
        granted = {(c, p) for c, p in (await conn.execute(query)).all()}
    assert {c for c, p in granted if p == "UPDATE"} == {"name", "next_case_number", "updated_at"}
    insertable = {c for c, p in granted if p == "INSERT"}
    assert "storage_quota_bytes" not in insertable and "name" in insertable


async def test_a_user_may_own_at_most_five_orgs() -> None:
    reg = await register()  # registration creates the first owned org
    for i in range(4):
        created = await reg.client.post(
            "/api/v1/orgs", json={"name": f"Org {i}"}, headers=csrf(reg.client)
        )
        assert created.status_code == 201, created.text
    sixth = await reg.client.post("/api/v1/orgs", json={"name": "Org 6"}, headers=csrf(reg.client))
    assert _code(sixth) == (409, "org_limit_reached")
    assert (await reg.client.get("/api/v1/orgs")).json()["total"] == 5


async def test_owned_org_limit_counts_only_owner_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "max_owned_orgs_per_user", 2)
    other = await register()
    reg = await register()
    await add_member(other.org_id, reg.user_id, MemberRole.ADMIN)  # member, not owner
    created = await reg.client.post("/api/v1/orgs", json={"name": "Two"}, headers=csrf(reg.client))
    assert created.status_code == 201
    third = await reg.client.post("/api/v1/orgs", json={"name": "Three"}, headers=csrf(reg.client))
    assert _code(third) == (409, "org_limit_reached")


async def test_concurrent_org_creates_respect_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "max_owned_orgs_per_user", 2)
    reg = await register()
    responses = await asyncio.gather(
        *(
            reg.client.post("/api/v1/orgs", json={"name": f"Race {i}"}, headers=csrf(reg.client))
            for i in range(3)
        )
    )
    assert sorted(r.status_code for r in responses) == [201, 409, 409]
