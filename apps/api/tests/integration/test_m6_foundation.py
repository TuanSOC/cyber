"""M6 phase 1 plumbing: `tenant_session(snapshot_read=True)` (RT14), the unauthenticated
public signing keys route (RT22), the landed M6 routes, the timeline's `kinds` parameter
(RT10), the report-worker ACL user and the `report.rendered` ingest stub."""

import base64
import io
from datetime import UTC, datetime, timedelta

import pytest
from minio.commonconfig import GOVERNANCE
from minio.error import S3Error
from minio.retention import Retention
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.main import app
from app.modules.reports import render_ingest
from tests.factories import csrf, new_client, register
from tests.integration.seed import seed_tenant
from tests.report_helpers import (
    new_signing_keys,
    purge_reports_test_bucket,
    reports_test_bucket,
)
from tests.security import (
    idor_cases_attack,
    idor_cases_case,
    idor_cases_renders,
    idor_cases_reports,
)
from tests.storage_helpers import lane_key

# --- snapshot reads -------------------------------------------------------------------------


async def test_snapshot_read_is_repeatable_read_and_read_only() -> None:
    t = await seed_tenant("alpha")
    async with tenant_session(t.org_id, t.owner_id, snapshot_read=True) as s:
        level = (await s.execute(text("SHOW transaction_isolation"))).scalar_one()
        read_only = (await s.execute(text("SHOW transaction_read_only"))).scalar_one()
        org = (await s.execute(text("SELECT current_setting('app.org_id')"))).scalar_one()
    assert (level, read_only, org) == ("repeatable read", "on", str(t.org_id))


async def test_a_write_inside_a_snapshot_read_fails() -> None:
    t = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="read-only transaction"):
        async with tenant_session(t.org_id, t.owner_id, snapshot_read=True) as s:
            await s.execute(
                text("UPDATE investigations SET title = 'x' WHERE id = :i"),
                {"i": t.investigation_id},
            )


async def test_snapshot_read_sees_one_instant() -> None:
    t = await seed_tenant("alpha")
    async with tenant_session(t.org_id, t.owner_id, snapshot_read=True) as s:
        before = (await s.execute(text("SELECT title FROM investigations"))).scalar_one()
        async with tenant_session(t.org_id, t.owner_id) as writer:
            await writer.execute(text("UPDATE investigations SET title = 'changed meanwhile'"))
        after = (await s.execute(text("SELECT title FROM investigations"))).scalar_one()
    assert before == after != "changed meanwhile"


async def test_default_sessions_are_unchanged() -> None:
    t = await seed_tenant("alpha")
    async with tenant_session(t.org_id, t.owner_id) as s:
        level = (await s.execute(text("SHOW transaction_isolation"))).scalar_one()
        read_only = (await s.execute(text("SHOW transaction_read_only"))).scalar_one()
    assert (level, read_only) == ("read committed", "off")


# --- public signing keys (RT22) -------------------------------------------------------------


async def test_signing_keys_route_is_public_and_lists_public_keys_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = new_signing_keys("prod-report-1")
    other = new_signing_keys("old-report-0")
    settings = get_settings()
    monkeypatch.setattr(settings, "report_signing_active_kid", keys.kid)
    monkeypatch.setattr(
        settings,
        "report_signing_public_keys",
        {keys.kid: keys.public_b64, other.kid: other.public_b64},
    )
    client = new_client()  # no session
    response = await client.get("/api/v1/report-signing-keys")
    assert response.status_code == 200, response.text
    assert response.json() == {
        "keys": [
            {"kid": "old-report-0", "alg": "Ed25519", "public_key": other.public_b64,
             "active": False},
            {"kid": "prod-report-1", "alg": "Ed25519", "public_key": keys.public_b64,
             "active": True},
        ]
    }  # fmt: skip
    assert keys.private_b64 not in response.text
    assert len(base64.b64decode(keys.public_b64)) == 32


async def test_signing_keys_route_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.modules.reports import router_keys

    monkeypatch.setattr(router_keys, "KEYS_PER_IP_PER_MIN", 2)
    client = new_client(ip="10.9.9.9")
    codes = [(await client.get("/api/v1/report-signing-keys")).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


# --- M6 routes ---------------------------------------------------------------------------


def _org_routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if "{org_id}" in path
        for method in item
        if method in {"get", "post", "put", "patch", "delete"}
    }


M6_MODULES = (idor_cases_case, idor_cases_reports, idor_cases_renders, idor_cases_attack)


def test_every_m6_route_is_in_the_schema_and_none_is_pending() -> None:
    """The 40 routes frozen in phase 1 all landed: every IDOR module's `PENDING_ROUTES` is
    empty (phase 9) and each module's cases cover live routes only."""
    assert all(not module.PENDING_ROUTES for module in M6_MODULES)
    routes = frozenset().union(*(module.ROUTE_CASES for module in M6_MODULES))
    assert len(routes) >= 40
    assert routes <= _org_routes(), sorted(routes - _org_routes())


async def test_m6_routes_check_membership_first_and_validate_bodies() -> None:
    owner = await register(org_name="Stub Org")
    outsider = await register(org_name="Outsider Org")
    url = f"/api/v1/orgs/{owner.org_id}/reports"
    assert (await outsider.client.get(url)).status_code == 404
    assert (await owner.client.get(url)).status_code == 200
    created = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/investigations",
        json={"title": "Stub case", "severity": "low"},
        headers=csrf(owner.client),
    )
    case_id = created.json()["id"]
    notes = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/investigations/{case_id}/notes",
        json={"body": "hello"},
        headers=csrf(owner.client),
    )
    assert notes.status_code == 201, notes.text
    bad = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/investigations/{case_id}/notes",
        json={"body": "x" * 20_001},
        headers=csrf(owner.client),
    )
    assert bad.status_code == 422


async def test_timeline_accepts_kinds_and_case_events_have_no_evidence() -> None:
    owner = await register(org_name="Timeline Org")
    created = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/investigations",
        json={"title": "Timeline case", "severity": "low"},
        headers=csrf(owner.client),
    )
    case_id = created.json()["id"]
    base = f"/api/v1/orgs/{owner.org_id}/investigations/{case_id}/timeline"
    response = await owner.client.get(base, params=[("kinds", "note"), ("kinds", "custody")])
    assert response.status_code == 200, response.text
    assert (await owner.client.get(base, params={"kinds": "bogus"})).status_code == 422
    schema = app.openapi()["components"]["schemas"]["TimelineEntryOut"]
    assert "evidence_id" not in schema.get("required", []) or {"type": "null"} in schema[
        "properties"
    ]["evidence_id"].get("anyOf", [])


# --- ingest stub ----------------------------------------------------------------------------


async def test_report_rendered_stub_validates_and_drops(caplog: pytest.LogCaptureFixture) -> None:
    await render_ingest.handle_rendered_message({"render_id": "nope"})
    assert "invalid message dropped" in caplog.text


# --- the reports-test bucket (RT6) ----------------------------------------------------------


def test_reports_test_bucket_is_locked_and_the_api_user_cannot_delete() -> None:
    assert get_settings().reports_bucket == "reports-test"
    bucket = reports_test_bucket()
    client = get_minio()
    probe = lane_key("probe/snapshot.json")  # lane-safe cleanup (M7 phase 11)
    try:
        assert client.get_object_lock_config(bucket) is not None
        put = client.put_object(bucket, probe, io.BytesIO(b"{}"), 2)
        with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
            client.remove_object(bucket, probe, version_id=put.version_id)
        retention = Retention(GOVERNANCE, datetime.now(UTC) + timedelta(days=1))
        client.set_object_retention(bucket, probe, retention, version_id=put.version_id)
        got = client.get_object_retention(bucket, probe, version_id=put.version_id)
        assert got is not None and got.mode == GOVERNANCE
    finally:
        purge_reports_test_bucket()
