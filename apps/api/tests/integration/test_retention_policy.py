"""The retention policy routes (M7 phase 3): floors, the delay on every loosening (lowered
values and turning `enforce` on, RT1), raises at once, the destruction acknowledgement, the
`retention_policy_index` upsert (RT3), the audit and the permissions."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.organizations.models import MemberRole
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email
from tests.integration.seed import Tenant
from tests.ops_helpers import backdate_policy

API = "/api/v1/orgs"
NULLS: dict[str, Any] = {"ti_results_days": None, "ai_runs_days": None, "closed_case_days": None}


async def _put(c: AsyncClient, org_id: uuid.UUID, **body: Any) -> Any:
    payload = {**NULLS, "enforce": False, **body}
    return await c.put(f"{API}/{org_id}/retention/policy", json=payload, headers=csrf(c))


async def _get(c: AsyncClient, org_id: uuid.UUID) -> dict[str, Any]:
    response = await c.get(f"{API}/{org_id}/retention/policy")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def _audit(org_id: uuid.UUID, action: str) -> list[dict[str, Any]]:
    async with tenant_session(org_id, None) as s:
        rows = await s.execute(
            text("SELECT details FROM audit_logs WHERE action = :a ORDER BY occurred_at, id"),
            {"a": action},
        )
        return [r for (r,) in rows.all()]


def _close(value: str | None, expected: datetime, slack: timedelta = timedelta(minutes=2)) -> bool:
    return value is not None and abs(datetime.fromisoformat(value) - expected) < slack


async def test_no_policy_keeps_everything() -> None:
    owner = await register()
    body = await _get(owner.client, owner.org_id)
    assert {k: body[k] for k in NULLS} == NULLS
    assert body["enforce"] is False and body["pending_enforce"] is False
    assert body["delay_days"] == get_settings().retention_policy_delay_days
    assert body["floors"] == {"ti_results_days": 30, "ai_runs_days": 30, "closed_case_days": 30}
    assert body["updated_by"] is None


@pytest.mark.parametrize("field", ["ti_results_days", "ai_runs_days", "closed_case_days"])
async def test_values_below_the_floor_are_refused(field: str) -> None:
    owner = await register()
    response = await _put(owner.client, owner.org_id, **{field: 29})
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "policy_floor"
    assert response.json()["error"]["fields"] == [field]
    assert (await _get(owner.client, owner.org_id))[field] is None


async def test_the_closed_case_floor_follows_the_evidence_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "evidence_lock_days", 60)
    owner = await register()
    assert (await _get(owner.client, owner.org_id))["floors"]["closed_case_days"] == 60
    assert (await _put(owner.client, owner.org_id, closed_case_days=45)).status_code == 422
    assert (await _put(owner.client, owner.org_id, closed_case_days=60)).status_code == 200


async def test_lowering_waits_for_the_delay_and_raising_applies_at_once() -> None:
    owner = await register()
    c, org = owner.client, owner.org_id
    delay = timedelta(days=get_settings().retention_policy_delay_days)

    # null -> a number is a lowering: pending.
    first = await _put(c, org, ti_results_days=90)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["ti_results_days"] is None and body["pending_ti_results_days"] == 90
    assert _close(body["effective_at"], datetime.now(UTC) + delay)
    effective_at = body["effective_at"]

    # Resubmitting the same pending value keeps its date; another field's new lowering
    # restarts the delay for everything pending (never shortens it).
    again = (await _put(c, org, ti_results_days=90)).json()
    assert again["effective_at"] == effective_at

    # Raising to null applies at once and cancels the pending lower.
    cancelled = (await _put(c, org)).json()
    assert cancelled["pending_ti_results_days"] is None and cancelled["effective_at"] is None

    # Once the delay passed the pending value is in force.
    await _put(c, org, ti_results_days=90, ai_runs_days=120)
    await backdate_policy(Tenant(org, owner.user_id, uuid.uuid4()), effective_days_ago=1)
    now_in_force = await _get(c, org)
    assert (now_in_force["ti_results_days"], now_in_force["ai_runs_days"]) == (90, 120)
    assert now_in_force["pending_ti_results_days"] is None and now_in_force["effective_at"] is None

    # Raising 90 -> 365 applies at once; lowering 120 -> 60 waits again.
    mixed = (await _put(c, org, ti_results_days=365, ai_runs_days=60)).json()
    assert mixed["ti_results_days"] == 365 and mixed["pending_ti_results_days"] is None
    assert mixed["ai_runs_days"] == 120 and mixed["pending_ai_runs_days"] == 60
    assert _close(mixed["effective_at"], datetime.now(UTC) + delay)

    changes = await _audit(org, "retention.policy_changed")
    assert len(changes) == 4  # the same-value resubmission changed nothing
    last = changes[-1]
    assert last["before"]["ti_results_days"] == 90 and last["after"]["ti_results_days"] == 365
    assert last["pending"] == {"ai_runs_days": 60}


async def test_enforce_needs_the_acknowledgement_and_waits_for_the_delay() -> None:
    owner = await register()
    c, org = owner.client, owner.org_id
    refused = await _put(c, org, closed_case_days=400, enforce=True)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "retention_acknowledgement_required"

    armed = await _put(c, org, closed_case_days=400, enforce=True, acknowledge_destruction=True)
    assert armed.status_code == 200, armed.text
    body = armed.json()
    delay = timedelta(days=get_settings().retention_policy_delay_days)
    assert body["enforce"] is False and body["pending_enforce"] is True
    assert _close(body["enforce_effective_at"], datetime.now(UTC) + delay)
    # The lowered value keeps its own date (both started now).
    assert body["pending_closed_case_days"] == 400

    # Resubmitting while pending needs no new acknowledgement and keeps the date.
    same = (await _put(c, org, closed_case_days=400, enforce=True)).json()
    assert same["enforce_effective_at"] == body["enforce_effective_at"]

    changed = await _audit(org, "retention.enforce_changed")
    assert len(changed) == 1 and changed[0]["requested"] is True
    assert datetime.fromisoformat(changed[0]["effective_at"]) == datetime.fromisoformat(
        body["enforce_effective_at"]
    )

    await backdate_policy(Tenant(org, owner.user_id, uuid.uuid4()), enforce_days_ago=1)
    assert (await _get(c, org))["enforce"] is True

    # Turning it off applies at once.
    off = (await _put(c, org, closed_case_days=400, enforce=False)).json()
    assert off["enforce"] is False and off["pending_enforce"] is False
    assert len(await _audit(org, "retention.enforce_changed")) == 2


async def test_every_put_upserts_the_policy_index() -> None:
    owner = await register()
    c, org = owner.client, owner.org_id

    async def index_time() -> datetime | None:
        async with tenant_session(None, None) as s:
            return (
                await s.execute(
                    text(
                        "SELECT updated_at FROM retention_policy_index WHERE organization_id = :o"
                    ),
                    {"o": org},
                )
            ).scalar_one_or_none()

    assert await index_time() is None
    assert (await _put(c, org)).status_code == 200  # even a no-op PUT
    first = await index_time()
    assert first is not None
    assert (await _put(c, org, ti_results_days=400)).status_code == 200
    second = await index_time()
    assert second is not None and second > first


async def test_viewers_read_but_cannot_change_the_policy() -> None:
    owner = await register()
    email = unique_email("viewer")
    viewer_id = await make_user(email)
    await add_member(owner.org_id, viewer_id, MemberRole.VIEWER)
    viewer = await login(email)
    assert (await viewer.get(f"{API}/{owner.org_id}/retention/policy")).status_code == 200
    assert (await _put(viewer, owner.org_id, ti_results_days=400)).status_code == 403
    analyst_email = unique_email("analyst")
    await add_member(owner.org_id, await make_user(analyst_email), MemberRole.ANALYST)
    analyst = await login(analyst_email)
    assert (await _put(analyst, owner.org_id, ti_results_days=400)).status_code == 403
    outsider: Registered = await register(org_name="Elsewhere")
    assert (await outsider.client.get(f"{API}/{owner.org_id}/retention/policy")).status_code == 404
