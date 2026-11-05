"""Case status reasons and status history (M6 phase 2).

- Closing, archiving and reopening need `status_reason` (1-500 characters, no NUL), else
  `422 status_reason_required`; other changes take an optional reason.
- Every status change inserts exactly one `investigation_status_events` row, atomically with
  the update; the rows refuse UPDATE and DELETE.
- `GET .../status-events` is newest first, cursor-paged, with the actor's name.
- The audit row says `has_reason`, never the reason text.
"""

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.investigations.models import InvestigationStatusEvent
from tests.factories import Registered, csrf, register
from tests.integration.test_orgs_members import org_with_roles

API = "/api/v1/orgs"


async def new_case(client: AsyncClient, org_id: uuid.UUID, title: str = "Status case") -> str:
    created = await client.post(
        f"{API}/{org_id}/investigations",
        json={"title": title, "severity": "high"},
        headers=csrf(client),
    )
    assert created.status_code == 201, created.text
    return str(created.json()["id"])


async def patch(client: AsyncClient, org_id: uuid.UUID, case_id: str, **body: Any) -> Any:
    return await client.patch(
        f"{API}/{org_id}/investigations/{case_id}", json=body, headers=csrf(client)
    )


async def move(client: AsyncClient, org_id: uuid.UUID, case_id: str, *steps: str) -> None:
    """Walk the status workflow with a reason on every step."""
    for step in steps:
        response = await patch(client, org_id, case_id, status=step, status_reason=f"to {step}")
        assert response.status_code == 200, response.text


async def events(client: AsyncClient, org_id: uuid.UUID, case_id: str, **params: Any) -> Any:
    response = await client.get(
        f"{API}/{org_id}/investigations/{case_id}/status-events", params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _event_count(reg: Registered, case_id: str) -> int:
    async with tenant_session(reg.org_id, reg.user_id) as s:
        count = await s.scalar(
            select(func.count())
            .select_from(InvestigationStatusEvent)
            .where(InvestigationStatusEvent.investigation_id == uuid.UUID(case_id))
        )
    return int(count or 0)


@pytest.mark.parametrize(
    ("steps", "last"),
    [
        ((), "closed"),
        (("in_progress",), "closed"),
        (("closed",), "archived"),
        (("closed",), "in_progress"),  # reopen
    ],
)
async def test_close_archive_and_reopen_need_a_reason(steps: tuple[str, ...], last: str) -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    await move(reg.client, reg.org_id, case_id, *steps)
    before = await _event_count(reg, case_id)

    missing = await patch(reg.client, reg.org_id, case_id, status=last)
    assert missing.status_code == 422, missing.text
    assert missing.json()["error"]["code"] == "status_reason_required"
    assert await _event_count(reg, case_id) == before  # nothing written
    current = (await reg.client.get(f"{API}/{reg.org_id}/investigations/{case_id}")).json()
    assert current["status"] == (steps[-1] if steps else "open")

    ok = await patch(reg.client, reg.org_id, case_id, status=last, status_reason="Done here")
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == last
    assert await _event_count(reg, case_id) == before + 1


async def test_starting_work_takes_an_optional_reason() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await patch(reg.client, reg.org_id, case_id, status="in_progress")
    assert response.status_code == 200, response.text
    [event] = (await events(reg.client, reg.org_id, case_id))["items"]
    assert (event["from_status"], event["to_status"], event["reason"]) == (
        "open",
        "in_progress",
        None,
    )


@pytest.mark.parametrize("reason", ["", "x" * 501, "nul\u0000byte"])
async def test_invalid_reasons_are_refused(reason: str) -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await patch(reg.client, reg.org_id, case_id, status="closed", status_reason=reason)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


async def test_a_reason_alone_is_not_an_update() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await patch(reg.client, reg.org_id, case_id, status_reason="why")
    assert response.status_code == 422


async def test_history_is_newest_first_paged_and_named() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    await move(reg.client, reg.org_id, case_id, "in_progress", "closed", "in_progress", "closed")
    page = await events(reg.client, reg.org_id, case_id)
    transitions = [(e["from_status"], e["to_status"]) for e in page["items"]]
    assert transitions == [
        ("in_progress", "closed"),
        ("closed", "in_progress"),
        ("in_progress", "closed"),
        ("open", "in_progress"),
    ]
    assert page["next_cursor"] is None
    assert {e["actor_id"] for e in page["items"]} == {str(reg.user_id)}
    assert {e["actor_name"] for e in page["items"]} == {reg.email.split("@")[0]}
    assert page["items"][0]["reason"] == "to closed"

    first = await events(reg.client, reg.org_id, case_id, limit=3)
    assert len(first["items"]) == 3 and first["next_cursor"]
    rest = await events(reg.client, reg.org_id, case_id, limit=3, cursor=first["next_cursor"])
    assert [e["id"] for e in first["items"] + rest["items"]] == [e["id"] for e in page["items"]]
    assert rest["next_cursor"] is None


async def test_bad_cursor_is_400() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{case_id}/status-events", params={"cursor": "%%%"}
    )
    assert (response.status_code, response.json()["error"]["code"]) == (400, "invalid_cursor")


async def test_no_status_change_writes_no_history() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    assert (await patch(reg.client, reg.org_id, case_id, title="Renamed case")).status_code == 200
    assert (await patch(reg.client, reg.org_id, case_id, status="open")).status_code == 200
    assert await _event_count(reg, case_id) == 0


async def test_invalid_transition_writes_nothing() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await patch(reg.client, reg.org_id, case_id, status="archived", status_reason="x")
    assert (response.status_code, response.json()["error"]["code"]) == (409, "invalid_transition")
    assert await _event_count(reg, case_id) == 0


async def test_archived_case_stays_read_only() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    await move(reg.client, reg.org_id, case_id, "closed", "archived")
    response = await patch(
        reg.client, reg.org_id, case_id, status="in_progress", status_reason="reopen"
    )
    assert (response.status_code, response.json()["error"]["code"]) == (
        409,
        "investigation_archived",
    )
    assert await _event_count(reg, case_id) == 2


async def test_audit_has_the_status_change_but_never_the_reason() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    secret = "Closing because the CFO asked"
    response = await patch(reg.client, reg.org_id, case_id, status="closed", status_reason=secret)
    assert response.status_code == 200
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "investigation.updated"}
        )
    ).json()
    details = logs["items"][0]["details"]
    assert (details["status_from"], details["status_to"], details["has_reason"]) == (
        "open",
        "closed",
        True,
    )
    assert details["changes"]["status"] == {"from": "open", "to": "closed"}
    assert secret not in str(logs)


async def test_history_rows_refuse_update_and_delete() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    await move(reg.client, reg.org_id, case_id, "closed")
    for stmt in (
        update(InvestigationStatusEvent).values(reason="rewritten"),
        delete(InvestigationStatusEvent),
    ):
        with pytest.raises(DBAPIError):
            async with tenant_session(reg.org_id, reg.user_id) as s:
                await s.execute(
                    stmt.where(InvestigationStatusEvent.investigation_id == uuid.UUID(case_id))
                )
    assert await _event_count(reg, case_id) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE investigation_status_events SET reason = 'x' WHERE investigation_id = :i",
        "DELETE FROM investigation_status_events WHERE investigation_id = :i",
    ],
)
async def test_history_rows_refuse_mutation_by_the_owner_too(
    statement: str, owner_engine: AsyncEngine
) -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    await move(reg.client, reg.org_id, case_id, "closed")
    with pytest.raises(DBAPIError, match="append-only"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.org_id', :o, true)"), {"o": str(reg.org_id)}
            )
            await conn.execute(text(statement), {"i": uuid.UUID(case_id)})


async def test_viewer_cannot_change_status_or_read_other_orgs_history() -> None:
    org = await org_with_roles()
    other = await register()
    case_id = await new_case(org.clients["analyst"], org.org_id)
    viewer = org.clients["viewer"]
    response = await patch(viewer, org.org_id, case_id, status="closed", status_reason="x")
    assert response.status_code == 403
    assert (await events(viewer, org.org_id, case_id))["items"] == []
    foreign = await other.client.get(f"{API}/{other.org_id}/investigations/{case_id}/status-events")
    assert foreign.status_code == 404
