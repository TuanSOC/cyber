"""Case timeline export (M6 phase 5): TLP-headed, formula-safe (RT19), capped with a marker,
served as a sandboxed attachment, audited, and isolated per org."""

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.case_timeline.schemas import CSV_COLUMNS
from app.modules.organizations.models import MemberRole
from tests.case_helpers import seed_case, seed_note, seed_status_event, set_case_policy
from tests.factories import Registered, add_member, login, make_user, register, unique_email
from tests.integration.seed import Tenant

API = "/api/v1/orgs"
HOSTILE = (
    '=HYPERLINK("http://evil.example")',
    "  =1+1",
    "＝cmd|' /C calc'!A0",  # full-width equals sign
    "+SUM(A1)",
    "-2+3",
    "@SUM(A1)",
    "\tTAB",
)


async def _case(reg: Registered, *, case_number: int = 4242) -> Tenant:
    case_id = await seed_case(
        Tenant(reg.org_id, reg.user_id, uuid.uuid4()), case_number=case_number
    )
    return Tenant(reg.org_id, reg.user_id, case_id)


async def _export(reg: Registered, t: Tenant, params: Any = None) -> Any:
    return await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/timeline/export", params=params
    )


def _rows(text: str) -> tuple[str, list[list[str]]]:
    first, rest = text.split("\r\n", 1)
    return first, list(csv.reader(io.StringIO(rest)))


async def _audit(org_id: uuid.UUID) -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog)
            .where(
                AuditLog.organization_id == org_id,
                AuditLog.action == "investigation.timeline_exported",
            )
            .order_by(AuditLog.occurred_at, AuditLog.id)
        )
        return list(rows.all())


async def test_csv_is_tlp_headed_formula_safe_and_sandboxed() -> None:
    reg = await register()
    t = await _case(reg)
    for body in HOSTILE:
        await seed_note(t, bodies=(body,), include_in_reports=True)
    await seed_status_event(t, reason="=cmd()")

    response = await _export(reg, t)
    assert response.status_code == 200, response.text
    headers = response.headers
    assert headers["content-type"].startswith("text/csv")
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert headers["content-security-policy"] == "sandbox"
    disposition = headers["content-disposition"]
    assert (
        disposition.startswith("attachment;") and "CASE-04242-timeline-TLP_AMBER.csv" in disposition
    )

    first, rows = _rows(response.text)
    assert first.startswith("# TLP:AMBER CASE-04242 exported ")
    exported = datetime.fromisoformat(first.rsplit(" ", 1)[1])
    assert abs(exported - datetime.now(UTC)) < timedelta(minutes=5)
    assert tuple(rows[0]) == CSV_COLUMNS
    titles = {r[3] for r in rows[1:]}
    for body in HOSTILE:
        assert "'" + body in titles, body
    assert "Status changed from open to in progress: =cmd()" in titles  # not a leading "="
    for row in rows[1:]:
        for cell in row:
            stripped = cell.lstrip("  　\n\v\f")
            assert not stripped or stripped[0] not in "=+-@\t\r＝＋－＠", cell
    assert len(rows) == 1 + len(HOSTILE) + 1


async def test_json_export_and_tlp_and_audit() -> None:
    reg = await register()
    t = await _case(reg, case_number=7)
    await set_case_policy(t, t.investigation_id, tlp="red")
    note = await seed_note(t, bodies=("JSON note",), include_in_reports=True)
    await seed_status_event(t)
    response = await _export(reg, t, {"format": "json", "kinds": "note"})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert "CASE-00007-timeline-TLP_RED.json" in response.headers["content-disposition"]
    body = json.loads(response.content)
    assert (body["tlp"], body["case"], body["truncated"]) == ("red", "CASE-00007", False)
    assert [e["ref_id"] for e in body["entries"]] == [str(note)]
    assert body["entries"][0]["evidence_id"] is None
    # The same entries as the timeline route, in order.
    page = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/timeline",
        params={"kinds": "note"},
    )
    assert page.json()["items"] == body["entries"]

    csv_response = await _export(reg, t)
    assert csv_response.text.startswith("# TLP:RED CASE-00007 exported ")

    first, second = await _audit(reg.org_id)
    assert first.actor_id == reg.user_id and first.target_id == t.investigation_id
    assert first.details["format"] == "json" and first.details["count"] == 1
    assert first.details["truncated"] is False
    assert first.details["filters"] == {"kinds": ["note"], "from": None, "to": None}
    assert second.details["format"] == "csv" and second.details["count"] == 2


async def test_the_row_cap_adds_a_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()
    t = await _case(reg)
    for n in range(4):
        await seed_note(t, bodies=(f"note {n}",), include_in_reports=True)
    monkeypatch.setattr(get_settings(), "timeline_export_max_rows", 2)

    _, rows = _rows((await _export(reg, t)).text)
    assert len(rows) == 1 + 2 + 1
    marker = rows[-1]
    assert marker[2] == "truncated" and "capped at 2 rows" in marker[3]

    body = json.loads((await _export(reg, t, {"format": "json"})).content)
    assert body["truncated"] is True and len(body["entries"]) == 2
    logs = await _audit(reg.org_id)
    assert [(log.details["count"], log.details["truncated"]) for log in logs] == [
        (2, True),
        (2, True),
    ]


async def test_from_to_filters_and_bad_ranges() -> None:
    reg = await register()
    t = await _case(reg)
    await seed_status_event(t)
    now = datetime.now(UTC)
    past = (now - timedelta(days=1)).isoformat()
    future = (now + timedelta(days=1)).isoformat()
    inside = json.loads((await _export(reg, t, {"format": "json", "from": past})).content)
    assert len(inside["entries"]) == 1
    after = json.loads((await _export(reg, t, {"format": "json", "from": future})).content)
    assert after["entries"] == []
    before = json.loads((await _export(reg, t, {"format": "json", "to": past})).content)
    assert before["entries"] == []
    bad = await _export(reg, t, {"from": future, "to": past})
    assert (bad.status_code, bad.json()["error"]["code"]) == (422, "invalid_range")
    assert (await _export(reg, t, {"format": "xml"})).status_code == 422
    [log, *_] = await _audit(reg.org_id)
    assert log.details["filters"]["from"] is not None


async def test_cross_org_is_404_and_viewers_may_export() -> None:
    reg = await register()
    t = await _case(reg)
    attacker = await register(org_name="Attacker Org")
    for org in (reg.org_id, attacker.org_id):
        response = await attacker.client.get(
            f"{API}/{org}/investigations/{t.investigation_id}/timeline/export"
        )
        assert response.status_code == 404, response.text
    assert await _audit(attacker.org_id) == []
    assert await _audit(reg.org_id) == []

    email = unique_email("viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)
    response = await viewer.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/timeline/export"
    )
    assert response.status_code == 200, response.text
