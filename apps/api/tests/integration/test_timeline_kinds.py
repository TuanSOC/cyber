"""Case timeline `status` and `note` entries and the `kinds` filter (M6 phase 5, RT10).

Status changes and notes opted into reports are case events (`evidence_id` and `job_id`
null). A note sits at the time of its first version (RT32) with its current text cut to
280 characters; deleted and not-included notes are absent. The sort key and the cursor
format are unchanged, so paging stays stable across the new kinds.
"""

import uuid
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import select, update

from app.core.tenancy import tenant_session
from app.modules.ai.context import select as ai_select
from app.modules.analysis import dispatch
from app.modules.investigations import timeline
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from tests.analysis_helpers import SentJobs, new_case, upload
from tests.case_helpers import seed_case, seed_note, seed_status_event
from tests.factories import Registered, register
from tests.integration.seed import Tenant

API = "/api/v1/orgs"
LONG = "Final text " + "x" * 400
NOTE = timeline.RefKindName.NOTE


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _get(reg: Registered, case_id: uuid.UUID, params: Any = None) -> Any:
    response = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{case_id}/timeline", params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


def _key(entry: dict[str, Any]) -> tuple[datetime, str, str]:
    return (datetime.fromisoformat(entry["ts"]), entry["kind"], entry["ref_id"])


async def _edit_note(t: Tenant, note_id: uuid.UUID, body: str) -> None:
    """A second version, written in a later transaction than the first."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            AnalystNoteVersion(
                note_id=note_id,
                version=2,
                organization_id=t.org_id,
                body=body,
                refs=[],
                author_id=t.owner_id,
            )
        )
        await s.flush()
        await s.execute(
            update(AnalystNote).where(AnalystNote.id == note_id).values(current_version=2)
        )


async def _seeded_case(reg: Registered) -> tuple[Tenant, dict[str, uuid.UUID]]:
    case_id = uuid.UUID(await new_case(reg))
    await upload(reg.client, reg.org_id, str(case_id), b"kinds evidence", "k.bin")
    t = Tenant(reg.org_id, reg.user_id, case_id)
    ids = {
        "opened": await seed_status_event(t, from_status=None, to_status="open"),
        "progress": await seed_status_event(t, reason="Escalated to IR"),
        "note": await seed_note(t, bodies=("First draft",), include_in_reports=True),
        "private": await seed_note(t, bodies=("Not for reports",)),
        "deleted": await seed_note(t, bodies=("Deleted",), include_in_reports=True, deleted=True),
    }
    await _edit_note(t, ids["note"], LONG)
    return t, ids


async def test_status_and_note_entries_are_case_events_in_order(sent: SentJobs) -> None:
    reg = await register()
    t, ids = await _seeded_case(reg)
    items = (await _get(reg, t.investigation_id, {"limit": 500}))["items"]
    assert items == sorted(items, key=_key)
    by_ref = {e["ref_id"]: e for e in items}
    assert str(ids["private"]) not in by_ref and str(ids["deleted"]) not in by_ref

    opened, progress = by_ref[str(ids["opened"])], by_ref[str(ids["progress"])]
    assert opened["title"] == "Status set to open"
    assert progress["title"] == "Status changed from open to in progress: Escalated to IR"
    for entry in (opened, progress):
        assert entry["kind"] == "status_changed" and entry["ref_kind"] == "status"
        assert entry["evidence_id"] is None and entry["job_id"] is None
        assert entry["ts_source"] == "recorded" and entry["severity"] is None

    note = by_ref[str(ids["note"])]
    assert (note["kind"], note["ref_kind"]) == ("note", "note")
    assert note["evidence_id"] is None and note["job_id"] is None
    # The current text, cut to 280 characters, at the time of the first version (RT32).
    assert len(note["title"]) == timeline.CASE_TEXT_MAX
    assert note["title"] == LONG[: timeline.CASE_TEXT_MAX - 1] + "…"
    async with tenant_session(t.org_id, t.owner_id) as s:
        first, second = (
            await s.scalars(
                select(AnalystNoteVersion.created_at)
                .where(AnalystNoteVersion.note_id == ids["note"])
                .order_by(AnalystNoteVersion.version)
            )
        ).all()
    assert first < second
    assert datetime.fromisoformat(note["ts"]) == first

    # The evidence entries keep their evidence id.
    upload_entry = next(e for e in items if e["kind"] == "custody_uploaded")
    assert upload_entry["evidence_id"] is not None


async def test_kinds_filter(sent: SentJobs) -> None:
    reg = await register()
    t, ids = await _seeded_case(reg)
    everything = (await _get(reg, t.investigation_id, {"limit": 500}))["items"]
    assert {"custody", "job", "status", "note"} <= {e["ref_kind"] for e in everything}

    notes = (await _get(reg, t.investigation_id, {"kinds": "note"}))["items"]
    assert [e["ref_id"] for e in notes] == [str(ids["note"])]
    mixed = (await _get(reg, t.investigation_id, [("kinds", "status"), ("kinds", "custody")]))[
        "items"
    ]
    assert {e["ref_kind"] for e in mixed} == {"status", "custody"}
    assert mixed == [e for e in everything if e["ref_kind"] in {"status", "custody"}]
    jobs = (await _get(reg, t.investigation_id, {"kinds": "job"}))["items"]
    assert jobs and all(e["ref_kind"] == "job" for e in jobs)
    assert (await _get(reg, t.investigation_id, {"kinds": "alert"}))["items"] == []


async def test_cursor_paging_is_stable_across_the_new_kinds(sent: SentJobs) -> None:
    reg = await register()
    t, _ = await _seeded_case(reg)
    for kinds in (None, [("kinds", "note"), ("kinds", "status"), ("kinds", "custody")]):
        everything = (await _get(reg, t.investigation_id, [("limit", 500), *(kinds or [])]))[
            "items"
        ]
        seen: list[dict[str, Any]] = []
        cursor = None
        while True:
            params: list[tuple[str, Any]] = [("limit", 2), *(kinds or [])]
            if cursor:
                params.append(("cursor", cursor))
            page = await _get(reg, t.investigation_id, params)
            assert len(page["items"]) <= 2
            seen.extend(page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert seen == everything and len(seen) >= 4


async def _bare_case(reg: Registered) -> Tenant:
    """A case seeded without routes: no events of its own."""
    case_id = await seed_case(Tenant(reg.org_id, reg.user_id, uuid.uuid4()))
    return Tenant(reg.org_id, reg.user_id, case_id)


async def test_a_long_status_reason_is_cut() -> None:
    reg = await register()
    t = await _bare_case(reg)
    case_id = t.investigation_id
    await seed_status_event(t, from_status="in_progress", to_status="closed", reason="r" * 500)
    [entry] = (await _get(reg, case_id))["items"]
    prefix = "Status changed from in progress to closed: "
    assert entry["title"].startswith(prefix)
    reason = entry["title"].removeprefix(prefix)
    assert len(reason) == timeline.CASE_TEXT_MAX and reason.endswith("…")


async def test_count_and_page_agree_for_case_events() -> None:
    reg = await register()
    t = await _bare_case(reg)
    case_id = t.investigation_id
    await seed_status_event(t)
    await seed_note(t, include_in_reports=True)
    async with tenant_session(t.org_id, t.owner_id) as s:
        entries = await timeline.page(s, t.org_id, case_id, limit=50)
        total = await timeline.count(s, t.org_id, case_id)
        only_notes = await timeline.page(s, t.org_id, case_id, limit=50, kinds=[NOTE])
    assert total == len(entries) == 2
    assert [e.ref_table for e in only_notes] == ["analyst_notes"]


async def test_ai_context_never_selects_notes_or_status_reasons(sent: SentJobs) -> None:
    """Notes and status reasons are case-management text (privacy, verifier scope): the AI
    case timeline selects the five M5 evidence kinds only, and counts only those."""
    reg = await register()
    t, ids = await _seeded_case(reg)
    async with tenant_session(t.org_id, t.owner_id) as s:
        everything = await timeline.page(s, t.org_id, t.investigation_id, limit=500)
        selection = await ai_select.case_timeline_items(s, t.org_id, t.investigation_id)
    assert {"status", "note"} <= {e.ref_kind for e in everything}
    tables = {item.ref_table for item in selection.items}
    assert tables and not tables & {"analyst_notes", "investigation_status_events"}
    assert str(ids["progress"]) not in {item.ref_id for item in selection.items}
    rendered = repr([item.fields for item in selection.items])
    assert "Escalated to IR" not in rendered and "Final text" not in rendered
    case_events = sum(e.ref_kind in {"status", "note"} for e in everything)
    assert selection.total == len(everything) - case_events
