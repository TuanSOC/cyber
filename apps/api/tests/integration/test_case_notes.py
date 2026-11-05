"""Analyst notes (M6 phase 2): versions, refs in scope, the author rule, soft delete and
history, stale edits, archived cases."""

import asyncio
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence
from app.modules.notes.models import AnalystNoteVersion
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc, NetworkAlert, TimelineEntry
from tests.factories import Registered, csrf, register
from tests.integration.test_case_policy_api import _member
from tests.integration.test_case_status import API, move, new_case
from tests.ti_api_helpers import succeeded_job


async def create(client: AsyncClient, org_id: uuid.UUID, case_id: str, **body: Any) -> Any:
    payload = {"body": "Beacon every 60 s to 192.0.2.1", **body}
    return await client.post(
        f"{API}/{org_id}/investigations/{case_id}/notes", json=payload, headers=csrf(client)
    )


async def edit(client: AsyncClient, org_id: uuid.UUID, note_id: str, **body: Any) -> Any:
    return await client.put(f"{API}/{org_id}/notes/{note_id}", json=body, headers=csrf(client))


async def remove(client: AsyncClient, org_id: uuid.UUID, note_id: str) -> Any:
    return await client.delete(f"{API}/{org_id}/notes/{note_id}", headers=csrf(client))


async def listing(client: AsyncClient, org_id: uuid.UUID, case_id: str, **params: Any) -> Any:
    response = await client.get(f"{API}/{org_id}/investigations/{case_id}/notes", params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def _job_case(reg: Registered) -> tuple[uuid.UUID, str, str]:
    """A succeeded pcap job with results: (job id, evidence id, case id)."""
    job = await succeeded_job(reg)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        evidence_id, case_id = (
            await s.execute(
                select(Evidence.id, Evidence.investigation_id)
                .join(AnalysisJob, AnalysisJob.evidence_id == Evidence.id)
                .where(AnalysisJob.id == job)
            )
        ).one()
    return job, str(evidence_id), str(case_id)


async def _result_id(reg: Registered, model: Any, job: uuid.UUID) -> str:
    async with tenant_session(reg.org_id, reg.user_id) as s:
        found = await s.scalar(select(model.id).where(model.job_id == job).limit(1))
    assert found is not None
    return str(found)


async def test_create_list_and_get() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    created = await create(reg.client, reg.org_id, case_id, pinned=True, include_in_reports=True)
    assert created.status_code == 201, created.text
    note = created.json()
    assert (note["version"], note["edited"], note["deleted"]) == (1, False, False)
    assert (note["pinned"], note["include_in_reports"]) == (True, True)
    assert note["created_by"] == note["author_id"] == str(reg.user_id)
    assert note["author_name"] == reg.email.split("@")[0]
    assert note["body"] == "Beacon every 60 s to 192.0.2.1"

    page = await listing(reg.client, reg.org_id, case_id)
    assert [n["id"] for n in page["items"]] == [note["id"]]
    detail = (await reg.client.get(f"{API}/{reg.org_id}/notes/{note['id']}")).json()
    assert detail["note"] == note
    assert [v["version"] for v in detail["versions"]] == [1]

    logs = (
        await reg.client.get(f"{API}/{reg.org_id}/audit-logs", params={"action": "note.created"})
    ).json()
    details = logs["items"][0]["details"]
    assert details == {"investigation_id": case_id, "version": 1, "ref_count": 0}
    assert "Beacon" not in str(logs)


async def test_edits_keep_every_version() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id, body="v1")).json()
    second = await edit(reg.client, reg.org_id, note["id"], expected_version=1, body="v2")
    assert second.status_code == 200, second.text
    assert (second.json()["version"], second.json()["body"], second.json()["edited"]) == (
        2,
        "v2",
        True,
    )
    # A flag-only change updates the flags, without a version.
    flags = await edit(reg.client, reg.org_id, note["id"], expected_version=2, pinned=True)
    assert (flags.json()["version"], flags.json()["pinned"]) == (2, True)
    # The same body again is not a new version either.
    same = await edit(reg.client, reg.org_id, note["id"], expected_version=2, body="v2")
    assert same.json()["version"] == 2
    third = await edit(reg.client, reg.org_id, note["id"], expected_version=2, body="v3")
    assert third.json()["version"] == 3
    detail = (await reg.client.get(f"{API}/{reg.org_id}/notes/{note['id']}")).json()
    assert [(v["version"], v["body"]) for v in detail["versions"]] == [
        (3, "v3"),
        (2, "v2"),
        (1, "v1"),
    ]
    edited = (
        await reg.client.get(f"{API}/{reg.org_id}/audit-logs", params={"action": "note.edited"})
    ).json()
    assert edited["total"] == 3  # body, pinned, body (the no-op wrote nothing)
    assert "v3" not in str([i["details"] for i in edited["items"]])


async def test_stale_edit_is_409() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id)).json()
    assert (await edit(reg.client, reg.org_id, note["id"], expected_version=1, body="a")).is_success
    stale = await edit(reg.client, reg.org_id, note["id"], expected_version=1, body="b")
    assert (stale.status_code, stale.json()["error"]["code"]) == (409, "stale_note")
    future = await edit(reg.client, reg.org_id, note["id"], expected_version=9, pinned=True)
    assert future.json()["error"]["code"] == "stale_note"


async def test_concurrent_edits_on_one_version_one_wins() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id)).json()
    results = await asyncio.gather(
        *(
            edit(reg.client, reg.org_id, note["id"], expected_version=1, body=f"edit {i}")
            for i in range(5)
        )
    )
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 409, 409, 409, 409], [r.text for r in results]
    assert {r.json()["error"]["code"] for r in results if r.status_code == 409} == {"stale_note"}
    detail = (await reg.client.get(f"{API}/{reg.org_id}/notes/{note['id']}")).json()
    assert [v["version"] for v in detail["versions"]] == [2, 1]


async def test_delete_keeps_the_history_and_shows_a_tombstone() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id, body="secret v1")).json()
    await edit(reg.client, reg.org_id, note["id"], expected_version=1, body="secret v2")
    deleted = await remove(reg.client, reg.org_id, note["id"])
    assert deleted.status_code == 204
    assert (await remove(reg.client, reg.org_id, note["id"])).status_code == 204  # idempotent

    assert (await listing(reg.client, reg.org_id, case_id))["items"] == []
    [tomb] = (await listing(reg.client, reg.org_id, case_id, include_deleted=True))["items"]
    assert (tomb["deleted"], tomb["body"], tomb["refs"], tomb["version"]) == (True, None, [], 2)
    assert tomb["deleted_by"] == str(reg.user_id) and tomb["deleted_at"]
    detail = (await reg.client.get(f"{API}/{reg.org_id}/notes/{note['id']}")).json()
    assert detail["note"]["body"] is None
    assert [v["body"] for v in detail["versions"]] == ["secret v2", "secret v1"]
    gone = await edit(reg.client, reg.org_id, note["id"], expected_version=2, body="v3")
    assert (gone.status_code, gone.json()["error"]["code"]) == (409, "note_deleted")
    logs = (
        await reg.client.get(f"{API}/{reg.org_id}/audit-logs", params={"action": "note.deleted"})
    ).json()
    assert logs["total"] == 1


async def test_only_the_author_or_an_admin_changes_a_note() -> None:
    reg = await register()  # owner (org.update)
    case_id = await new_case(reg.client, reg.org_id)
    author = await _member(reg, "analyst")
    colleague = await _member(reg, "analyst")
    viewer = await _member(reg, "viewer")
    note = (await create(author, reg.org_id, case_id)).json()

    assert (
        await edit(colleague, reg.org_id, note["id"], expected_version=1, body="x")
    ).status_code == 403
    assert (await remove(colleague, reg.org_id, note["id"])).status_code == 403
    assert (
        await edit(viewer, reg.org_id, note["id"], expected_version=1, body="x")
    ).status_code == 403
    assert (await create(viewer, reg.org_id, case_id)).status_code == 403
    assert (await viewer.get(f"{API}/{reg.org_id}/notes/{note['id']}")).status_code == 200

    by_author = await edit(author, reg.org_id, note["id"], expected_version=1, body="author")
    assert by_author.status_code == 200
    by_admin = await edit(reg.client, reg.org_id, note["id"], expected_version=2, body="admin")
    assert by_admin.status_code == 200
    assert by_admin.json()["author_id"] == str(reg.user_id)  # the version's author
    assert by_admin.json()["created_by"] == note["created_by"]
    assert (await remove(reg.client, reg.org_id, note["id"])).status_code == 204


async def test_refs_in_the_case_scope_are_accepted() -> None:
    reg = await register()
    job, evidence_id, case_id = await _job_case(reg)
    refs = [
        {"kind": "evidence", "ref_id": evidence_id},
        {"kind": "job", "ref_id": str(job)},
        {"kind": "ioc", "ref_id": await _result_id(reg, Ioc, job), "job_id": str(job)},
        {"kind": "finding", "ref_id": await _result_id(reg, AnalysisFinding, job)},
        {"kind": "alert", "ref_id": await _result_id(reg, NetworkAlert, job)},
        {"kind": "timeline", "ref_id": await _result_id(reg, TimelineEntry, job)},
    ]
    created = await create(reg.client, reg.org_id, case_id, refs=refs)
    assert created.status_code == 201, created.text
    assert created.json()["refs"] == [{"job_id": None, **r} for r in refs]
    logs = (
        await reg.client.get(f"{API}/{reg.org_id}/audit-logs", params={"action": "note.created"})
    ).json()
    assert logs["items"][0]["details"]["ref_count"] == len(refs)


async def test_refs_out_of_scope_are_refused() -> None:
    reg = await register()
    other = await register()
    job, evidence_id, case_id = await _job_case(reg)
    other_job, other_evidence, _ = await _job_case(reg)  # another case of the same org
    foreign_job, foreign_evidence, _ = await _job_case(other)
    ioc = await _result_id(reg, Ioc, job)
    bad_refs = [
        {"kind": "evidence", "ref_id": other_evidence},
        {"kind": "job", "ref_id": str(other_job)},
        {"kind": "ioc", "ref_id": await _result_id(reg, Ioc, other_job)},
        {"kind": "evidence", "ref_id": foreign_evidence},
        {"kind": "job", "ref_id": str(foreign_job)},
        {"kind": "finding", "ref_id": str(uuid.uuid4())},
        {"kind": "ioc", "ref_id": ioc, "job_id": str(other_job)},  # wrong job
        {"kind": "alert", "ref_id": ioc},  # an IOC id is not an alert
        {"kind": "capability", "ref_id": "not-a-uuid"},
        {"kind": "evidence", "ref_id": evidence_id, "job_id": str(job)},
    ]
    for ref in bad_refs:
        response = await create(reg.client, reg.org_id, case_id, refs=[ref])
        assert response.status_code == 422, (ref, response.text)
        assert response.json()["error"]["code"] == "ref_out_of_scope"
        assert response.json()["error"]["index"] == 0
    note = (await create(reg.client, reg.org_id, case_id)).json()
    response = await edit(
        reg.client, reg.org_id, note["id"], expected_version=1, refs=[bad_refs[0]]
    )
    assert response.json()["error"]["code"] == "ref_out_of_scope"
    assert (await listing(reg.client, reg.org_id, case_id))["items"][0]["version"] == 1


@pytest.mark.parametrize(
    "body",
    [
        {"body": ""},
        {"body": "x" * 20_001},
        {"body": "nul\u0000"},
        {"body": "ok", "refs": [{"kind": "flow", "ref_id": "x"}]},
        {"body": "ok", "refs": [{"kind": "job", "ref_id": "a b"}]},
        {"body": "ok", "refs": [{"kind": "job", "ref_id": "x"}] * 21},
        {"body": "ok", "author": "someone"},
    ],
)
async def test_invalid_bodies_are_422(body: dict[str, Any]) -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{case_id}/notes", json=body, headers=csrf(reg.client)
    )
    assert (response.status_code, response.json()["error"]["code"]) == (422, "validation_error")


async def test_list_filters_and_pages() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    ids = [
        (await create(reg.client, reg.org_id, case_id, body=f"n{i}", pinned=i % 2 == 0)).json()[
            "id"
        ]
        for i in range(5)
    ]
    newest_first = list(reversed(ids))
    page = await listing(reg.client, reg.org_id, case_id)
    assert [n["id"] for n in page["items"]] == newest_first
    pinned = await listing(reg.client, reg.org_id, case_id, pinned=True)
    assert [n["id"] for n in pinned["items"]] == [ids[4], ids[2], ids[0]]
    first = await listing(reg.client, reg.org_id, case_id, limit=2)
    second = await listing(reg.client, reg.org_id, case_id, limit=2, cursor=first["next_cursor"])
    third = await listing(reg.client, reg.org_id, case_id, limit=2, cursor=second["next_cursor"])
    assert [n["id"] for n in first["items"] + second["items"] + third["items"]] == newest_first
    assert third["next_cursor"] is None
    # Another case's notes are not listed.
    other_case = await new_case(reg.client, reg.org_id, title="Other case")
    assert (await listing(reg.client, reg.org_id, other_case))["items"] == []


async def test_notes_of_an_archived_case_are_read_only() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id)).json()
    await move(reg.client, reg.org_id, case_id, "closed", "archived")
    for response in (
        await create(reg.client, reg.org_id, case_id),
        await edit(reg.client, reg.org_id, note["id"], expected_version=1, body="x"),
        await remove(reg.client, reg.org_id, note["id"]),
    ):
        assert (response.status_code, response.json()["error"]["code"]) == (
            409,
            "investigation_archived",
        )
    assert len((await listing(reg.client, reg.org_id, case_id))["items"]) == 1


async def test_notes_are_tenant_scoped() -> None:
    reg = await register()
    other = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id)).json()
    for org_id in (reg.org_id, other.org_id):
        assert (await other.client.get(f"{API}/{org_id}/notes/{note['id']}")).status_code == 404
        assert (
            await edit(other.client, org_id, note["id"], expected_version=1, body="x")
        ).status_code == 404
        assert (await remove(other.client, org_id, note["id"])).status_code == 404
        assert (await create(other.client, org_id, case_id)).status_code == 404
    assert (await reg.client.get(f"{API}/{reg.org_id}/notes/{uuid.uuid4()}")).status_code == 404


async def test_version_rows_refuse_update_in_the_db(owner_engine: AsyncEngine) -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    note = (await create(reg.client, reg.org_id, case_id, body="original")).json()
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(reg.org_id, reg.user_id) as s:
            await s.execute(
                text("UPDATE analyst_note_versions SET body = 'forged' WHERE note_id = :n"),
                {"n": uuid.UUID(note["id"])},
            )
    for statement in (
        "UPDATE analyst_note_versions SET body = 'forged' WHERE note_id = :n",
        "DELETE FROM analyst_note_versions WHERE note_id = :n",
    ):
        with pytest.raises(DBAPIError, match="append-only"):
            async with owner_engine.begin() as conn:
                await conn.execute(
                    text("SELECT set_config('app.org_id', :o, true)"), {"o": str(reg.org_id)}
                )
                await conn.execute(text(statement), {"n": uuid.UUID(note["id"])})
    async with tenant_session(reg.org_id, reg.user_id) as s:
        body = await s.scalar(
            select(AnalystNoteVersion.body).where(
                AnalystNoteVersion.note_id == uuid.UUID(note["id"])
            )
        )
    assert body == "original"
