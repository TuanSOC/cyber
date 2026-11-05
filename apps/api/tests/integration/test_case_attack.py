"""ATT&CK case mappings (M6 phase 5): validation against the v20 index, duplicates, source
scope checks, audited status changes, the tactic matrix, archived cases and the role
matrix."""

import uuid
from typing import Any

from sqlalchemy import select, update

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.case_attack.labels import TACTIC_ORDER, tactic_shortnames
from app.modules.investigations.models import Investigation
from app.modules.organizations.models import MemberRole
from app.modules.static_analysis.models import MalwareCapability
from tests.case_helpers import seed_case, seed_evidence, seed_job_on, seed_mapping
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email
from tests.integration.seed import Tenant

API = "/api/v1/orgs"


async def _case(reg: Registered) -> Tenant:
    response = await reg.client.post(
        f"{API}/{reg.org_id}/investigations",
        json={"title": "ATT&CK case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 201, response.text
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(response.json()["id"]))


async def _capability(t: Tenant, investigation_id: uuid.UUID | None = None) -> tuple[str, str]:
    """A capa row on a succeeded static job of the case: (capability id, job id)."""
    evidence = await seed_evidence(t, investigation_id, filename="sample.exe")
    job = await seed_job_on(t, evidence, "static")
    async with tenant_session(t.org_id, None) as s:
        row = MalwareCapability(
            organization_id=t.org_id,
            job_id=job,
            name="inject code into another process",
            namespace="host-interaction/process/inject",
            attack=["T1055.012"],
            mbc=[],
            matches=1,
        )
        s.add(row)
        await s.flush()
        cap_id = row.id
    return str(cap_id), str(job)


async def _post(reg: Registered, t: Tenant, **body: Any) -> Any:
    return await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack",
        json=body,
        headers=csrf(reg.client),
    )


async def _patch(reg: Registered, mapping_id: str, **body: Any) -> Any:
    return await reg.client.patch(
        f"{API}/{reg.org_id}/attack-mappings/{mapping_id}", json=body, headers=csrf(reg.client)
    )


async def _get(reg: Registered, t: Tenant) -> Any:
    response = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack"
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _audit(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.action == action)
            .order_by(AuditLog.occurred_at, AuditLog.id)
        )
        return list(rows.all())


def _code(response: Any) -> tuple[int, str]:
    return response.status_code, response.json()["error"]["code"]


async def test_technique_must_be_live_in_the_v20_index() -> None:
    reg = await register()
    t = await _case(reg)
    for tid in ("T9999", "T1002", "T1026"):  # unknown, revoked (-> T1560), deprecated
        assert _code(await _post(reg, t, technique_id=tid, status="confirmed")) == (
            422,
            "invalid_technique",
        ), tid
    for body in (
        {"technique_id": "T12", "status": "confirmed"},
        {"technique_id": "T1059", "status": "maybe"},
        {"technique_id": "T1059", "status": "confirmed", "rationale": "x" * 2001},
        {"technique_id": "T1059", "status": "confirmed", "rationale": "nul\x00"},
        {
            "technique_id": "T1059",
            "status": "confirmed",
            "sources": [{"kind": "capability", "ref_id": str(uuid.uuid4())}] * 33,
        },
    ):
        assert _code(await _post(reg, t, **body)) == (422, "validation_error"), body
    assert (await _get(reg, t))["mappings"] == []


async def test_create_labels_sources_duplicate_and_audit() -> None:
    reg = await register()
    t = await _case(reg)
    cap_id, job_id = await _capability(t)
    created = await _post(
        reg,
        t,
        technique_id="T1055.012",
        status="confirmed",
        rationale="capa: inject code into another process",
        sources=[
            {"kind": "capability", "ref_id": cap_id},
            {"kind": "capability", "ref_id": cap_id},
        ],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["label"] == {
        "technique_id": "T1055.012",
        "name": "Process Hollowing",
        "tactics": ["Stealth", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1055/012",
        "revoked": False,
        "deprecated": False,
    }
    # De-duplicated, with the job id filled in from the row and a deep-link path.
    assert body["sources"] == [
        {
            "kind": "capability",
            "ref_id": cap_id,
            "job_id": job_id,
            "run_id": None,
            "path": f"/o/{reg.org_id}/malware/{job_id}?tab=capabilities&ref={cap_id}",
            "citation_status": None,
        }
    ]
    assert body["updated_by"] == str(reg.user_id) and body["updated_by_name"]

    duplicate = await _post(reg, t, technique_id="T1055.012", status="suspected")
    assert _code(duplicate) == (409, "mapping_exists")

    [log] = await _audit(reg.org_id, "case_attack.mapped")
    assert log.target_id == uuid.UUID(body["id"])
    assert log.details["technique_id"] == "T1055.012"
    assert log.details["status"] == "confirmed" and log.details["sources"] == 1

    read = await _get(reg, t)
    assert read["index_version"] == "20.0" and "MITRE" in read["notice"]
    assert [m["id"] for m in read["mappings"]] == [body["id"]]
    assert read["mappings"][0]["sources"][0]["path"] is not None


async def test_sources_are_rechecked_in_the_case_scope() -> None:
    reg = await register()
    t = await _case(reg)
    cap_id, job_id = await _capability(t)
    other_case = await seed_case(t)
    foreign_cap, _ = await _capability(t, other_case)
    stranger = await register(org_name="Stranger Org")
    stranger_case = await _case(stranger)
    stranger_cap, _ = await _capability(stranger_case)
    for source in (
        {"kind": "capability", "ref_id": foreign_cap},  # same org, another case
        {"kind": "capability", "ref_id": stranger_cap},  # another org
        {"kind": "capability", "ref_id": cap_id, "job_id": str(uuid.uuid4())},  # wrong job
        {"kind": "finding", "ref_id": cap_id},  # wrong kind
        {"kind": "capability", "ref_id": "not-a-uuid"},
        {"kind": "ai_run", "ref_id": str(uuid.uuid4())},  # no such run
    ):
        response = await _post(reg, t, technique_id="T1055", status="suspected", sources=[source])
        assert _code(response) == (422, "ref_out_of_scope"), source
    ok = await _post(
        reg,
        t,
        technique_id="T1055",
        status="suspected",
        sources=[{"kind": "capability", "ref_id": cap_id, "job_id": job_id}],
    )
    assert ok.status_code == 201, ok.text
    # PATCH re-checks too.
    bad = await _patch(
        reg, ok.json()["id"], sources=[{"kind": "capability", "ref_id": foreign_cap}]
    )
    assert _code(bad) == (422, "ref_out_of_scope")


async def test_status_changes_are_audited_from_to() -> None:
    reg = await register()
    t = await _case(reg)
    created = (await _post(reg, t, technique_id="T1059", status="suspected")).json()
    response = await _patch(reg, created["id"], status="rejected", rationale="Benign admin script")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected"
    assert response.json()["rationale"] == "Benign admin script"
    # A no-op update changes nothing and is not audited.
    same = await _patch(reg, created["id"], status="rejected")
    assert same.status_code == 200
    [log] = await _audit(reg.org_id, "case_attack.updated")
    assert log.details["changes"]["status"] == {"from": "suspected", "to": "rejected"}
    assert log.details["changes"]["rationale"] == {"changed": True}
    assert log.details["technique_id"] == "T1059"
    assert _code(await _patch(reg, created["id"])) == (422, "validation_error")
    assert (await _patch(reg, str(uuid.uuid4()), status="confirmed")).status_code == 404


async def test_matrix_groups_confirmed_and_suspected_by_v20_tactic() -> None:
    reg = await register()
    t = await _case(reg)
    for tid, status in (
        ("T1071.001", "rejected"),
        ("T1055.012", "confirmed"),
        ("T1059", "suspected"),
        ("T1055", "confirmed"),
    ):
        assert (await _post(reg, t, technique_id=tid, status=status)).status_code == 201
    body = await _get(reg, t)
    assert [m["technique_id"] for m in body["mappings"]] == [
        "T1055",
        "T1055.012",
        "T1059",
        "T1071.001",
    ]
    names = [entry["tactic"] for entry in body["matrix"]]
    assert names[:3] == ["Reconnaissance", "Resource Development", "Initial Access"]
    assert names.index("Execution") < names.index("Privilege Escalation") < names.index("Stealth")
    assert names[-1] == "Impact" and len(names) == len(TACTIC_ORDER)
    grouped = {e["tactic"]: [m["technique_id"] for m in e["techniques"]] for e in body["matrix"]}
    assert grouped["Stealth"] == ["T1055", "T1055.012"]
    assert grouped["Privilege Escalation"] == ["T1055", "T1055.012"]
    assert grouped["Execution"] == ["T1059"]
    assert grouped["Command and Control"] == []  # the rejected mapping is not in the matrix


def test_tactic_order_covers_the_index() -> None:
    assert tactic_shortnames() == list(TACTIC_ORDER)


async def test_archived_case_is_read_only() -> None:
    reg = await register()
    t = await _case(reg)
    mapping = await seed_mapping(t, technique_id="T1059")
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(Investigation)
            .where(Investigation.id == t.investigation_id)
            .values(status="archived")
        )
    assert _code(await _post(reg, t, technique_id="T1055", status="confirmed")) == (
        409,
        "investigation_archived",
    )
    assert _code(await _patch(reg, str(mapping), status="rejected")) == (
        409,
        "investigation_archived",
    )
    body = await _get(reg, t)
    assert [m["status"] for m in body["mappings"]] == ["confirmed"]


async def test_viewer_reads_but_cannot_write() -> None:
    reg = await register()
    t = await _case(reg)
    mapping = await seed_mapping(t, technique_id="T1059")
    email = unique_email("viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = Registered(await login(email), reg.user_id, reg.org_id, email, {})
    assert (await _get(viewer, t))["mappings"][0]["id"] == str(mapping)
    suggestions = await viewer.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack/suggestions"
    )
    assert suggestions.status_code == 200
    assert (await _post(viewer, t, technique_id="T1055", status="confirmed")).status_code == 403
    assert (await _patch(viewer, str(mapping), status="rejected")).status_code == 403
    assert (await _get(reg, t))["mappings"][0]["status"] == "confirmed"
