"""Batch release of a disk job's segments (M9 phase 9, RT20).

`POST /evidence/{id}/sensitivity/release` with `job_id` (a disk `triage` / `full` job whose
segment set includes `{id}`) releases every still-restricted segment of the job in one
transaction: one acknowledgement and reason, one `disk.sensitivity_released` audit row per
item (details carry `job_id`), the share-policy flags left set (two explicit steps). Derived
evidence is never included. `404` for a job that is unknown, of another org, not a disk
analysis, or whose segments do not include the path evidence; `409` when none is left.
"""

import uuid

from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import tenant_of
from tests.case_helpers import seed_case, seed_evidence, seed_job_on
from tests.disk_helpers import seed_disk_job
from tests.factories import register
from tests.integration.seed import Tenant
from tests.integration.test_disk_sensitivity import (
    REASON,
    derived_evidence,
    disk_segments,
    release,
)
from tests.integration.test_memory_sensitivity import audit_rows, flags, member, state


async def _states(t: Tenant, ids: list[uuid.UUID]) -> list[str | None]:
    return [await state(t, e) for e in ids]


async def test_one_request_releases_every_restricted_segment() -> None:
    reg = await register(org_name="Batch Release Org")
    t = await tenant_of(reg)
    segments = await disk_segments(t, 3)
    derived = await derived_evidence(t)
    job_id = await seed_disk_job(t, segments)

    # Any segment of the set may be the path evidence.
    response = await release(reg.client, reg.org_id, segments[1], job_id=str(job_id))
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["evidence_id"], body["state"], body["source"]) == (
        str(segments[1]),
        "released",
        "disk",
    )
    assert body["release_reason"] == REASON
    assert await _states(t, segments) == ["released"] * 3
    # Two explicit steps: every flag stays set until the M6 PUT clears it.
    for segment in segments:
        assert await flags(t, segment) == (True, True)
    # Derived evidence of the case is never part of a batch.
    assert await state(t, derived) == "restricted"

    rows = await audit_rows(reg.org_id, "disk.sensitivity_released")
    assert {r.target_id for r in rows} == set(segments)
    for row in rows:
        assert row.details == {
            "from": "restricted",
            "to": "released",
            "reason": REASON,
            "acknowledged": True,
            "source": "disk",
            "job_id": str(job_id),
        }

    again = await release(reg.client, reg.org_id, segments[0], job_id=str(job_id))
    assert again.status_code == 409, again.text
    assert again.json()["error"]["code"] == "evidence_sensitivity_released"
    assert len(await audit_rows(reg.org_id, "disk.sensitivity_released")) == 3


async def test_already_released_segments_are_skipped() -> None:
    reg = await register(org_name="Batch Partial Org")
    t = await tenant_of(reg)
    segments = await disk_segments(t, 3)
    job_id = await seed_disk_job(t, segments)
    assert (await release(reg.client, reg.org_id, segments[0])).status_code == 200

    # The path evidence itself is already released: the others still are released.
    response = await release(reg.client, reg.org_id, segments[0], job_id=str(job_id))
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "released"
    assert await _states(t, segments) == ["released"] * 3
    rows = await audit_rows(reg.org_id, "disk.sensitivity_released")
    assert len(rows) == 3
    batch = [r for r in rows if r.details.get("job_id") == str(job_id)]
    assert {r.target_id for r in batch} == set(segments[1:])


async def test_the_batch_needs_the_acknowledgement_and_org_update() -> None:
    reg = await register(org_name="Batch Ack Org")
    t = await tenant_of(reg)
    segments = await disk_segments(t, 2)
    job_id = await seed_disk_job(t, segments)
    refused = await release(
        reg.client, reg.org_id, segments[0], job_id=str(job_id), acknowledge=False
    )
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"]["code"] == "acknowledgement_required"
    analyst = await member(reg, MemberRole.ANALYST)
    forbidden = await release(analyst, reg.org_id, segments[0], job_id=str(job_id))
    assert forbidden.status_code == 403, forbidden.text
    assert await _states(t, segments) == ["restricted"] * 2
    assert await audit_rows(reg.org_id, "disk.sensitivity_released") == []


async def test_a_job_that_does_not_cover_the_evidence_is_404() -> None:
    reg = await register(org_name="Batch 404 Org")
    t = await tenant_of(reg)
    segments = await disk_segments(t, 2)
    job_id = await seed_disk_job(t, segments)
    other_segments = await disk_segments(t, 1, stem="other")
    other_job = await seed_disk_job(t, other_segments)
    pcap_job = await seed_job_on(t, await seed_evidence(t), "pcap")
    extract_job = await seed_disk_job(t, segments, profile="extract")
    # A disk job of another case of the org (its segments are in that case).
    case_b = await seed_case(t, title="Other case")
    tb = Tenant(t.org_id, t.owner_id, case_b)
    job_b = await seed_disk_job(tb, await disk_segments(tb, 1, stem="b"))

    for job in (uuid.uuid4(), other_job, pcap_job, extract_job, job_b):
        response = await release(reg.client, reg.org_id, segments[0], job_id=str(job))
        assert response.status_code == 404, (job, response.text)
    # Evidence never marked restricted, inside a job: 404 like the single release.
    plain = await seed_evidence(t, filename="plain.E01")
    plain_job = await seed_disk_job(t, [plain])
    assert (await release(reg.client, reg.org_id, plain, job_id=str(plain_job))).status_code == 404
    unknown = await release(reg.client, reg.org_id, uuid.uuid4(), job_id=str(job_id))
    assert unknown.status_code == 404
    assert await _states(t, segments) == ["restricted"] * 2
    assert await audit_rows(reg.org_id, "disk.sensitivity_released") == []


async def test_derived_evidence_in_a_segment_set_is_never_batch_released() -> None:
    """Defence in depth: even a derived item listed as a segment keeps its restriction."""
    reg = await register(org_name="Batch Derived Org")
    t = await tenant_of(reg)
    [segment] = await disk_segments(t, 1)
    derived = await derived_evidence(t)
    job_id = await seed_disk_job(t, [segment, derived])
    response = await release(reg.client, reg.org_id, segment, job_id=str(job_id))
    assert response.status_code == 200, response.text
    assert await state(t, segment) == "released"
    assert await state(t, derived) == "restricted"
    # Only the derived item left: nothing to release.
    again = await release(reg.client, reg.org_id, derived, job_id=str(job_id))
    assert again.status_code == 409, again.text


async def test_another_orgs_job_is_404_and_changes_nothing() -> None:
    victim = await register(org_name="Batch Victim Org")
    attacker = await register(org_name="Batch Attacker Org")
    tv = await tenant_of(victim)
    ta = await tenant_of(attacker)
    victim_segments = await disk_segments(tv, 2)
    victim_job = await seed_disk_job(tv, victim_segments)
    [own] = await disk_segments(ta, 1)

    # The attacker's own restricted evidence with the victim's job id.
    response = await release(attacker.client, attacker.org_id, own, job_id=str(victim_job))
    assert response.status_code == 404, response.text
    # The victim's evidence through the attacker's org, and through the victim's org.
    for org_id in (attacker.org_id, victim.org_id):
        hijack = await release(attacker.client, org_id, victim_segments[0], job_id=str(victim_job))
        assert hijack.status_code in (403, 404), hijack.text
    assert await _states(tv, victim_segments) == ["restricted"] * 2
    assert await state(ta, own) == "restricted"
    assert await audit_rows(victim.org_id, "disk.sensitivity_released") == []
