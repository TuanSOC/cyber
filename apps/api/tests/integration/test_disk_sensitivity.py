"""Disk sensitivity (M9 phase 9, RT2): TLP:RED by default for disk images and derived evidence.

- `apply_restricted_default(..., source="disk" | "derived")` marks evidence `restricted` with
  its source and sets both share-policy flags (never loosening), audits
  `disk.sensitivity_defaulted` once (details carry `source`) and is idempotent; a released
  row stays released;
- a `kind=disk` upload is restricted before any job, and the first disk job restricts every
  segment (phase 7's call sites: skipped until they land in this lane);
- the generic release (`org.update`, acknowledged, reasoned, once) audits
  `disk.sensitivity_released`; a released image does not release a file derived from it
  (each item is released on its own, a recorded decision).

The module also holds the phase-9 helpers of the other `test_disk_*` modules.
"""

import inspect
import secrets
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Literal

import pytest
from httpx import AsyncClient, Response

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.evidence import sensitivity, uploads
from app.modules.memory_analysis.models import MemorySensitivity
from app.modules.organizations.models import MemberRole
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from tests.ai_api_helpers import tenant_of
from tests.analysis_helpers import new_case, upload
from tests.case_helpers import seed_evidence, set_evidence_policy
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant
from tests.integration.test_memory_sensitivity import (
    audit_rows,
    flags,
    member,
    put_flags,
    state,
)

API = "/api/v1/orgs"
REASON = "Legal approved the triage of this disk image for case work"
# A worker-masked secret as it lands in a disk finding (`cyberlab_worker.mask`).
MASKED_TITLE = "Credential in shell history: export AWS_SECRET_ACCESS_KEY=wJ******"
RAW_SECRET = "wJalrXUtnFEMI"

# --- helpers (shared with the other test_disk_* modules) ------------------------------------


async def apply_disk_default(
    t: Tenant, evidence_id: uuid.UUID, source: Literal["disk", "derived"] = "disk"
) -> bool:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return await sensitivity.apply_restricted_default(
            s, t.org_id, evidence_id, t.owner_id, source
        )


async def disk_segments(
    t: Tenant, n: int = 2, investigation_id: uuid.UUID | None = None, *, stem: str = "image"
) -> list[uuid.UUID]:
    """`n` evidence items of the case defaulted to restricted (source `disk`), as the first
    disk job over them would leave them."""
    out = []
    for i in range(n):
        evidence_id = await seed_evidence(t, investigation_id, filename=f"{stem}.E{i + 1:02d}")
        assert await apply_disk_default(t, evidence_id)
        out.append(evidence_id)
    return out


async def derived_evidence(t: Tenant, investigation_id: uuid.UUID | None = None) -> uuid.UUID:
    """A file exported from a restricted image, as phase 10's promote leaves it."""
    evidence_id = await seed_evidence(t, investigation_id, filename="dropper.exe")
    assert await apply_disk_default(t, evidence_id, "derived")
    return evidence_id


async def seed_disk_results(
    t: Tenant,
    job_id: uuid.UUID,
    *,
    findings: Sequence[tuple[str, str]] = (("high", MASKED_TITLE),),
    iocs: Sequence[tuple[str, str]] = (("ip", "198.51.100.23"),),
) -> list[uuid.UUID]:
    """Findings (severity, title) and IOCs (type, value) of a disk job, as the ingest writes
    them. Returns the finding row ids."""
    now = datetime.now(UTC)
    rows: list[AnalysisFinding] = []
    async with tenant_session(t.org_id, t.owner_id) as s:
        for severity, title in findings:
            row = AnalysisFinding(
                organization_id=t.org_id,
                job_id=job_id,
                finding_id=uuid.uuid4(),
                ts=now,
                type="disk_credential_in_file",
                title=title,
                description=f"{title} (/home/alice/.bash_history)",
                severity=severity,
                confidence=0.6,
                detection_method="heuristic:disk@1",
                evidence_refs=[],
                attributes={},
            )
            s.add(row)
            rows.append(row)
        for ioc_type, value in iocs:
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=now,
                    last_seen=now,
                    count=1,
                    source="disk",
                )
            )
        await s.flush()
        ids = [r.id for r in rows]
    return ids


async def release(
    client: AsyncClient, org_id: uuid.UUID, evidence_id: uuid.UUID | str, **body: object
) -> Response:
    """The generic release (`job_id` in `body` makes it a batch release, RT20)."""
    payload: dict[str, object] = {"acknowledge": True, "reason": REASON, **body}
    return await client.post(
        f"{API}/{org_id}/evidence/{evidence_id}/sensitivity/release",
        json=payload,
        headers=csrf(client),
    )


async def get_sensitivity(
    client: AsyncClient, org_id: uuid.UUID, evidence_id: uuid.UUID | str
) -> Response:
    return await client.get(f"{API}/{org_id}/evidence/{evidence_id}/sensitivity")


async def release_and_clear(reg: Registered, evidence_ids: Sequence[uuid.UUID]) -> None:
    """The two explicit steps for each item: the admin release, then the M6 PUT."""
    for evidence_id in evidence_ids:
        released = await release(reg.client, reg.org_id, evidence_id)
        assert released.status_code == 200, released.text
        cleared = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
        assert cleared.status_code == 200, cleared.text


async def source_of(t: Tenant, evidence_id: uuid.UUID) -> str | None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(MemorySensitivity, evidence_id)
        return None if row is None else row.source


# --- the default ----------------------------------------------------------------------------


@pytest.mark.parametrize("source", ["disk", "derived"])
async def test_the_default_restricts_and_excludes_once(source: Literal["disk", "derived"]) -> None:
    reg = await register(org_name=f"Disk Default {source} Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="image.E01")
    assert await state(t, evidence_id) is None and await flags(t, evidence_id) is None

    assert await apply_disk_default(t, evidence_id, source) is True
    assert await state(t, evidence_id) == "restricted"
    assert await source_of(t, evidence_id) == source
    assert await flags(t, evidence_id) == (True, True)
    [row] = await audit_rows(t.org_id, "disk.sensitivity_defaulted")
    assert (row.target_id, row.actor_id) == (evidence_id, t.owner_id)
    assert row.details["source"] == source
    assert row.details["share_policy"]["to"] == {"ai_excluded": True, "ti_excluded": True}
    assert await audit_rows(t.org_id, "memory.sensitivity_defaulted") == []

    # A second disk job (or a re-promote) changes nothing: no second audit row.
    assert await apply_disk_default(t, evidence_id, source) is False
    assert len(await audit_rows(t.org_id, "disk.sensitivity_defaulted")) == 1
    body = (await get_sensitivity(reg.client, reg.org_id, evidence_id)).json()
    assert (body["state"], body["source"]) == ("restricted", source)


async def test_the_default_never_loosens_an_existing_policy() -> None:
    reg = await register(org_name="Disk Strict Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="image.E01")
    await set_evidence_policy(t, evidence_id, ai_excluded=False, ti_excluded=True)
    assert await apply_disk_default(t, evidence_id)
    assert await flags(t, evidence_id) == (True, True)
    [row] = await audit_rows(t.org_id, "disk.sensitivity_defaulted")
    assert row.details["share_policy"]["from"] == {"ai_excluded": False, "ti_excluded": True}


async def test_a_released_row_stays_released() -> None:
    reg = await register(org_name="Disk Released Org")
    t = await tenant_of(reg)
    [segment] = await disk_segments(t, 1)
    await release_and_clear(reg, [segment])
    # A later disk job over the released segment: no new restriction, the flags stay off.
    assert await apply_disk_default(t, segment) is False
    assert await state(t, segment) == "released"
    assert await flags(t, segment) == (False, False)


async def test_the_default_keeps_the_first_source() -> None:
    """Idempotent whatever the source: a restricted memory image used again is not re-sourced."""
    reg = await register(org_name="Disk First Source Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="host.mem")
    async with tenant_session(t.org_id, t.owner_id) as s:
        assert await sensitivity.apply_restricted_default(
            s, t.org_id, evidence_id, t.owner_id, "memory"
        )
    assert await apply_disk_default(t, evidence_id) is False
    assert await source_of(t, evidence_id) == "memory"


async def test_a_disk_upload_is_restricted_before_any_job() -> None:
    if "apply_restricted_default" not in inspect.getsource(uploads):
        pytest.skip("the upload-time default is phase 7's call site (not merged in this lane)")
    reg = await register(org_name="Disk Upload Org")
    case_id = await new_case(reg)
    response = await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{case_id}/evidence",
        params={"filename": "laptop.E01", "kind": "disk"},
        content=secrets.token_bytes(64 * 1024),
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert response.status_code == 201, response.text
    evidence_id = response.json()["id"]
    jobs = await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses")
    assert jobs.json()["items"] == []  # no automatic analysis (no static `av` run, M8 RT3)
    body = (await get_sensitivity(reg.client, reg.org_id, evidence_id)).json()
    assert (body["state"], body["source"]) == ("restricted", "disk")
    policy = (
        await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy")
    ).json()
    assert (policy["ai_excluded"], policy["ti_excluded"]) == (True, True)


async def test_the_first_disk_job_restricts_every_segment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[dispatch.DispatchInput] = []

    async def capture(item: dispatch.DispatchInput) -> None:
        sent.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    reg = await register(org_name="Disk Job Default Org")
    case_id = await new_case(reg)
    segments = [
        (await upload(reg.client, reg.org_id, case_id, secrets.token_bytes(4096), name))["id"]
        for name in ("server.001", "server.002")
    ]
    job = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{segments[0]}/analyses",
        json={"analyzer": "disk", "segments": segments},
        headers=csrf(reg.client),
    )
    if job.status_code == 501:
        pytest.skip("the disk analysis request is phase 7's (not merged in this lane)")
    assert job.status_code == 201, job.text
    for evidence_id in segments:
        body = (await get_sensitivity(reg.client, reg.org_id, evidence_id)).json()
        assert (body["state"], body["source"]) == ("restricted", "disk"), evidence_id
        policy = (
            await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy")
        ).json()
        assert (policy["ai_excluded"], policy["ti_excluded"]) == (True, True)
    assert len(await audit_rows(reg.org_id, "disk.sensitivity_defaulted")) == 2


# --- the release ----------------------------------------------------------------------------


async def test_release_is_admin_only_acknowledged_once_and_audited() -> None:
    reg = await register(org_name="Disk Release Org")
    t = await tenant_of(reg)
    [segment] = await disk_segments(t, 1)

    analyst = await member(reg, MemberRole.ANALYST)
    assert (await release(analyst, reg.org_id, segment)).status_code == 403
    refused = await release(reg.client, reg.org_id, segment, acknowledge=False)
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"]["code"] == "acknowledgement_required"
    for reason in ("", "x" * 501):
        assert (await release(reg.client, reg.org_id, segment, reason=reason)).status_code == 422
    assert await state(t, segment) == "restricted"

    done = await release(reg.client, reg.org_id, segment, reason=f"  {REASON}  ")
    assert done.status_code == 200, done.text
    assert (done.json()["state"], done.json()["source"]) == ("released", "disk")
    assert done.json()["release_reason"] == REASON
    assert await flags(t, segment) == (True, True)  # two explicit steps
    [row] = await audit_rows(reg.org_id, "disk.sensitivity_released")
    assert row.target_id == segment
    assert row.details == {
        "from": "restricted",
        "to": "released",
        "reason": REASON,
        "acknowledged": True,
        "source": "disk",
    }
    assert await audit_rows(reg.org_id, "memory.sensitivity_released") == []

    again = await release(reg.client, reg.org_id, segment)
    assert again.status_code == 409, again.text
    assert again.json()["error"]["code"] == "evidence_sensitivity_released"


async def test_a_released_image_does_not_release_derived_evidence() -> None:
    reg = await register(org_name="Disk Derived Org")
    t = await tenant_of(reg)
    [segment] = await disk_segments(t, 1)
    derived = await derived_evidence(t)
    await release_and_clear(reg, [segment])
    assert await state(t, derived) == "restricted"
    assert await flags(t, derived) == (True, True)
    # The derived item is released on its own.
    done = await release(reg.client, reg.org_id, derived)
    assert done.status_code == 200, done.text
    assert (done.json()["state"], done.json()["source"]) == ("released", "derived")


async def test_another_orgs_disk_evidence_is_404() -> None:
    reg = await register(org_name="Disk Victim Org")
    other = await register(org_name="Disk Attacker Org")
    t = await tenant_of(reg)
    [segment] = await disk_segments(t, 1)
    for org_id in (other.org_id, reg.org_id):
        assert (await get_sensitivity(other.client, org_id, segment)).status_code in (403, 404)
        assert (await release(other.client, org_id, segment)).status_code in (403, 404)
    assert await state(t, segment) == "restricted"
