"""AI and threat intel on restricted disk evidence (M9 phase 9).

The M6 share policy does it once the default set the flags; a disk job maps to **every**
segment of its set (`investigations.policy.load_policy`), so one excluded segment blocks it:
- a job-scope AI preview / run on a disk job is `409 policy_blocked` (`evidence_ai_excluded`),
  still blocked while any segment stays excluded, allowed once every segment is released and
  cleared;
- the incident builder skips the job while any segment is excluded (`policy_excluded`);
- job-scope TI enrichment is `409 policy_blocked` (`evidence_ti_excluded`);
- the disk arm of the digest is the job's findings and IOCs only (masked text), never file
  listings or events (RT1).
"""

import uuid

import pytest
from httpx import Response

from app.core.tenancy import tenant_session
from app.modules.ai.context import builder
from app.modules.ai.contracts import RefKind
from app.modules.analysis.models import AnalysisJob
from tests.ai_api_helpers import (
    capture_ai_sends,
    enable_ai,
    preview,
    request_run,
    tenant_of,
    use_fake_builder,
)
from tests.case_helpers import seed_evidence, seed_job_on
from tests.disk_helpers import seed_disk_job
from tests.factories import Registered, register
from tests.integration.seed import Tenant
from tests.integration.test_disk_sensitivity import (
    MASKED_TITLE,
    RAW_SECRET,
    disk_segments,
    release,
    release_and_clear,
    seed_disk_results,
)
from tests.integration.test_memory_sensitivity import put_flags
from tests.ti_api_helpers import capture_sends, enrich_job
from tests.ti_api_helpers import enable as enable_ti

OPTS = builder.Options(
    include_ti=False,
    include_strings=False,
    include_case_text=False,
    budget_tokens=10_000,
    max_jobs=10,
)


async def _disk_job(reg: Registered, n: int = 2) -> tuple[Tenant, list[uuid.UUID], uuid.UUID]:
    t = await tenant_of(reg)
    segments = await disk_segments(t, n)
    job_id = await seed_disk_job(t, segments)  # with the fixture's file listing and events
    await seed_disk_results(t, job_id)
    return t, segments, job_id


def _code(response: Response) -> tuple[int, str | None, str | None]:
    error = response.json().get("error", {}) if response.status_code >= 400 else {}
    return response.status_code, error.get("code"), error.get("reason")


async def test_ai_on_a_restricted_disk_job_is_blocked_until_every_segment_is_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_ai_sends(monkeypatch)
    use_fake_builder(monkeypatch)
    reg = await register(org_name="Disk AI Org")
    await enable_ai(reg.client, reg.org_id)
    _, segments, job_id = await _disk_job(reg)
    body = {"task": "ioc_correlation", "job_id": str(job_id)}

    for call in (preview, request_run):
        response = await call(reg.client, reg.org_id, **body)
        assert _code(response) == (409, "policy_blocked", "evidence_ai_excluded"), response.text

    # The batch release alone leaves every flag set: still blocked.
    released = await release(reg.client, reg.org_id, segments[0], job_id=str(job_id))
    assert released.status_code == 200, released.text
    assert _code(await preview(reg.client, reg.org_id, **body))[1] == "policy_blocked"

    # Segment 0 (the job's `evidence_id`) cleared, segment 1 still excluded: blocked.
    cleared = await put_flags(reg.client, reg.org_id, segments[0], ai=False, ti=False)
    assert cleared.status_code == 200, cleared.text
    blocked = await preview(reg.client, reg.org_id, **body)
    assert _code(blocked) == (409, "policy_blocked", "evidence_ai_excluded"), blocked.text

    cleared = await put_flags(reg.client, reg.org_id, segments[1], ai=False, ti=False)
    assert cleared.status_code == 200, cleared.text
    ok = await preview(reg.client, reg.org_id, **body)
    assert ok.status_code == 200, ok.text


async def test_the_incident_builder_skips_a_disk_job_with_an_excluded_segment() -> None:
    reg = await register(org_name="Disk Incident Org")
    t, segments, job_id = await _disk_job(reg)
    pcap_job = await seed_job_on(t, await seed_evidence(t), "pcap")

    async def case_jobs() -> list[uuid.UUID]:
        async with tenant_session(t.org_id, t.owner_id) as s:
            case = await builder._case_jobs(s, t.org_id, t.investigation_id, OPTS)  # noqa: SLF001
        return [j.id for j in case.jobs]

    assert await case_jobs() == [pcap_job]
    # Only segment 0 (the job's `evidence_id`) released and cleared: segment 1 still
    # excludes the job.
    await release_and_clear(reg, segments[:1])
    assert await case_jobs() == [pcap_job]

    await release_and_clear(reg, segments[1:])
    assert set(await case_jobs()) == {pcap_job, job_id}


async def test_the_disk_digest_is_findings_and_iocs_only() -> None:
    reg = await register(org_name="Disk Digest Org")
    t, segments, job_id = await _disk_job(reg)
    await release_and_clear(reg, segments)
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = await s.get(AnalysisJob, job_id)
        assert job is not None
        selections = await builder._digest_selections(s, t.org_id, job, OPTS)  # noqa: SLF001
    assert [sel.kind for sel in selections] == [RefKind.FINDING, RefKind.IOC, RefKind.TI_RESULT]
    by_kind = {sel.kind: sel for sel in selections}
    [finding] = by_kind[RefKind.FINDING].items
    shown = " ".join(str(v) for v in finding.fields.values())
    assert MASKED_TITLE in shown and RAW_SECRET not in shown
    assert [i.ref_id for i in by_kind[RefKind.IOC].items]
    assert by_kind[RefKind.TI_RESULT].items == []  # include_ti is off


async def test_job_scope_ti_is_policy_blocked_until_release_and_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = capture_sends(monkeypatch)
    reg = await register(org_name="Disk TI Org")
    await enable_ti(reg.client, reg.org_id)
    _, segments, job_id = await _disk_job(reg)

    response = await enrich_job(reg.client, reg.org_id, job_id)
    assert _code(response) == (409, "policy_blocked", "evidence_ti_excluded"), response.text
    assert sent.runs == []

    await release_and_clear(reg, segments)
    allowed = await enrich_job(reg.client, reg.org_id, job_id)
    assert allowed.status_code < 500, allowed.text
    assert _code(allowed)[1] != "policy_blocked", allowed.text
