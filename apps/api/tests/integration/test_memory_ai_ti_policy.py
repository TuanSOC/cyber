"""AI and threat intel on restricted memory evidence (M8 phase 8).

No memory-specific policy code: the M6 share policy does it once the default set the flags.
- a job-scope AI preview / run on a memory job is `409 policy_blocked`
  (`evidence_ai_excluded`); the incident builder skips the job and counts the evidence;
- job-scope TI enrichment is `409 policy_blocked` (`evidence_ti_excluded`);
- the release alone changes nothing (the flags stay); release + the M6 PUT lets both through;
- the memory arm of the digest is the job's findings and IOCs only (masked text, phase 3),
  never a pcap summary (RT1).
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
from tests.factories import Registered, register
from tests.integration.seed import Tenant
from tests.integration.test_memory_sensitivity import (
    MASKED_TITLE,
    RAW_SECRET,
    memory_evidence,
    put_flags,
    release,
    release_and_clear,
    seed_memory_results,
)
from tests.memory_helpers import seed_memory_job
from tests.ti_api_helpers import capture_sends, enrich_job
from tests.ti_api_helpers import enable as enable_ti

OPTS = builder.Options(
    include_ti=False,
    include_strings=False,
    include_case_text=False,
    budget_tokens=10_000,
    max_jobs=10,
)


async def _memory_job(reg: Registered) -> tuple[Tenant, uuid.UUID, uuid.UUID]:
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    job_id = await seed_memory_job(t, evidence_id)
    await seed_memory_results(t, job_id)
    return t, evidence_id, job_id


def _code(response: Response) -> tuple[int, str | None, str | None]:
    error = response.json().get("error", {}) if response.status_code >= 400 else {}
    return response.status_code, error.get("code"), error.get("reason")


async def test_ai_on_a_restricted_memory_job_is_policy_blocked_until_release_and_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_ai_sends(monkeypatch)
    use_fake_builder(monkeypatch)
    reg = await register(org_name="Memory AI Org")
    await enable_ai(reg.client, reg.org_id)
    _, evidence_id, job_id = await _memory_job(reg)
    body = {"task": "ioc_correlation", "job_id": str(job_id)}

    for call in (preview, request_run):
        response = await call(reg.client, reg.org_id, **body)
        assert _code(response) == (409, "policy_blocked", "evidence_ai_excluded"), response.text

    # The release alone leaves the flags set: still blocked.
    assert (await release(reg.client, reg.org_id, evidence_id)).status_code == 200
    assert _code(await preview(reg.client, reg.org_id, **body))[1] == "policy_blocked"

    cleared = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
    assert cleared.status_code == 200, cleared.text
    ok = await preview(reg.client, reg.org_id, **body)
    assert ok.status_code == 200, ok.text


async def test_the_incident_builder_skips_restricted_memory_evidence() -> None:
    reg = await register(org_name="Memory Incident Org")
    t, evidence_id, job_id = await _memory_job(reg)
    async with tenant_session(t.org_id, t.owner_id) as s:
        case = await builder._case_jobs(s, t.org_id, t.investigation_id, OPTS)  # noqa: SLF001
    assert job_id not in [j.id for j in case.jobs]
    assert case.excluded == frozenset({evidence_id})

    await release_and_clear(reg, evidence_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        case = await builder._case_jobs(s, t.org_id, t.investigation_id, OPTS)  # noqa: SLF001
    assert job_id in [j.id for j in case.jobs]
    assert case.excluded == frozenset()


async def test_the_memory_digest_is_findings_and_iocs_only() -> None:
    reg = await register(org_name="Memory Digest Org")
    t, evidence_id, job_id = await _memory_job(reg)
    await release_and_clear(reg, evidence_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = await s.get(AnalysisJob, job_id)
        assert job is not None
        selections = await builder._digest_selections(s, t.org_id, job, OPTS)  # noqa: SLF001
    kinds = [sel.kind for sel in selections]
    assert kinds == [RefKind.FINDING, RefKind.IOC, RefKind.TI_RESULT]
    by_kind = {sel.kind: sel for sel in selections}
    [finding] = by_kind[RefKind.FINDING].items
    shown = " ".join(str(v) for v in finding.fields.values())
    assert MASKED_TITLE in shown and RAW_SECRET not in shown
    assert [i.ref_id for i in by_kind[RefKind.IOC].items]  # the connection IP
    assert by_kind[RefKind.TI_RESULT].items == []  # include_ti is off


async def test_job_scope_ti_is_policy_blocked_until_release_and_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = capture_sends(monkeypatch)
    reg = await register(org_name="Memory TI Org")
    await enable_ti(reg.client, reg.org_id)
    _, evidence_id, job_id = await _memory_job(reg)

    response = await enrich_job(reg.client, reg.org_id, job_id)
    assert _code(response) == (409, "policy_blocked", "evidence_ti_excluded"), response.text
    assert sent.runs == []

    await release_and_clear(reg, evidence_id)
    allowed = await enrich_job(reg.client, reg.org_id, job_id)
    assert allowed.status_code < 500, allowed.text
    assert _code(allowed)[1] != "policy_blocked", allowed.text
