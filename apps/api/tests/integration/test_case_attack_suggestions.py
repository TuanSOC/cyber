"""ATT&CK suggestions of a case (M6 phase 5): only evidence-backed sources of the case's own
jobs (capa capabilities and finding ids of the latest jobs, AI techniques of completed runs
with a verified citation); revoked, deprecated and unknown ids are dropped; nothing is
mapped by reading them."""

import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import (
    CitationReason,
    ClaimStatus,
    ClaimVerdict,
    OutputVerification,
)
from app.modules.pcap_analysis.models import AnalysisFinding
from app.modules.static_analysis.models import MalwareCapability
from tests.ai_api_helpers import finish_run
from tests.ai_doubles import make_context
from tests.ai_helpers import seed_ai_run
from tests.case_helpers import seed_case, seed_evidence, seed_job_on, seed_mapping
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant

API = "/api/v1/orgs"


async def _case(reg: Registered) -> Tenant:
    response = await reg.client.post(
        f"{API}/{reg.org_id}/investigations",
        json={"title": "Suggestions case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 201, response.text
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(response.json()["id"]))


async def _static_job(t: Tenant, attack: list[str], case_id: uuid.UUID | None = None) -> uuid.UUID:
    evidence = await seed_evidence(t, case_id, filename="sample.exe")
    job = await seed_job_on(t, evidence, "static")
    async with tenant_session(t.org_id, None) as s:
        s.add(
            MalwareCapability(
                organization_id=t.org_id,
                job_id=job,
                name="capa rule",
                namespace="host-interaction/process/inject",
                attack=attack,
                mbc=[],
                matches=1,
            )
        )
    return job


async def _pcap_finding(t: Tenant, attributes: dict[str, Any]) -> uuid.UUID:
    evidence = await seed_evidence(t, filename="capture.pcap")
    job = await seed_job_on(t, evidence, "pcap")
    async with tenant_session(t.org_id, None) as s:
        s.add(
            AnalysisFinding(
                organization_id=t.org_id,
                job_id=job,
                finding_id=uuid.uuid4(),
                ts=datetime.now(UTC),
                type="beacon",
                title="Periodic beacon",
                description="Regular HTTPS connections",
                severity="medium",
                confidence=0.7,
                detection_method="heuristic:beacon@1",
                evidence_refs=[],
                attributes=attributes,
            )
        )
    return job


async def _ai_run(t: Tenant, job: uuid.UUID, verdicts: dict[str, ClaimStatus], status: str) -> str:
    run_id = await seed_ai_run(t, job_id=job, ctx=make_context(job_id=job))
    claims = {
        f"attack:{tid}": ClaimVerdict(
            status=verdict,
            reason=None
            if verdict is ClaimStatus.SUPPORTED
            else CitationReason.NO_VERIFIED_CITATION,
        )
        for tid, verdict in verdicts.items()
    }
    await finish_run(
        t.org_id,
        run_id,
        status=status,
        body={
            "observed": [],
            "overall_confidence": {"level": "medium", "rationale": "r"},
            "attack_techniques": [
                {"technique_id": tid, "rationale": "AI rationale", "citations": []}
                for tid in verdicts
            ],
        },
        verification=OutputVerification(claims=claims),
    )
    return str(run_id)


async def _suggestions(reg: Registered, t: Tenant) -> dict[str, Any]:
    response = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack/suggestions"
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["index_version"] == "20.0" and "MITRE" in body["notice"]
    return {s["technique_id"]: s for s in body["items"]}


async def test_suggestions_come_only_from_evidence_backed_sources_of_the_case() -> None:
    reg = await register()
    t = await _case(reg)
    # capa: a live id, a revoked one (T1002 -> T1560) and an unknown one.
    static_job = await _static_job(t, ["T1055.012", "T1002", "T9999"])
    # A finding naming a live id, a deprecated one (T1026) and a cut-off list tail.
    pcap_job = await _pcap_finding(t, {"attack": "T1071.001, T1026, T1059.0..."})
    # AI: a verified technique, an unverified one, and a verified one of a failed run.
    run_id = await _ai_run(
        t, pcap_job, {"T1059": ClaimStatus.SUPPORTED, "T1027": ClaimStatus.UNSUPPORTED}, "completed"
    )
    await _ai_run(t, pcap_job, {"T1566.001": ClaimStatus.SUPPORTED}, "failed")
    # Another case of the same org and another org: never suggested.
    other_case = await seed_case(t)
    await _static_job(t, ["T1622"], other_case)
    stranger = await register(org_name="Stranger Org")
    await _static_job(await _case(stranger), ["T1037"])

    found = await _suggestions(reg, t)
    assert sorted(found) == ["T1055.012", "T1059", "T1071.001"]
    [cap] = found["T1055.012"]["sources"]
    assert cap["kind"] == "capability" and cap["job_id"] == str(static_job)
    assert cap["path"].startswith(f"/o/{reg.org_id}/malware/{static_job}?tab=capabilities")
    [finding] = found["T1071.001"]["sources"]
    assert finding["kind"] == "finding" and finding["job_id"] == str(pcap_job)
    assert finding["path"].startswith(f"/o/{reg.org_id}/pcap/{pcap_job}?tab=findings")
    [ai] = found["T1059"]["sources"]
    assert ai == {
        "kind": "ai_run",
        "ref_id": run_id,
        "job_id": str(pcap_job),
        "run_id": run_id,
        "path": f"/o/{reg.org_id}/ai-analyst/{run_id}",
        "citation_status": "verified",
    }
    assert found["T1059"]["label"]["name"] == "Command and Scripting Interpreter"
    assert not any(s["already_mapped"] for s in found.values())

    # Reading suggestions maps nothing.
    read = await reg.client.get(f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack")
    assert read.json()["mappings"] == []

    # The suggested sources are accepted as mapping sources as they are.
    mapped = await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack",
        json={
            "technique_id": "T1059",
            "status": "confirmed",
            "sources": [
                {k: v for k, v in ai.items() if k in {"kind", "ref_id", "job_id", "run_id"}}
            ],
        },
        headers=csrf(reg.client),
    )
    assert mapped.status_code == 201, mapped.text
    assert mapped.json()["sources"][0]["path"] == ai["path"]


async def test_duplicates_merge_and_rejected_mappings_stay_visible() -> None:
    reg = await register()
    t = await _case(reg)
    await _static_job(t, ["T1055.012"])
    second = await _static_job(t, ["T1055.012", "T1622"])
    await seed_mapping(t, technique_id="T1055.012", status="rejected")
    found = await _suggestions(reg, t)
    assert sorted(found) == ["T1055.012", "T1622"]
    assert len(found["T1055.012"]["sources"]) == 2  # one technique, both capa rows
    assert found["T1055.012"]["already_mapped"] is True
    assert found["T1622"]["already_mapped"] is False
    assert found["T1622"]["sources"][0]["job_id"] == str(second)


async def test_only_the_latest_static_job_per_evidence_counts() -> None:
    reg = await register()
    t = await _case(reg)
    evidence = await seed_evidence(t, filename="sample.exe")
    for attack in (["T1622"], ["T1055"]):  # the second job is the newer one
        job = await seed_job_on(t, evidence, "static")
        async with tenant_session(t.org_id, None) as s:
            s.add(
                MalwareCapability(
                    organization_id=t.org_id,
                    job_id=job,
                    name="capa rule",
                    namespace="anti-analysis",
                    attack=attack,
                    mbc=[],
                    matches=1,
                )
            )
    assert sorted(await _suggestions(reg, t)) == ["T1055"]


async def test_cross_org_case_is_404() -> None:
    reg = await register()
    t = await _case(reg)
    attacker = await register(org_name="Attacker Org")
    response = await attacker.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/attack/suggestions"
    )
    assert response.status_code == 404
    own_org = await attacker.client.get(
        f"{API}/{attacker.org_id}/investigations/{t.investigation_id}/attack/suggestions"
    )
    assert own_org.status_code == 404
