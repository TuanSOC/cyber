"""Memory IOCs and in-org correlation (M8 phase 8).

Correlation is allowed for restricted memory evidence (keys only, never across orgs, RT32):
the memory job's IOCs are ordinary `iocs` rows, so the unchanged M7 indexer picks them up. A
remote IP seen by a memory job and by a pcap job of another case shows in the pcap job's
"also seen in"; the lookup lists the memory occurrence with `analyzer: memory` (the web links
it to `/memory/{job}`, the phase-1 analyzer sweep); another org's identical IP never counts.
"""

import uuid

from app.modules.analysis.models import Analyzer
from app.modules.correlation import indexer
from tests.case_helpers import seed_case
from tests.factories import csrf
from tests.integration.seed import seed_tenant
from tests.integration.test_correlation_indexer import index_rows, job_with_iocs, member_client
from tests.integration.test_memory_sensitivity import memory_evidence, seed_memory_results
from tests.memory_helpers import seed_memory_job

API = "/api/v1/orgs"
REMOTE_IP = "203.0.113.77"


async def test_a_memory_ip_correlates_with_a_pcap_job_of_another_case_in_the_org_only() -> None:
    a = await seed_tenant(f"memcorr-a-{uuid.uuid4().hex[:6]}")
    b = await seed_tenant(f"memcorr-b-{uuid.uuid4().hex[:6]}")
    memory_case = await seed_case(a, title="Memory case")
    pcap_case = await seed_case(a, title="Network case")
    other_org_case = await seed_case(b, title="Other org case")

    image = await memory_evidence(a, memory_case)
    memory_job = await seed_memory_job(a, image)
    await seed_memory_results(a, memory_job, iocs=[("ip", REMOTE_IP)])
    await index_rows(a, (memory_job,), analyzer=Analyzer.MEMORY)
    assert await indexer.index_job(a.org_id, memory_job)

    pcap_job = await job_with_iocs(a, pcap_case, [("ip", REMOTE_IP)])
    await job_with_iocs(b, other_org_case, [("ip", REMOTE_IP)])

    c = await member_client(a.org_id)
    pivot = await c.get(f"{API}/{a.org_id}/analyses/{pcap_job}/correlations")
    assert pivot.status_code == 200, pivot.text
    [item] = [i for i in pivot.json()["items"] if i["kind"] == "ipv4"]
    assert (item["other_jobs"], item["other_cases"]) == (1, 1)
    assert [case["investigation_id"] for case in item["top_cases"]] == [str(memory_case)]

    # And from the memory job's side.
    back = await c.get(f"{API}/{a.org_id}/analyses/{memory_job}/correlations")
    assert back.status_code == 200, back.text
    [item] = [i for i in back.json()["items"] if i["kind"] == "ipv4"]
    assert [case["investigation_id"] for case in item["top_cases"]] == [str(pcap_case)]

    found = await c.post(
        f"{API}/{a.org_id}/correlations/lookup",
        json={"kind": "ipv4", "value": REMOTE_IP},
        headers=csrf(c),
    )
    assert found.status_code == 200, found.text
    body = found.json()
    assert (body["jobs"], body["cases"]) == (2, 2)
    by_job = {o["job_id"]: o for o in body["items"]}
    assert set(by_job) == {str(memory_job), str(pcap_job)}
    assert by_job[str(memory_job)]["analyzer"] == "memory"
    assert by_job[str(memory_job)]["evidence_id"] == str(image)
    assert by_job[str(pcap_job)]["analyzer"] == "pcap"
