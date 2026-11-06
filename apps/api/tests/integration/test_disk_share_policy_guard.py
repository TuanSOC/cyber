"""The share-policy guard of restricted disk and derived evidence (M9 phase 9, RT2).

While the evidence is `restricted`, the M6 `PUT /evidence/{id}/share-policy` refuses to turn
a flag off with `409 evidence_sensitivity_restricted` (M8's `memory_sensitivity_restricted`
stays the memory code), writing and auditing nothing; turning flags on still works. After the
admin release the analyst clears the flags through the same route.
"""

from typing import Literal

import pytest

from tests.ai_api_helpers import tenant_of
from tests.case_helpers import seed_evidence
from tests.factories import register
from tests.integration.test_disk_sensitivity import apply_disk_default, release
from tests.integration.test_memory_sensitivity import audit_rows, flags, put_flags

Source = Literal["disk", "derived"]


@pytest.mark.parametrize("source", ["disk", "derived"])
@pytest.mark.parametrize(("ai", "ti"), [(False, True), (True, False), (False, False)])
async def test_clearing_a_flag_of_restricted_evidence_is_refused(
    source: Source, ai: bool, ti: bool
) -> None:
    reg = await register(org_name=f"Disk Guard {source} Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="image.E01")
    assert await apply_disk_default(t, evidence_id, source)
    response = await put_flags(reg.client, reg.org_id, evidence_id, ai=ai, ti=ti)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "evidence_sensitivity_restricted"
    assert await flags(t, evidence_id) == (True, True)
    assert await audit_rows(reg.org_id, "evidence.share_policy_updated") == []


@pytest.mark.parametrize("source", ["disk", "derived"])
async def test_after_the_release_the_flags_clear(source: Source) -> None:
    reg = await register(org_name=f"Disk Guard Release {source} Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t, filename="image.E01")
    assert await apply_disk_default(t, evidence_id, source)
    same = await put_flags(reg.client, reg.org_id, evidence_id, ai=True, ti=True)
    assert same.status_code == 200, same.text  # setting (or keeping) flags stays allowed
    assert (await release(reg.client, reg.org_id, evidence_id)).status_code == 200
    cleared = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
    assert cleared.status_code == 200, cleared.text
    assert await flags(t, evidence_id) == (False, False)
