"""The share-policy guard of restricted memory evidence (M8 phase 8).

While the evidence is `restricted`, the M6 `PUT /evidence/{id}/share-policy` refuses to turn
a flag off (`409 memory_sensitivity_restricted`, nothing written or audited); turning flags
on, or a PUT that changes nothing, still works. After the admin release the analyst clears
the flags through the same route, and anyone with `evidence.write` may set them again.
Evidence that is no memory image behaves as in M6.
"""

import pytest

from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import tenant_of
from tests.case_helpers import seed_evidence
from tests.factories import register
from tests.integration.test_memory_sensitivity import (
    audit_rows,
    flags,
    member,
    memory_evidence,
    put_flags,
    release,
)


@pytest.mark.parametrize(("ai", "ti"), [(False, True), (True, False), (False, False)])
async def test_clearing_a_flag_of_restricted_evidence_is_refused(ai: bool, ti: bool) -> None:
    reg = await register(org_name="Guard Refuse Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    response = await put_flags(reg.client, reg.org_id, evidence_id, ai=ai, ti=ti)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "memory_sensitivity_restricted"
    assert await flags(t, evidence_id) == (True, True)
    assert await audit_rows(reg.org_id, "evidence.share_policy_updated") == []


async def test_setting_flags_stays_allowed_while_restricted() -> None:
    reg = await register(org_name="Guard Same Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    same = await put_flags(reg.client, reg.org_id, evidence_id, ai=True, ti=True)
    assert same.status_code == 200, same.text
    assert (same.json()["ai_excluded"], same.json()["ti_excluded"]) == (True, True)
    assert same.json()["effective"]["ai_blocked"] and same.json()["effective"]["ti_blocked"]


async def test_the_permission_check_comes_first() -> None:
    """An analyst may not turn a flag off at all (M6, 403), restricted or not."""
    reg = await register(org_name="Guard Analyst Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    analyst = await member(reg, MemberRole.ANALYST)
    response = await put_flags(analyst, reg.org_id, evidence_id, ai=False, ti=True)
    assert response.status_code == 403, response.text


async def test_after_the_release_the_flags_clear_and_can_be_set_again() -> None:
    reg = await register(org_name="Guard Release Org")
    t = await tenant_of(reg)
    evidence_id = await memory_evidence(t)
    assert (await release(reg.client, reg.org_id, evidence_id)).status_code == 200
    cleared = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
    assert cleared.status_code == 200, cleared.text
    assert await flags(t, evidence_id) == (False, False)
    [audit] = await audit_rows(reg.org_id, "evidence.share_policy_updated")
    assert audit.details == {
        "from": {"ai_excluded": True, "ti_excluded": True},
        "to": {"ai_excluded": False, "ti_excluded": False},
    }
    # The release is not reversible through the API, but the flags are: an analyst sets them.
    analyst = await member(reg, MemberRole.ANALYST)
    again = await put_flags(analyst, reg.org_id, evidence_id, ai=True, ti=True)
    assert again.status_code == 200, again.text
    assert await flags(t, evidence_id) == (True, True)
    # And, released, an admin may clear them again.
    final = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
    assert final.status_code == 200, final.text


async def test_other_evidence_behaves_as_in_m6() -> None:
    reg = await register(org_name="Guard Plain Org")
    t = await tenant_of(reg)
    evidence_id = await seed_evidence(t)
    on = await put_flags(reg.client, reg.org_id, evidence_id, ai=True, ti=True)
    assert on.status_code == 200, on.text
    off = await put_flags(reg.client, reg.org_id, evidence_id, ai=False, ti=False)
    assert off.status_code == 200, off.text
    assert await flags(t, evidence_id) == (False, False)
