"""Case TLP and the share-policy flags on `PATCH /investigations/{id}` (M6 phase 2).

- Raising the TLP needs only `investigation.write`; lowering it needs `org.update`
  (`403 tlp_downgrade_forbidden`) and `acknowledge_tlp_downgrade` (`422
  tlp_downgrade_not_acknowledged`).
- Turning `ai_excluded` / `ti_excluded` on needs `investigation.write`; turning one off needs
  `integrations.manage` (403).
- Audit: `tlp_from/to`, the flag changes; no free text.
"""

from typing import Any

import pytest

from tests.factories import register
from tests.integration.test_case_status import API, new_case, patch
from tests.integration.test_orgs_members import org_with_roles


async def _case(client: Any, org_id: Any, case_id: str) -> dict[str, Any]:
    response = await client.get(f"{API}/{org_id}/investigations/{case_id}")
    assert response.status_code == 200
    return dict(response.json())


async def test_new_cases_are_amber_and_unrestricted() -> None:
    reg = await register()
    case = await _case(reg.client, reg.org_id, await new_case(reg.client, reg.org_id))
    assert (case["tlp"], case["ai_excluded"], case["ti_excluded"]) == ("amber", False, False)
    assert case["share_policy"] == {"ai_blocked": False, "ti_blocked": False, "reasons": []}


async def test_role_matrix_for_tlp() -> None:
    org = await org_with_roles()
    analyst, admin, viewer = (org.clients[r] for r in ("analyst", "admin", "viewer"))
    case_id = await new_case(analyst, org.org_id)

    # An analyst raises.
    raised = await patch(analyst, org.org_id, case_id, tlp="red")
    assert raised.status_code == 200, raised.text
    assert raised.json()["tlp"] == "red"
    assert raised.json()["share_policy"] == {
        "ai_blocked": True,
        "ti_blocked": True,
        "reasons": ["tlp_red"],
    }
    # An analyst cannot lower, even with the acknowledgement.
    for body in ({"tlp": "green"}, {"tlp": "green", "acknowledge_tlp_downgrade": True}):
        lowered = await patch(analyst, org.org_id, case_id, **body)
        assert lowered.status_code == 403, lowered.text
        assert lowered.json()["error"]["code"] == "tlp_downgrade_forbidden"
    # An admin lowers only with the acknowledgement.
    unacked = await patch(admin, org.org_id, case_id, tlp="green")
    assert unacked.status_code == 422
    assert unacked.json()["error"]["code"] == "tlp_downgrade_not_acknowledged"
    false_ack = await patch(
        admin, org.org_id, case_id, tlp="green", acknowledge_tlp_downgrade=False
    )
    assert false_ack.status_code == 422
    acked = await patch(admin, org.org_id, case_id, tlp="green", acknowledge_tlp_downgrade=True)
    assert acked.status_code == 200, acked.text
    assert acked.json()["tlp"] == "green"
    # A viewer gets 403 for anything.
    assert (await patch(viewer, org.org_id, case_id, tlp="red")).status_code == 403
    assert (await _case(viewer, org.org_id, case_id))["tlp"] == "green"


@pytest.mark.parametrize(
    ("start", "target", "downgrade"),
    [
        ("clear", "green", False),
        ("amber", "amber_strict", False),
        ("amber_strict", "red", False),
        ("amber_strict", "amber", True),
        ("red", "clear", True),
    ],
)
async def test_tlp_order(start: str, target: str, downgrade: bool) -> None:
    reg = await register()  # the owner: may downgrade with the ack
    case_id = await new_case(reg.client, reg.org_id)
    if start != "amber":
        first = await patch(
            reg.client, reg.org_id, case_id, tlp=start, acknowledge_tlp_downgrade=True
        )
        assert first.status_code == 200, first.text
    response = await patch(reg.client, reg.org_id, case_id, tlp=target)
    if downgrade:
        assert response.json()["error"]["code"] == "tlp_downgrade_not_acknowledged"
    else:
        assert response.status_code == 200, response.text


async def test_unknown_tlp_is_422() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    for value in ("white", "amber+strict", "RED", None):
        response = await patch(reg.client, reg.org_id, case_id, tlp=value)
        assert response.status_code == 422, value


async def test_role_matrix_for_exclusion_flags() -> None:
    org = await org_with_roles()
    analyst, admin, viewer = (org.clients[r] for r in ("analyst", "admin", "viewer"))
    case_id = await new_case(analyst, org.org_id)

    on = await patch(analyst, org.org_id, case_id, ai_excluded=True, ti_excluded=True)
    assert on.status_code == 200, on.text
    assert on.json()["share_policy"] == {
        "ai_blocked": True,
        "ti_blocked": True,
        "reasons": ["case_ai_excluded", "case_ti_excluded"],
    }
    for flag in ("ai_excluded", "ti_excluded"):
        off = await patch(analyst, org.org_id, case_id, **{flag: False})
        assert off.status_code == 403, off.text
        assert (await patch(viewer, org.org_id, case_id, **{flag: False})).status_code == 403
    case = await _case(analyst, org.org_id, case_id)
    assert (case["ai_excluded"], case["ti_excluded"]) == (True, True)

    off = await patch(admin, org.org_id, case_id, ai_excluded=False)
    assert off.status_code == 200, off.text
    assert off.json()["share_policy"]["reasons"] == ["case_ti_excluded"]
    # Re-sending the current value is a no-op, not a change: allowed for the analyst.
    same = await patch(analyst, org.org_id, case_id, ai_excluded=False, title="Same flags")
    assert same.status_code == 200, same.text


async def test_rejected_update_changes_nothing() -> None:
    org = await org_with_roles()
    analyst = org.clients["analyst"]
    case_id = await new_case(analyst, org.org_id, title="Original title")
    await patch(analyst, org.org_id, case_id, tlp="red")
    response = await patch(analyst, org.org_id, case_id, title="Changed title", tlp="clear")
    assert response.status_code == 403
    case = await _case(analyst, org.org_id, case_id)
    assert (case["title"], case["tlp"]) == ("Original title", "red")


async def test_audit_records_tlp_and_flags_without_free_text() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    response = await patch(
        reg.client,
        reg.org_id,
        case_id,
        tlp="clear",
        acknowledge_tlp_downgrade=True,
        ai_excluded=True,
        description="Sensitive narrative",
    )
    assert response.status_code == 200, response.text
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "investigation.updated"}
        )
    ).json()
    details = logs["items"][0]["details"]
    assert (details["tlp_from"], details["tlp_to"], details["tlp_downgrade"]) == (
        "amber",
        "clear",
        True,
    )
    assert details["ai_excluded"] is True
    assert details["changes"]["tlp"] == {"from": "amber", "to": "clear"}
    assert details["changes"]["ai_excluded"] == {"from": False, "to": True}
    assert details["changes"]["description"] == {"changed": True}
    assert "Sensitive narrative" not in str(logs)
    assert "acknowledge_tlp_downgrade" not in details["changes"]
