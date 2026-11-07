"""IDOR cases owned by M11 phase 3 (Invitations).

Ensures that invitation management routes (/orgs/{org_id}/invitations/{invitation_id}/...)
strictly enforce organization boundaries: an attacker from org A cannot resend or revoke
an invitation belonging to org B.
"""

from typing import Any

from tests.factories import Registered
from tests.identity_helpers import seed_invitation
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_ORG = "/api/v1/orgs/{org_id}"
_INV = f"{_ORG}/invitations/{{invitation_id}}"

ROUTE_CASES: RouteCases = {
    ("GET", f"{_ORG}/invitations"): lambda v: {},
    ("POST", f"{_ORG}/invitations"): lambda v: {
        "json": {"email": "idor_probe@example.com", "role": "analyst"}
    },
    ("POST", f"{_INV}/resend"): lambda v: {},
    ("POST", f"{_INV}/revoke"): lambda v: {},
}

PATH_OVERRIDES: PathOverrides = {}


async def _extend(owner: Registered, victim: Victim) -> dict[str, Any]:
    seeded = await seed_invitation(
        victim.org_id, owner.user_id, email="victim_idor_invitee@example.com"
    )
    return {"invitation_id": str(seeded.id)}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
RESOURCE_PARAMS: tuple[str, ...] = ("{invitation_id}",)


async def _invitation_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    invs = (await owner.client.get(f"/api/v1/orgs/{victim.org_id}/invitations")).json()
    return {
        "invitations": sorted(
            (i["id"], i["email"], i["role"], i["status"])
            for i in invs.get("items", [])
        )
    }


STATE_HOOKS: list[StateHook] = [_invitation_state]
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
