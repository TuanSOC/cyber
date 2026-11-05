"""IDOR cases owned by M6 phase 2 (case management): status history, the evidence share
policy, notes, IOC collections and the case-wide IOC read.

The victim extender gives the victim case a status event, a note, a collection with an item
and an evidence share policy (`{note_id}`, `{collection_id}`, `{item_id}`); the state hook
snapshots them, so an attack that changes any of them fails the "nothing changed" check.
The evidence policy sets only `ai_excluded` on the *first* evidence: the AI and TI cases of
the other modules work on the second evidence's job and stay allowed.
"""

from typing import Any

from tests.factories import Registered, csrf
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_ORG = "/api/v1/orgs/{org_id}"
_INV = f"{_ORG}/investigations/{{investigation_id}}"
_COL = f"{_ORG}/ioc-collections/{{collection_id}}"

ROUTE_CASES: RouteCases = {
    ("GET", f"{_INV}/status-events"): lambda v: {"params": {"limit": 10}},
    ("GET", f"{_ORG}/evidence/{{evidence_id}}/share-policy"): lambda v: {},
    ("PUT", f"{_ORG}/evidence/{{evidence_id}}/share-policy"): lambda v: {
        "json": {"ai_excluded": True, "ti_excluded": True}
    },
    ("GET", f"{_INV}/notes"): lambda v: {"params": {"include_deleted": "true"}},
    ("POST", f"{_INV}/notes"): lambda v: {"json": {"body": "Injected note"}},
    ("GET", f"{_ORG}/notes/{{note_id}}"): lambda v: {},
    ("PUT", f"{_ORG}/notes/{{note_id}}"): lambda v: {
        "json": {"expected_version": 1, "body": "Hijacked note", "pinned": True}
    },
    ("DELETE", f"{_ORG}/notes/{{note_id}}"): lambda v: {},
    ("GET", f"{_INV}/ioc-collections"): lambda v: {},
    ("POST", f"{_INV}/ioc-collections"): lambda v: {"json": {"name": "Injected collection"}},
    ("GET", _COL): lambda v: {},
    ("PATCH", _COL): lambda v: {"json": {"name": "Hijacked", "archived": True}},
    ("GET", f"{_COL}/items"): lambda v: {"params": {"include_removed": "true", "q": "victim"}},
    ("POST", f"{_COL}/items"): lambda v: {
        "json": {"items": [{"type": "domain", "value": "planted.example.org"}]}
    },
    ("DELETE", f"{_COL}/items/{{item_id}}"): lambda v: {},
    ("GET", f"{_COL}/export"): lambda v: {"params": {"format": "stix21", "defang": "false"}},
    ("GET", f"{_INV}/iocs"): lambda v: {"params": {"type": "ip", "limit": 50}},
}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ("{note_id}", "{collection_id}", "{item_id}")
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()


def _ok(response: Any) -> dict[str, Any]:
    assert response.status_code < 300, response.text
    return dict(response.json())


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    c = owner.client
    base = f"/api/v1/orgs/{victim.org_id}"
    case = f"{base}/investigations/{victim.investigation_id}"
    headers = csrf(c)
    _ok(await c.patch(case, json={"status": "in_progress"}, headers=headers))
    note = _ok(await c.post(f"{case}/notes", json={"body": "Victim note"}, headers=headers))
    collection = _ok(
        await c.post(f"{case}/ioc-collections", json={"name": "Victim list"}, headers=headers)
    )
    added = _ok(
        await c.post(
            f"{base}/ioc-collections/{collection['id']}/items",
            json={
                "items": [{"type": "domain", "value": "victim-c2.example.net", "note": "victim"}]
            },
            headers=headers,
        )
    )
    _ok(
        await c.put(
            f"{base}/evidence/{victim.evidence_id}/share-policy",
            json={"ai_excluded": True, "ti_excluded": False},
            headers=headers,
        )
    )
    return {
        "note_id": note["id"],
        "collection_id": collection["id"],
        "item_id": str(added["results"][0]["item_id"]),
    }


async def _case_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    c = owner.client
    base = f"/api/v1/orgs/{victim.org_id}"
    case = f"{base}/investigations/{victim.investigation_id}"
    notes = _ok(await c.get(f"{case}/notes", params={"include_deleted": "true"}))
    note = _ok(await c.get(f"{base}/notes/{victim.extra['note_id']}"))
    collections = _ok(await c.get(f"{case}/ioc-collections"))
    items = _ok(
        await c.get(
            f"{base}/ioc-collections/{victim.extra['collection_id']}/items",
            params={"include_removed": "true"},
        )
    )
    policy = _ok(await c.get(f"{base}/evidence/{victim.evidence_id}/share-policy"))
    events = _ok(await c.get(f"{case}/status-events"))
    detail = _ok(await c.get(case))
    return {
        "notes": sorted(
            (n["id"], n["version"], n["body"], n["pinned"], n["deleted"]) for n in notes["items"]
        ),
        "note_versions": [(v["version"], v["body"]) for v in note["versions"]],
        "collections": sorted(
            (x["name"], x["archived"], x["item_count"]) for x in collections["items"]
        ),
        "items": sorted((i["id"], i["value"], i["removed_at"]) for i in items["items"]),
        "share_policy": (policy["ai_excluded"], policy["ti_excluded"]),
        "status_events": [e["id"] for e in events["items"]],
        "case_policy": (detail["tlp"], detail["ai_excluded"], detail["ti_excluded"]),
    }


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_case_state]
