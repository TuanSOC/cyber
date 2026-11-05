"""IOC collections (M6 phase 2): create / rename / archive, normalization and dedupe, job-IOC
scope, the TI join, soft remove and the archived rules."""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.pcap_analysis.models import Ioc
from tests.factories import Registered, csrf, register
from tests.integration.test_case_notes import _job_case
from tests.integration.test_case_policy_api import _member
from tests.integration.test_case_status import API, move, new_case
from tests.ti_api_helpers import add_result, capture_sends, enable, key_of, lookup


async def new_collection(
    client: AsyncClient, org_id: uuid.UUID, case_id: str, name: str = "Blocklist", **body: Any
) -> Any:
    return await client.post(
        f"{API}/{org_id}/investigations/{case_id}/ioc-collections",
        json={"name": name, **body},
        headers=csrf(client),
    )


async def add(client: AsyncClient, org_id: uuid.UUID, collection_id: str, *items: Any) -> Any:
    return await client.post(
        f"{API}/{org_id}/ioc-collections/{collection_id}/items",
        json={"items": list(items)},
        headers=csrf(client),
    )


async def items(client: AsyncClient, org_id: uuid.UUID, collection_id: str, **params: Any) -> Any:
    response = await client.get(
        f"{API}/{org_id}/ioc-collections/{collection_id}/items", params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


async def collection_with(reg: Registered, *entries: Any) -> tuple[str, str]:
    """(case id, collection id) with the given items added."""
    case_id = await new_case(reg.client, reg.org_id)
    created = await new_collection(reg.client, reg.org_id, case_id)
    assert created.status_code == 201, created.text
    collection_id = str(created.json()["id"])
    if entries:
        added = await add(reg.client, reg.org_id, collection_id, *entries)
        assert added.status_code == 200, added.text
    return case_id, collection_id


async def job_iocs(reg: Registered, job: uuid.UUID) -> dict[str, str]:
    """value -> iocs.id of a job."""
    async with tenant_session(reg.org_id, reg.user_id) as s:
        rows = await s.execute(select(Ioc.value, Ioc.id).where(Ioc.job_id == job))
    return {value: str(ioc_id) for value, ioc_id in rows.all()}


async def test_create_list_get_and_duplicate_names() -> None:
    reg = await register()
    case_id = await new_case(reg.client, reg.org_id)
    created = await new_collection(reg.client, reg.org_id, case_id, description="C2 infra")
    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["name"], body["description"], body["archived"], body["item_count"]) == (
        "Blocklist",
        "C2 infra",
        False,
        0,
    )
    for name in ("Blocklist", "BLOCKLIST", "  blocklist  "):
        dup = await new_collection(reg.client, reg.org_id, case_id, name=name)
        assert (dup.status_code, dup.json()["error"]["code"]) == (409, "collection_exists")
    # The same name in another case is fine.
    other_case = await new_case(reg.client, reg.org_id, title="Other case")
    assert (await new_collection(reg.client, reg.org_id, other_case)).status_code == 201

    second = (await new_collection(reg.client, reg.org_id, case_id, name="Watch")).json()
    listed = (
        await reg.client.get(f"{API}/{reg.org_id}/investigations/{case_id}/ioc-collections")
    ).json()
    assert [c["id"] for c in listed["items"]] == [second["id"], body["id"]]
    assert listed["next_cursor"] is None
    detail = (await reg.client.get(f"{API}/{reg.org_id}/ioc-collections/{body['id']}")).json()
    assert detail == {"collection": body, "counts_by_type": {}}
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.created"}
        )
    ).json()
    assert logs["total"] == 3


@pytest.mark.parametrize(
    ("entry", "ioc_type", "value", "eligible"),
    [
        ({"type": "domain", "value": "Evil.COM."}, "domain", "evil.com", True),
        ({"type": "domain", "value": "evil[.]com"}, "domain", "evil.com", True),
        ({"type": "ip", "value": "8.8.8.8"}, "ipv4", "8.8.8.8", True),
        (
            {"type": "ipv6", "value": "2001:4860:4860:0:0:0:0:8888"},
            "ipv6",
            "2001:4860:4860::8888",
            True,
        ),
        ({"type": "url", "value": "hxxps://evil.com/a?b=c#d"}, "url", "https://evil.com/a", True),
        ({"type": "sha256", "value": "A" * 64}, "sha256", "a" * 64, True),
        ({"type": "file_md5", "value": "B" * 32}, "md5", "b" * 32, True),
        ({"type": "email", "value": "Bad@Evil.com"}, "email", "bad@evil.com", True),
        # Kept, but never sent to a provider (computed `ti_eligible=false`).
        ({"type": "ip", "value": "10.0.0.5"}, "ipv4", "10.0.0.5", False),
        ({"type": "domain", "value": "FIN-SRV-01"}, "domain", "fin-srv-01", False),
        ({"type": "domain", "value": "dc01.corp.local"}, "domain", "dc01.corp.local", False),
        (
            {"type": "url", "value": "http://10.0.0.5:8080/x?q"},
            "url",
            "http://10.0.0.5:8080/x",
            False,
        ),
        (
            {"type": "url", "value": "https://intranet/login"},
            "url",
            "https://intranet/login",
            False,
        ),
        # Pcap-only types keep their job type and an opaque key.
        ({"type": "ja3", "value": " 771,4865-4866,0-23 "}, "ja3", "771,4865-4866,0-23", False),
        ({"type": "registry_key", "value": "HKLM\\Run\\x"}, "registry_key", "HKLM\\Run\\x", False),
    ],
)
async def test_values_are_normalized(
    entry: dict[str, str], ioc_type: str, value: str, eligible: bool
) -> None:
    reg = await register()
    _, collection_id = await collection_with(reg, entry)
    [item] = (await items(reg.client, reg.org_id, collection_id))["items"]
    assert (item["ioc_type"], item["value"], item["ti_eligible"]) == (ioc_type, value, eligible)
    assert item["source"] == "manual" and item["job_id"] is None
    if ioc_type in ("ja3", "registry_key"):
        expected = hashlib.sha256(f"{ioc_type}\0{value}".encode()).hexdigest()
        assert item["ioc_key"] == expected
    else:
        assert item["ioc_key"] == key_of(ioc_type, value)


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ({"type": "md5", "value": "xyz"}, "invalid"),
        ({"type": "url", "value": "ftp://evil.com/x"}, "bad_scheme"),
        ({"type": "url", "value": "http://user:pw@evil.com/"}, "has_userinfo"),
        ({"type": "domain", "value": "10.0.0.1"}, "invalid"),
        ({"type": "hostname", "value": "evil.com"}, "unsupported_type"),
        ({"type": "ip", "value": "999.1.1.1"}, "invalid"),
    ],
)
async def test_invalid_values_are_reported_per_item(entry: dict[str, str], reason: str) -> None:
    reg = await register()
    _, collection_id = await collection_with(reg)
    response = await add(
        reg.client, reg.org_id, collection_id, entry, {"type": "domain", "value": "ok.com"}
    )
    body = response.json()
    assert (body["added"], body["duplicates"], body["invalid"]) == (1, 0, 1)
    assert body["results"][0] == {
        "index": 0,
        "outcome": "invalid",
        "item_id": None,
        "reason": reason,
    }
    assert body["results"][1]["outcome"] == "added"


async def test_duplicates_are_idempotent_and_removed_items_are_readded() -> None:
    reg = await register()
    _, collection_id = await collection_with(reg)
    first = (
        await add(reg.client, reg.org_id, collection_id, {"type": "domain", "value": "evil.com"})
    ).json()
    [added] = first["results"]
    again = (
        await add(
            reg.client,
            reg.org_id,
            collection_id,
            {"type": "domain", "value": "EVIL.com"},
            {"type": "domain", "value": "new.com"},
            {"type": "domain", "value": "new.com"},
        )
    ).json()
    assert [r["outcome"] for r in again["results"]] == ["duplicate", "added", "duplicate"]
    assert again["results"][0]["item_id"] == added["item_id"]
    assert again["results"][2]["item_id"] == again["results"][1]["item_id"]

    url = f"{API}/{reg.org_id}/ioc-collections/{collection_id}/items/{added['item_id']}"
    assert (await reg.client.delete(url, headers=csrf(reg.client))).status_code == 204
    assert (await reg.client.delete(url, headers=csrf(reg.client))).status_code == 204
    active = await items(reg.client, reg.org_id, collection_id)
    assert [i["value"] for i in active["items"]] == ["new.com"]
    readd = (
        await add(reg.client, reg.org_id, collection_id, {"type": "domain", "value": "evil.com"})
    ).json()
    assert readd["results"][0]["outcome"] == "added"
    assert readd["results"][0]["item_id"] != added["item_id"]
    everything = await items(reg.client, reg.org_id, collection_id, include_removed=True)
    assert len(everything["items"]) == 3
    removed = [i for i in everything["items"] if i["removed_at"]]
    assert [i["id"] for i in removed] == [added["item_id"]]
    assert removed[0]["removed_by"] == str(reg.user_id)
    detail = (await reg.client.get(f"{API}/{reg.org_id}/ioc-collections/{collection_id}")).json()
    assert detail["counts_by_type"] == {"domain": 2}
    assert detail["collection"]["item_count"] == 2

    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.items_added"}
        )
    ).json()
    assert logs["items"][-1]["details"]["added"] == 1
    removals = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.item_removed"}
        )
    ).json()
    assert removals["total"] == 1


async def test_job_iocs_of_the_case_only() -> None:
    reg = await register()
    other = await register()
    job, _, case_id = await _job_case(reg)
    other_job, _, _ = await _job_case(reg)  # same org, another case
    foreign_job, _, _ = await _job_case(other)
    own = await job_iocs(reg, job)
    collection = (await new_collection(reg.client, reg.org_id, case_id)).json()
    response = await add(
        reg.client,
        reg.org_id,
        collection["id"],
        {"ioc_id": own["192.0.2.1"]},
        {"ioc_id": own["example.com"]},
        {"ioc_id": (await job_iocs(reg, other_job))["192.0.2.1"]},
        {"ioc_id": (await job_iocs(other, foreign_job))["192.0.2.1"]},
        {"ioc_id": str(uuid.uuid4())},
    )
    body = response.json()
    assert [r["outcome"] for r in body["results"]] == [
        "added",
        "added",
        "invalid",
        "invalid",
        "invalid",
    ]
    assert {r["reason"] for r in body["results"][2:]} == {"ioc_out_of_scope"}
    listed = {
        i["value"]: i for i in (await items(reg.client, reg.org_id, collection["id"]))["items"]
    }
    assert set(listed) == {"192.0.2.1", "example.com"}
    ip = listed["192.0.2.1"]
    assert (ip["source"], ip["job_id"], ip["ioc_id"], ip["ioc_type"]) == (
        "job_ioc",
        str(job),
        own["192.0.2.1"],
        "ipv4",
    )
    # A manual entry of the same value is a duplicate of the job IOC.
    dup = await add(reg.client, reg.org_id, collection["id"], {"type": "ip", "value": "192.0.2.1"})
    assert dup.json()["results"][0]["outcome"] == "duplicate"


async def test_items_carry_the_latest_ti_answer_per_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_sends(monkeypatch)
    reg = await register()
    await enable(reg.client, reg.org_id)
    run = await lookup(reg.client, reg.org_id, "hit.example.com")
    assert run.status_code == 202, run.text
    run_id = run.json()["run"]["id"]
    await add_result(reg.org_id, run_id, fetched_at=datetime(2026, 1, 1, tzinfo=UTC))
    _, collection_id = await collection_with(
        reg, {"type": "domain", "value": "hit.example.com"}, {"type": "domain", "value": "x.org"}
    )
    listed = {i["value"]: i for i in (await items(reg.client, reg.org_id, collection_id))["items"]}
    hit = listed["hit.example.com"]
    assert hit["ti_eligible"] is False  # special-use name: never sent to a public provider
    [answer] = hit["ti"]
    assert (answer["provider"], answer["status"], answer["found"]) == ("mock", "ok", True)
    assert answer["summary"]["label"] == "test-hit"
    assert "verdict" not in answer
    assert listed["x.org"]["ti"] == []


async def test_filters_and_pages() -> None:
    reg = await register()
    entries = [{"type": "domain", "value": f"d{i:02d}.com"} for i in range(55)]
    entries.append({"type": "ip", "value": "8.8.4.4"})
    _, collection_id = await collection_with(reg, *entries)
    assert [
        i["value"]
        for i in (await items(reg.client, reg.org_id, collection_id, type="ipv4"))["items"]
    ] == ["8.8.4.4"]
    assert [
        i["value"] for i in (await items(reg.client, reg.org_id, collection_id, q="d07"))["items"]
    ] == ["d07.com"]
    first = await items(reg.client, reg.org_id, collection_id)
    assert len(first["items"]) == 50 and first["next_cursor"]
    rest = await items(reg.client, reg.org_id, collection_id, cursor=first["next_cursor"])
    assert len(rest["items"]) == 6 and rest["next_cursor"] is None
    seen = {i["id"] for i in first["items"] + rest["items"]}
    assert len(seen) == 56


async def test_too_many_items_per_call_is_422() -> None:
    reg = await register()
    _, collection_id = await collection_with(reg)
    entries = [{"type": "domain", "value": f"d{i}.com"} for i in range(501)]
    response = await add(reg.client, reg.org_id, collection_id, *entries)
    assert response.status_code == 422


async def test_rename_archive_and_unarchive() -> None:
    reg = await register()
    case_id, collection_id = await collection_with(reg, {"type": "domain", "value": "a.com"})
    await new_collection(reg.client, reg.org_id, case_id, name="Taken")
    url = f"{API}/{reg.org_id}/ioc-collections/{collection_id}"

    taken = await reg.client.patch(url, json={"name": "taken"}, headers=csrf(reg.client))
    assert (taken.status_code, taken.json()["error"]["code"]) == (409, "collection_exists")
    renamed = await reg.client.patch(
        url, json={"name": "Renamed", "description": "d"}, headers=csrf(reg.client)
    )
    assert renamed.status_code == 200, renamed.text
    assert (renamed.json()["name"], renamed.json()["description"]) == ("Renamed", "d")

    archived = await reg.client.patch(url, json={"archived": True}, headers=csrf(reg.client))
    assert archived.json()["archived"] is True
    item_id = (await items(reg.client, reg.org_id, collection_id))["items"][0]["id"]
    for response in (
        await add(reg.client, reg.org_id, collection_id, {"type": "domain", "value": "b.com"}),
        await reg.client.delete(f"{url}/items/{item_id}", headers=csrf(reg.client)),
        await reg.client.patch(url, json={"name": "Again"}, headers=csrf(reg.client)),
    ):
        assert (response.status_code, response.json()["error"]["code"]) == (
            409,
            "collection_archived",
        )
    # Reads and exports still work on an archived collection.
    assert (await items(reg.client, reg.org_id, collection_id))["items"]
    unarchived = await reg.client.patch(
        url, json={"archived": False, "name": "Again"}, headers=csrf(reg.client)
    )
    assert unarchived.status_code == 200
    assert (unarchived.json()["archived"], unarchived.json()["name"]) == (False, "Again")
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.updated"}
        )
    ).json()
    assert logs["total"] == 3
    assert {"changed", "archived"} <= set(logs["items"][0]["details"])


async def test_archived_case_makes_collections_read_only() -> None:
    reg = await register()
    case_id, collection_id = await collection_with(reg, {"type": "domain", "value": "a.com"})
    await move(reg.client, reg.org_id, case_id, "closed", "archived")
    url = f"{API}/{reg.org_id}/ioc-collections/{collection_id}"
    for response in (
        await new_collection(reg.client, reg.org_id, case_id, name="New"),
        await add(reg.client, reg.org_id, collection_id, {"type": "domain", "value": "b.com"}),
        await reg.client.patch(url, json={"name": "x"}, headers=csrf(reg.client)),
    ):
        assert (response.status_code, response.json()["error"]["code"]) == (
            409,
            "investigation_archived",
        )
    assert (await reg.client.get(url)).status_code == 200


async def test_roles_and_tenancy() -> None:
    reg = await register()
    other = await register()
    viewer = await _member(reg, "viewer")
    case_id, collection_id = await collection_with(reg, {"type": "domain", "value": "a.com"})
    assert (await new_collection(viewer, reg.org_id, case_id, name="V")).status_code == 403
    assert (
        await add(viewer, reg.org_id, collection_id, {"type": "domain", "value": "v.com"})
    ).status_code == 403
    assert (await items(viewer, reg.org_id, collection_id))["items"]
    item_id = (await items(reg.client, reg.org_id, collection_id))["items"][0]["id"]
    for org_id in (reg.org_id, other.org_id):
        base = f"{API}/{org_id}/ioc-collections/{collection_id}"
        assert (await other.client.get(base)).status_code == 404
        assert (await other.client.get(f"{base}/items")).status_code == 404
        assert (
            await add(other.client, org_id, collection_id, {"type": "domain", "value": "x.com"})
        ).status_code == 404
        deleted = await other.client.delete(f"{base}/items/{item_id}", headers=csrf(other.client))
        assert deleted.status_code == 404
    # An item id of another collection is 404 on this one.
    _, second = await collection_with(reg)
    wrong = await reg.client.delete(
        f"{API}/{reg.org_id}/ioc-collections/{second}/items/{item_id}", headers=csrf(reg.client)
    )
    assert wrong.status_code == 404
