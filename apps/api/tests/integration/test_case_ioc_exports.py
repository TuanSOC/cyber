"""IOC collection exports through the API (M6 phase 2): headers, TLP marking, defang default,
never redacted, the `defang=false` permission, formula-safe CSV and the audit row. M8
(security review): items of restricted memory evidence are withheld below TLP:RED."""

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cyberlab_jobs.report import STIX_TLP_MARKINGS, TLP
from httpx import AsyncClient, Response

from app.core.tenancy import tenant_session
from app.modules.threat_intel.models import TiResult
from tests.factories import Registered, register
from tests.integration.seed import Tenant
from tests.integration.test_case_ioc_collections import (
    add,
    collection_with,
    job_iocs,
    new_collection,
)
from tests.integration.test_case_notes import _job_case
from tests.integration.test_case_policy_api import _member
from tests.integration.test_case_status import API, patch
from tests.integration.test_memory_sensitivity import release
from tests.memory_helpers import restricted_memory_evidence
from tests.ti_helpers import seed_run

ENTRIES = (
    {"type": "domain", "value": "evil.com"},
    {"type": "ip", "value": "10.0.0.5"},  # internal: exported in clear (never redacted)
    {"type": "url", "value": "https://evil.com/x.php"},
    {"type": "sha256", "value": "a" * 64},
    {"type": "ja3", "value": "771,4865,0"},
    {"type": "registry_key", "value": "=cmd|' /C calc'!A0"},
    {"type": "file_path", "value": "-2+3", "note": "@SUM(1)"},
)


async def export(
    client: AsyncClient, org_id: uuid.UUID, collection_id: str, **params: Any
) -> Response:
    return await client.get(f"{API}/{org_id}/ioc-collections/{collection_id}/export", params=params)


async def _seeded(reg: Registered) -> tuple[str, str]:
    return await collection_with(reg, *ENTRIES)


@pytest.mark.parametrize(
    ("fmt", "content_type", "ext"),
    [
        ("csv", "text/csv; charset=utf-8", "csv"),
        ("json", "application/json", "json"),
        ("stix21", "application/stix+json;version=2.1", "stix.json"),
    ],
)
async def test_download_headers(fmt: str, content_type: str, ext: str) -> None:
    reg = await register()
    _, collection_id = await _seeded(reg)
    response = await export(reg.client, reg.org_id, collection_id, format=fmt)
    assert response.status_code == 200, response.text
    h = response.headers
    assert h["content-type"] == content_type
    assert h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "no-store"
    assert h["content-security-policy"] == "sandbox"
    assert h["x-export-redacted"] == "false"
    assert h["x-export-defanged"] == "true"
    disposition = h["content-disposition"]
    assert disposition.startswith('attachment; filename="CASE-')
    assert f'_Blocklist_TLP-AMBER.{ext}"' in disposition
    assert "filename*=UTF-8''" in disposition


async def test_csv_is_tlp_marked_defanged_and_formula_safe() -> None:
    reg = await register()
    _, collection_id = await _seeded(reg)
    text = (await export(reg.client, reg.org_id, collection_id, format="csv")).text
    first, rest = text.split("\r\n", 1)
    # One cell (quoted: the collection name is JSON-quoted text).
    (comment,) = next(csv.reader([first]))
    assert comment.startswith("# TLP:AMBER CASE-")
    assert "not redacted" in comment and "defanged" in comment
    rows = list(csv.reader(io.StringIO(rest)))
    assert rows[0] == [
        "type",
        "value",
        "ioc_key",
        "source",
        "job_id",
        "note",
        "added_at",
        "ti_eligible",
    ]
    by_type = {r[0]: r for r in rows[1:]}
    assert by_type["domain"][1] == "evil[.]com"
    assert by_type["ipv4"][1] == "10[.]0[.]0[.]5"  # internal value present (defanged only)
    assert by_type["url"][1] == "hxxps[:]//evil[.]com/x[.]php"
    assert by_type["sha256"][1] == "a" * 64
    assert by_type["registry_key"][1] == "'=cmd|' /C calc'!A0"
    assert by_type["file_path"][1] == "'-2+3"
    assert by_type["file_path"][5] == "'@SUM(1)"
    assert by_type["ipv4"][7] == "false" and by_type["domain"][7] == "true"
    assert len(rows) == 1 + len(ENTRIES)


async def test_clear_text_export_needs_evidence_write() -> None:
    reg = await register()
    _, collection_id = await _seeded(reg)
    viewer = await _member(reg, "viewer")
    analyst = await _member(reg, "analyst")
    defanged = await export(viewer, reg.org_id, collection_id, format="json")
    assert defanged.status_code == 200
    refused = await export(viewer, reg.org_id, collection_id, format="json", defang="false")
    assert refused.status_code == 403
    clear = await export(analyst, reg.org_id, collection_id, format="json", defang="false")
    assert clear.status_code == 200
    assert clear.headers["x-export-defanged"] == "false"
    body = clear.json()
    assert body["defanged"] is False
    values = {i["value"] for i in body["items"]}
    assert {"evil.com", "10.0.0.5", "https://evil.com/x.php"} <= values


async def test_a_refused_clear_text_export_is_audited() -> None:
    reg = await register()
    _, collection_id = await _seeded(reg)
    viewer = await _member(reg, "viewer")
    refused = await export(viewer, reg.org_id, collection_id, format="csv", defang="false")
    assert refused.status_code == 403
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.export_refused"}
        )
    ).json()
    assert logs["total"] == 1
    [entry] = logs["items"]
    assert entry["target_id"] == collection_id
    assert entry["details"]["format"] == "csv" and entry["details"]["defang"] is False
    assert "evil" not in json.dumps(logs)


async def test_a_defanged_json_export_leaves_raw_ti_summaries_out() -> None:
    """TI summaries are raw provider JSON (never defanged): the defanged export carries the
    attributed answer without it; the clear-text export keeps it."""
    reg = await register()
    case_id, collection_id = await _seeded(reg)
    clear = await export(reg.client, reg.org_id, collection_id, format="json", defang="false")
    key = {i["ioc_type"]: i for i in clear.json()["items"]}["domain"]["ioc_key"]
    t = Tenant(reg.org_id, reg.user_id, uuid.UUID(case_id))
    run_id = await seed_run(t)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        s.add(
            TiResult(
                organization_id=reg.org_id,
                run_id=run_id,
                provider="mock",
                ioc_type="domain",
                value_norm="evil.com",
                ioc_key=key,
                status="ok",
                found=True,
                summary={"related": ["https://evil.com/c2", "10.0.0.5"], "label": "evil.com"},
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
    defanged = await export(reg.client, reg.org_id, collection_id, format="json")
    assert defanged.status_code == 200
    [answer] = {i["ioc_type"]: i for i in defanged.json()["items"]}["domain"]["ti"]
    assert answer["provider"] == "mock" and answer["found"] is True
    assert answer["summary"] is None
    assert "evil.com" not in defanged.text and "https://" not in defanged.text
    clear = await export(reg.client, reg.org_id, collection_id, format="json", defang="false")
    [answer] = {i["ioc_type"]: i for i in clear.json()["items"]}["domain"]["ti"]
    assert answer["summary"]["label"] == "evil.com"


async def test_json_export() -> None:
    reg = await register()
    case_id, collection_id = await _seeded(reg)
    assert (await patch(reg.client, reg.org_id, case_id, tlp="red")).status_code == 200
    body = (await export(reg.client, reg.org_id, collection_id, format="json")).json()
    assert body["tlp"] == "red" and body["defanged"] is True
    assert body["collection"]["id"] == collection_id
    assert body["collection"]["item_count"] == len(ENTRIES)
    assert body["exported_at"]
    by_type = {i["ioc_type"]: i for i in body["items"]}
    assert sorted(by_type) == [
        "domain",
        "file_path",
        "ipv4",
        "ja3",
        "registry_key",
        "sha256",
        "url",
    ]
    assert by_type["domain"]["value"] == "evil[.]com"
    assert by_type["ipv4"]["ti_eligible"] is False


async def test_stix_export() -> None:
    reg = await register()
    case_id, collection_id = await _seeded(reg)
    await patch(reg.client, reg.org_id, case_id, tlp="green", acknowledge_tlp_downgrade=True)
    response = await export(reg.client, reg.org_id, collection_id, format="stix21", defang="false")
    bundle = json.loads(response.content)
    marking, identity, *indicators = bundle["objects"]
    assert marking == STIX_TLP_MARKINGS[TLP.GREEN]
    assert identity["name"] == "Acme IR"
    # ja3 and file_path have no STIX path: skipped and counted.
    assert len(indicators) == len(ENTRIES) - 2
    assert response.headers["x-export-skipped"] == "2"
    assert response.headers["x-export-count"] == str(len(ENTRIES) - 2)
    patterns = {i["pattern"] for i in indicators}
    assert "[domain-name:value = 'evil.com']" in patterns
    assert "[ipv4-addr:value = '10.0.0.5']" in patterns
    assert "[windows-registry-key:key = '=cmd|\\' /C calc\\'!A0']" in patterns
    assert all(i["object_marking_refs"] == [marking["id"]] for i in indicators)
    again = json.loads(
        (
            await export(reg.client, reg.org_id, collection_id, format="stix21", defang="false")
        ).content
    )
    assert [o["id"] for o in again["objects"][1:]] == [o["id"] for o in bundle["objects"][1:]]


async def test_exports_are_audited() -> None:
    reg = await register()
    _, collection_id = await _seeded(reg)
    await export(reg.client, reg.org_id, collection_id, format="stix21")
    await export(reg.client, reg.org_id, collection_id, format="csv", defang="false")
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.exported"}
        )
    ).json()
    assert logs["total"] == 2
    newest, oldest = (item["details"] for item in logs["items"])
    assert (newest["format"], newest["defang"], newest["count"]) == ("csv", False, len(ENTRIES))
    assert (oldest["format"], oldest["defang"], oldest["skipped"]) == ("stix21", True, 2)
    assert newest["redacted"] is False and newest["tlp"] == "amber"
    assert "evil" not in json.dumps(logs)


async def test_exports_are_tenant_scoped_and_validated() -> None:
    reg = await register()
    other = await register()
    _, collection_id = await _seeded(reg)
    for org_id in (reg.org_id, other.org_id):
        assert (await export(other.client, org_id, collection_id)).status_code == 404
    assert (await export(reg.client, reg.org_id, collection_id, format="xml")).status_code == 422
    unknown = await export(reg.client, reg.org_id, str(uuid.uuid4()))
    assert unknown.status_code == 404


# --- M8 (security review): restricted memory evidence below TLP:RED -------------------------


async def _memory_collection(reg: Registered) -> tuple[str, str, uuid.UUID]:
    """A collection holding two IOCs of a job on restricted memory evidence plus one manual
    entry: (case id, collection id, evidence id)."""
    job, evidence_id, case_id = await _job_case(reg)
    tenant = Tenant(reg.org_id, reg.user_id, uuid.UUID(case_id))
    await restricted_memory_evidence(tenant, uuid.UUID(evidence_id))
    own = await job_iocs(reg, job)
    created = await new_collection(reg.client, reg.org_id, case_id)
    collection_id = str(created.json()["id"])
    added = await add(
        reg.client,
        reg.org_id,
        collection_id,
        {"ioc_id": own["192.0.2.1"]},
        {"ioc_id": own["example.com"]},
        {"type": "domain", "value": "manual.example.net"},
    )
    assert [r["outcome"] for r in added.json()["results"]] == ["added"] * 3
    return case_id, collection_id, uuid.UUID(evidence_id)


async def test_restricted_memory_items_are_withheld_below_tlp_red() -> None:
    reg = await register()
    case_id, collection_id, _ = await _memory_collection(reg)
    # CSV: only the manual item, the withheld count in the comment line and the header.
    response = await export(reg.client, reg.org_id, collection_id, format="csv")
    assert response.status_code == 200, response.text
    assert response.headers["x-export-withheld"] == "2"
    assert response.headers["x-export-count"] == "1"
    first, rest = response.text.split("\r\n", 1)
    assert "2 item(s) of restricted memory evidence withheld" in first
    rows = list(csv.reader(io.StringIO(rest)))
    assert [r[1] for r in rows[1:]] == ["manual[.]example[.]net"]
    assert "192.0.2" not in response.text and "example[.]com" not in response.text
    # JSON: the additive `omissions`.
    body = (await export(reg.client, reg.org_id, collection_id, format="json")).json()
    assert [i["value"] for i in body["items"]] == ["manual[.]example[.]net"]
    assert body["omissions"] == {"memory_restricted": 2}
    # STIX: one indicator.
    stix = await export(reg.client, reg.org_id, collection_id, format="stix21", defang="false")
    _, _, *indicators = json.loads(stix.content)["objects"]
    assert [i["pattern"] for i in indicators] == ["[domain-name:value = 'manual.example.net']"]
    assert stix.headers["x-export-withheld"] == "2"
    assert b"192.0.2.1" not in stix.content
    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "ioc_collection.exported"}
        )
    ).json()
    assert {item["details"]["withheld"] for item in logs["items"]} == {2}


async def test_tlp_red_or_a_release_exports_every_item() -> None:
    reg = await register()
    case_id, collection_id, evidence_id = await _memory_collection(reg)
    raised = await patch(reg.client, reg.org_id, case_id, tlp="red")
    assert raised.status_code == 200, raised.text
    body = (await export(reg.client, reg.org_id, collection_id, format="json")).json()
    assert len(body["items"]) == 3 and "omissions" not in body
    # Back below RED: withheld again until an admin releases the evidence.
    lowered = await patch(reg.client, reg.org_id, case_id, tlp="amber",
                          acknowledge_tlp_downgrade=True)  # fmt: skip
    assert lowered.status_code == 200, lowered.text
    response = await export(reg.client, reg.org_id, collection_id, format="csv")
    assert response.headers["x-export-withheld"] == "2"
    released = await release(reg.client, reg.org_id, evidence_id)
    assert released.status_code == 200, released.text
    response = await export(reg.client, reg.org_id, collection_id, format="csv")
    assert response.headers["x-export-withheld"] == "0"
    assert response.headers["x-export-count"] == "3"
    assert "withheld" not in response.text.split("\r\n", 1)[0]


async def test_exports_without_memory_evidence_are_unchanged() -> None:
    reg = await register()
    _, collection_id = await _seeded(reg)
    response = await export(reg.client, reg.org_id, collection_id, format="json")
    assert response.headers["x-export-withheld"] == "0"
    assert "omissions" not in response.json()
