"""M10 phase 6: capa locations and the capa base through the static ingest and read model.

- A new-format `static.v1` stream (capabilities with `locations`, a header with
  `capa_base_address`) stores decimal strings and the base; the capabilities route serves
  them as `0x…` text in `CapabilityLinkedOut` (RT6).
- An old-format stream (no new keys at all: a static image from before M10, RT18) still
  ingests, with `[]` / NULL.
- The static JSON report (`cyberlab.report.static.v1`) is the same for both: `CapabilityOut`
  is unchanged and nothing of the new fields reaches it (the M8 RT10 lesson).
"""

import json
import re
import uuid
from typing import Any

import pytest
from cyberlab_jobs.static import CapabilityRecord
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJob
from app.modules.static_analysis.models import MalwareCapability, MalwareSample
from tests import pcap_results as pr
from tests import static_results as sr
from tests.analysis_helpers import SentJobs, new_case, pe_bytes, upload
from tests.factories import Registered, register

BASE = 0x140000000
SAMPLE_BYTES = pe_bytes()
SAMPLE = sr.sample_for(SAMPLE_BYTES)
INJECT = [BASE + 0x1280, BASE + 0x12A0]
HIGH = [2**64 - 16, 2**64 - 1]  # above 2**53: exact only as strings


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _queued(sent: SentJobs) -> tuple[Registered, dispatch.DispatchInput]:
    reg = await register(org_name="Capa Locations Org")
    await upload(reg.client, reg.org_id, await new_case(reg), SAMPLE_BYTES, "sample.exe")
    item = sent[-1]
    assert item.analyzer == "static"
    return reg, item


def _capabilities(*, locations: bool) -> list[CapabilityRecord]:
    return [
        CapabilityRecord(
            name="inject thread",
            namespace="host-interaction/process/inject",
            attack=["T1055"],
            matches=2,
            locations=INJECT if locations else [],
        ),
        CapabilityRecord(
            name="high addresses",
            namespace="anti-analysis",
            locations=HIGH if locations else [],
        ),
        CapabilityRecord(name="file-scope rule", namespace="executable/pe"),
    ]


def _records(*, locations: bool) -> list[Any]:
    rows = [r for r in sr.sample_records() if not isinstance(r, CapabilityRecord)]
    return [*rows, *_capabilities(locations=locations)]


def _old_format(raw: list[bytes]) -> list[bytes]:
    """The same lines without any M10 key (as a pre-M10 static image wrote them)."""
    out = []
    for line in raw:
        obj = json.loads(line)
        if obj.get("kind") == "header":
            obj.pop("capa_base_address", None)
        if obj.get("kind") == "capability":
            obj.pop("locations", None)
        out.append(json.dumps(obj).encode() + b"\n")
    return out


async def _deliver(sent: SentJobs, *, new_format: bool) -> tuple[Registered, uuid.UUID]:
    reg, item = await _queued(sent)
    if new_format:
        raw = sr.lines(item.job_id, SAMPLE, _records(locations=True), capa_base_address=BASE)
    else:
        raw = _old_format(sr.lines(item.job_id, SAMPLE, _records(locations=False)))
        assert b"locations" not in b"".join(raw) and b"capa_base_address" not in b"".join(raw)
    await pr.deliver(item, pr.encode(raw))
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None and job.status == "succeeded", job and job.error_code
    return reg, item.job_id


async def _stored(org_id: uuid.UUID, job_id: uuid.UUID) -> tuple[Any, dict[str, list[str]]]:
    async with tenant_session(org_id, None) as session:
        base = await session.scalar(
            select(MalwareSample.capa_base_address).where(MalwareSample.job_id == job_id)
        )
        rows = await session.execute(
            select(MalwareCapability.name, MalwareCapability.locations).where(
                MalwareCapability.job_id == job_id
            )
        )
        return base, {name: locations for name, locations in rows}


async def _get(reg: Registered, job_id: uuid.UUID, path: str) -> Any:
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/{path}")
    assert response.status_code == 200, response.text
    return response.json()


async def test_a_new_format_stream_stores_locations_and_the_base(sent: SentJobs) -> None:
    reg, job_id = await _deliver(sent, new_format=True)
    base, locations = await _stored(reg.org_id, job_id)
    assert base == BASE
    assert locations == {
        "inject thread": [str(a) for a in INJECT],
        "high addresses": [str(a) for a in HIGH],
        "file-scope rule": [],
    }
    page = await _get(reg, job_id, "capabilities")
    items = {i["name"]: i for i in page["items"]}
    assert items["inject thread"]["locations"] == ["0x140001280", "0x1400012a0"]
    assert items["high addresses"]["locations"] == ["0xfffffffffffffff0", "0xffffffffffffffff"]
    assert items["file-scope rule"]["locations"] == []
    assert all(i["functions"] is None for i in items.values())  # no RE job of this sample


async def test_an_old_format_stream_still_ingests_without_locations(sent: SentJobs) -> None:
    reg, job_id = await _deliver(sent, new_format=False)
    base, locations = await _stored(reg.org_id, job_id)
    assert base is None
    assert set(locations) == {"inject thread", "high addresses", "file-scope rule"}
    assert all(v == [] for v in locations.values())
    page = await _get(reg, job_id, "capabilities")
    assert all(i["locations"] == [] for i in page["items"])


async def test_more_than_32_locations_are_refused_whole(sent: SentJobs) -> None:
    """The contract caps a capability at 32 sorted, unique locations: nothing is written."""
    reg, item = await _queued(sent)
    raw = sr.lines(item.job_id, SAMPLE, _records(locations=True), capa_base_address=BASE)
    obj = {
        "kind": "capability",
        "name": "too many",
        "matches": 33,
        "locations": list(range(0x1000, 0x1000 + 33)),
    }
    await pr.deliver(item, pr.encode([*raw, json.dumps(obj).encode() + b"\n"]))
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None and (job.status, job.error_code) == ("failed", "invalid_result")
    _, locations = await _stored(reg.org_id, item.job_id)
    assert locations == {}


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Sections whose content comes from the result rows (the identity sections differ per org).
RESULT_SECTIONS = (
    "sample",
    "pe",
    "elf",
    "findings",
    "signatures",
    "capabilities",
    "iocs",
    "imports_summary",
    "sections",
)


def _result_sections(report: dict[str, Any]) -> str:
    text = json.dumps({k: report[k] for k in RESULT_SECTIONS}, sort_keys=True)
    return _UUID.sub("<id>", text)


async def test_the_static_report_is_unchanged_by_the_new_fields(sent: SentJobs) -> None:
    """RT6: the report of a job with locations equals the report of the same result without
    them (ids aside), and neither names a location or the base."""
    new_reg, new_job = await _deliver(sent, new_format=True)
    old_reg, old_job = await _deliver(sent, new_format=False)
    responses = {}
    for name, (reg, job_id) in {"new": (new_reg, new_job), "old": (old_reg, old_job)}.items():
        response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/report")
        assert response.status_code == 200, response.text
        assert "locations" not in response.text and "capa_base_address" not in response.text
        responses[name] = response.json()
    assert _result_sections(responses["new"]) == _result_sections(responses["old"])
    capability = responses["new"]["capabilities"]["items"][0]
    assert set(capability) == {"id", "name", "namespace", "attack", "mbc", "matches"}
