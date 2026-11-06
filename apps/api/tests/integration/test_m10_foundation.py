"""M10 phase 1 plumbing: the frozen RE routes exist and check membership (implemented in
phase 8: `404` for an unknown job); an RE request is validated by schema and refused before
anything is created (no static source: `409 static_analysis_required`, phase 7); `quick`
is `422 profile_unavailable` while disabled; the platform-wide heavy-analysis cap (RT2)
refuses a second memory / disk / reverse job without naming it; `explain_function` reaches
the run path (phase 9; the AI checks apply); the capabilities route serves
`CapabilityLinkedOut` while the static report keeps `CapabilityOut` (RT6)."""

import uuid

import pytest

from app.core.config import get_settings
from app.main import app
from app.modules.analysis.models import Analyzer
from tests.analysis_helpers import new_case, upload
from tests.disk_helpers import seed_disk_job
from tests.factories import csrf, register
from tests.integration.seed import Tenant
from tests.memory_helpers import seed_memory_job
from tests.reverse_helpers import seed_re_job, seed_static_source_job
from tests.security import idor_cases_reverse

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/reverse"
ROUTES = frozenset(
    {
        ("GET", _JOB),
        ("GET", f"{_JOB}/functions"),
        ("GET", f"{_JOB}/functions/{{entry}}"),
        ("GET", f"{_JOB}/functions/{{entry}}/code"),
        ("GET", f"{_JOB}/imports"),
        ("GET", f"{_JOB}/strings"),
        ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/capabilities/{capability_id}/functions"),
    }
)


def _org_routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if path.startswith("/api/v1/orgs/{org_id}")
        for method in item
    }


def test_every_m10_route_is_frozen_and_has_its_idor_case() -> None:
    assert ROUTES <= _org_routes(), sorted(ROUTES - _org_routes())
    assert idor_cases_reverse.PENDING_ROUTES == frozenset()  # phase 8
    assert set(idor_cases_reverse.ROUTE_CASES) == ROUTES


async def test_m10_routes_answer_404_for_an_unknown_job() -> None:
    owner = await register(org_name="M10 Org")
    outsider = await register(org_name="M10 Outsider")
    ids = {
        "org_id": str(owner.org_id),
        "job_id": str(uuid.uuid4()),
        "entry": "0x401000",
        "capability_id": str(uuid.uuid4()),
    }
    for method, template in sorted(ROUTES):
        url = template.format(**ids)
        response = await owner.client.request(method, url)
        assert response.status_code == 404, (url, response.text)
        foreign = await outsider.client.request(method, url)
        assert foreign.status_code in (403, 404), (url, foreign.status_code)


async def test_an_re_request_is_schema_checked_and_creates_nothing() -> None:
    owner = await register(org_name="M10 Run Org")
    case_id = await new_case(owner)
    evidence = await upload(owner.client, owner.org_id, case_id, b"MZ" + b"\0" * 4094, "a.bin")
    url = f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses"
    for bad in (
        {"analyzer": "reverse", "profile": "triage"},
        {"analyzer": "reverse", "profile": "targeted"},  # RT10: no targeted profile
        {"analyzer": "reverse", "profile": "quick", "decompile_addresses": ["0x401000"]},
        {"analyzer": "reverse", "decompile_addresses": ["0x401000", "0x401000"]},
        {"analyzer": "reverse", "decompile_addresses": ["401000"]},
        {"analyzer": "reverse", "decompile_addresses": [f"0x{i:x}" for i in range(65)]},
        {"analyzer": "static", "source_job_id": str(uuid.uuid4())},
        {"analyzer": "pcap", "decompile_addresses": ["0x1"]},
    ):
        response = await owner.client.post(url, json=bad, headers=csrf(owner.client))
        assert response.status_code == 422, (bad, response.text)
    ok = {"analyzer": "reverse", "decompile_addresses": ["0x401000"]}
    response = await owner.client.post(url, json=ok, headers=csrf(owner.client))
    # Phase 7: no succeeded static `full` job of this evidence is a source.
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "static_analysis_required"
    jobs = await owner.client.get(f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses")
    assert all(j["analyzer"] != "reverse" for j in jobs.json()["items"])


async def test_quick_is_unavailable_while_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "re_quick_enabled", False)
    owner = await register(org_name="M10 Quick Org")
    case_id = await new_case(owner)
    evidence = await upload(owner.client, owner.org_id, case_id, b"MZ" + b"\0" * 4094, "q.bin")
    response = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "reverse", "profile": "quick"},
        headers=csrf(owner.client),
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "profile_unavailable"


@pytest.mark.parametrize("busy", [Analyzer.MEMORY, Analyzer.DISK, Analyzer.REVERSE])
@pytest.mark.parametrize("wanted", ["memory", "reverse"])
async def test_the_heavy_cap_refuses_a_second_heavy_job(
    monkeypatch: pytest.MonkeyPatch, busy: Analyzer, wanted: str
) -> None:
    """RT2: another org's active heavy job blocks this request; the answer names neither the
    job nor the org."""
    monkeypatch.setattr(get_settings(), "analysis_heavy_max_active", 1)
    other = await register(org_name=f"M10 Busy {busy}")
    other_case = uuid.UUID(await new_case(other))
    t = Tenant(other.org_id, other.user_id, other_case)
    if busy == Analyzer.MEMORY:
        busy_job = await seed_memory_job(t, status="running")
    elif busy == Analyzer.DISK:
        busy_job = await seed_disk_job(t, status="running")
    else:
        busy_job = await seed_re_job(t, status="running")
    owner = await register(org_name="M10 Heavy Org")
    case_id = await new_case(owner)
    evidence = await upload(owner.client, owner.org_id, case_id, b"\0" * 4096, "h.bin")
    response = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": wanted},
        headers=csrf(owner.client),
    )
    assert response.status_code == 429, response.text
    error = response.json()["error"]
    assert (error["code"], error["reason"]) == ("too_many_active_jobs", "heavy_analysis_busy")
    assert str(busy_job) not in response.text and str(other.org_id) not in response.text


async def test_explain_function_reaches_the_run_path() -> None:
    """Phase 9 removed the pending refusal: the normal AI checks answer (AI is off here)."""
    owner = await register(org_name="M10 AI Org")
    case_id = uuid.UUID(await new_case(owner))
    t = Tenant(owner.org_id, owner.user_id, case_id)
    job_id = await seed_re_job(t)
    response = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/ai/runs",
        json={"task": "explain_function", "job_id": str(job_id), "target_id": str(uuid.uuid4())},
        headers=csrf(owner.client),
    )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "ai_disabled"


async def test_capabilities_route_carries_locations_and_report_does_not() -> None:
    owner = await register(org_name="M10 Capa Org")
    case_id = uuid.UUID(await new_case(owner))
    t = Tenant(owner.org_id, owner.user_id, case_id)
    static_job = await seed_static_source_job(t)
    page = await owner.client.get(
        f"/api/v1/orgs/{owner.org_id}/analyses/{static_job}/capabilities"
    )
    assert page.status_code == 200, page.text
    items = {i["name"]: i for i in page.json()["items"]}
    assert items["inject thread"]["locations"] == ["0x140001280", "0x1400012a0"]
    assert items["connect to URL"]["locations"] == []
    assert items["inject thread"]["functions"] is None  # phase 8
    schema = app.openapi()["components"]["schemas"]
    assert "locations" not in schema["CapabilityOut"]["properties"]  # RT6: report unchanged
    assert "locations" in schema["CapabilityLinkedOut"]["properties"]
