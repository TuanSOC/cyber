"""M10 phase 8: the RE read API and the capability -> functions link of the static side.

The main job is a real one: requested through the API from a static source with capa
locations and finished through the phase-7 ingest with the `pe_full` fixture (so findings,
IOCs and capa links exist). Seeded jobs (`tests/reverse_helpers.seed_re_job`) cover the job
states, the analyzer / org mix-ups, a 10 000-caller hub and addresses above 2**53. Expected
values come from the fixture itself.
"""

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import insert, select

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.reverse_engineering.models import ReCallEdge, ReFunction
from app.modules.static_analysis.models import MalwareCapability
from app.workers import ingest
from tests import memory_results as mr
from tests import reverse_results as rr
from tests.analysis_helpers import SentJobs, new_case
from tests.factories import Registered, register
from tests.integration.seed import Tenant
from tests.reverse_helpers import seed_re_job, seed_static_source_job

ENTRY = 0x140001000  # `entry` (export, rank 0)
MAIN = 0x140001060
INJECT = 0x1400011E0
RESOLVE = 0x140001320
BEACON = 0x140001440
INSTALL = 0x140001550
DECODE = 0x140001610
PRINT_BANNER = 0x1400017B0
SERVICE_MAIN = 0x1400017F0


def h(value: int) -> str:
    return f"0x{value:x}"


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _ingested(
    sent: SentJobs, reg: Registered | None = None, evidence_id: str | None = None
) -> tuple[Registered, dispatch.DispatchInput, str]:
    """A succeeded RE job of the `pe_full` fixture (with links, findings and IOCs)."""
    if reg is None:
        reg = await register(org_name="RE Reads Org")
    if evidence_id is None:
        evidence_id, _ = await rr.static_source(sent, reg)
    response = await rr.request_re(reg, evidence_id)
    assert response.status_code == 201, response.text
    item = sent[-1]
    size, sha256 = await mr.evidence_identity(reg.org_id, item.job_id)
    await mr.deliver(item, rr.stream(item.job_id, size=size, sha256=sha256))
    return reg, item, evidence_id


def _base(reg: Registered, job_id: uuid.UUID | str) -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/reverse"


async def _get(reg: Registered, url: str, **params: Any) -> Any:
    response = await reg.client.get(url, params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def _status(reg: Registered, url: str, **params: Any) -> tuple[int, str | None]:
    response = await reg.client.get(url, params=params)
    code = response.json().get("error", {}).get("code") if response.status_code >= 400 else None
    return response.status_code, code


def _entries(page: dict[str, Any]) -> list[str]:
    return [item["entry"] for item in page["items"]]


# --- summary ---------------------------------------------------------------------------------


async def test_the_summary_shows_the_program_stages_counts_and_the_newer_job(
    sent: SentJobs,
) -> None:
    reg, item, evidence_id = await _ingested(sent)
    body = await _get(reg, _base(reg, item.job_id))
    assert body["job_id"] == str(item.job_id) and body["evidence_id"] == evidence_id
    assert body["source_job_id"] == str(item.re_source.job_id)
    assert (body["profile"], body["engine"], body["engine_version"]) == ("full", "replay", "12.2")
    assert (body["format"], body["arch"], body["bits"], body["code_kind"]) == (
        "pe",
        "x86_64",
        64,
        "pseudo_c",
    )
    assert body["image_base"] == body["preferred_base"] == "0x140000000"
    assert body["entry"] == h(ENTRY) and body["analysis_status"] == "complete"
    assert [(s["stage"], s["status"]) for s in body["stages"]] == [
        ("analyze", "ok"),
        ("decompile", "ok"),
    ]
    assert body["stages"][0]["peak_memory_bytes"] == 1_610_612_736
    assert body["counts"]["functions"] == 31 and body["counts"]["capa_linked"] == 3
    assert body["counts"]["capa_unlocated"] == 1
    assert body["truncated"] == {} and body["tool_versions"]["ghidra"] == "12.2"
    assert body["decompile_addresses"] == [] and body["newer_job_id"] is None

    # "Decompile this function": a newer job of the same sample; the old page links to it.
    response = await rr.request_re(reg, evidence_id, decompile_addresses=[h(DECODE)])
    assert response.status_code == 201, response.text
    newer = response.json()["id"]
    assert (await _get(reg, _base(reg, item.job_id)))["newer_job_id"] == newer


async def test_job_states_and_analyzers(sent: SentJobs) -> None:
    reg = await register(org_name="RE States Org")
    t = Tenant(reg.org_id, reg.user_id, uuid.UUID(await new_case(reg)))
    queued = await seed_re_job(t, status="queued", fixture=None)
    for path in ("", "/functions", f"/functions/{h(ENTRY)}", f"/functions/{h(ENTRY)}/code",
                 "/imports", "/strings"):  # fmt: skip
        assert await _status(reg, _base(reg, queued) + path) == (409, "analysis_not_ready")
    # A job the worker failed without a result: terminal, nothing stored.
    evidence_id, _ = await rr.static_source(sent, reg)
    assert (await rr.request_re(reg, evidence_id)).status_code == 201
    failed = sent[-1]
    await ingest.handle_event(
        {
            "job_id": str(failed.job_id),
            "organization_id": str(reg.org_id),
            "ingest_token": failed.ingest_token,
            "event": "finished",
            "outcome": "failed",
            "error_code": "analysis_timeout",
            "worker_version": rr.WORKER,
        }
    )
    assert await _status(reg, _base(reg, failed.job_id)) == (404, "results_not_available")
    assert (await _get(reg, _base(reg, failed.job_id) + "/functions"))["total"] == 0
    # A static job id on the RE routes; an RE job id on the static capability route.
    static = await seed_static_source_job(t)
    assert (await _status(reg, _base(reg, static)))[0] == 404
    succeeded = await seed_re_job(t, static)
    capability = await _capability_id(reg, static, "inject thread")
    url = f"/api/v1/orgs/{reg.org_id}/analyses/{succeeded}/capabilities/{capability}/functions"
    assert (await _status(reg, url))[0] == 404


# --- functions -------------------------------------------------------------------------------


async def test_functions_page_order_filters_and_priority_reasons(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    url = f"{_base(reg, item.job_id)}/functions"
    page = await _get(reg, url, limit=100)
    assert page["total"] == 29  # the two FID library functions are hidden by default
    assert _entries(page)[:4] == [h(ENTRY), h(MAIN), h(INJECT), h(RESOLVE)]
    ranks = [i["priority_rank"] for i in page["items"]]
    ranked = [r for r in ranks if r is not None]
    assert ranked == sorted(ranked) and ranks[len(ranked) :] == [None] * (len(ranks) - len(ranked))
    by_entry = {i["entry"]: i for i in page["items"]}
    reasons = {e: by_entry[h(e)]["priority_reason"] for e in (ENTRY, MAIN, INJECT, RESOLVE,
               BEACON, INSTALL, SERVICE_MAIN)}  # fmt: skip
    assert reasons == {
        ENTRY: "entry_or_export",
        MAIN: "size",
        INJECT: "capability",
        RESOLVE: "capability",
        BEACON: "suspicious_import",
        INSTALL: "suspicious_import",
        SERVICE_MAIN: "entry_or_export",
    }
    inject = by_entry[h(INJECT)]
    assert inject["name"] == "inject_remote" and inject["capabilities"] == 1
    assert inject["decompile_status"] == "ok" and inject["rva"] == "0x11e0"
    assert by_entry[h(BEACON)]["decompile_status"] == "timeout"
    assert all(i["priority_reason"] is None for i in page["items"] if i["priority_rank"] is None)

    assert (await _get(reg, url, include_library="true"))["total"] == 31
    assert _entries(await _get(reg, url, q="INJECT")) == [h(INJECT)]
    decompiled = await _get(reg, url, decompiled="true")
    assert set(_entries(decompiled)) == {h(e) for e in (ENTRY, MAIN, INJECT, RESOLVE, DECODE)}
    assert (await _get(reg, url, decompiled="false"))["total"] == 29 - 5
    assert set(_entries(await _get(reg, url, has_capability="true"))) == {h(INJECT), h(RESOLVE)}
    suspicious = await _get(reg, url, calls_suspicious_import="true")
    assert set(_entries(suspicious)) == {h(INJECT), h(INSTALL), h(BEACON)}
    assert _entries(await _get(reg, url, references_ioc_string="true")) == [h(BEACON)]
    both = await _get(reg, url, calls_suspicious_import="true", references_ioc_string="false")
    assert set(_entries(both)) == {h(INJECT), h(INSTALL)}
    # `ref`: one row of the job (a library function too), or 404.
    library = (await _get(reg, url, include_library="true", q="_initterm"))["items"][0]
    assert _entries(await _get(reg, url, ref=library["id"])) == [library["entry"]]
    assert (await _status(reg, url, ref=str(uuid.uuid4())))[0] == 404
    for bad in ({"q": ""}, {"q": "x" * 129}, {"limit": 101}):
        assert (await _status(reg, url, **bad))[0] == 422


async def test_function_detail_links_everything_about_it(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    body = await _get(reg, f"{_base(reg, item.job_id)}/functions/{h(INJECT)}")
    assert body["function"]["entry"] == h(INJECT) and body["body_truncated"] is False
    assert body["body"] == [{"start": "0x11e0", "end": "0x1320"}]
    assert body["callers"] == [{"entry": h(MAIN), "name": "main"}]
    assert len(body["callees"]) == 3  # the three import thunks
    assert {i["name"] for i in body["imports"]} == {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }
    [capability] = body["capabilities"]
    assert capability["name"] == "inject thread" and capability["file_va"] == "0x140001280"
    assert capability["static_job_id"] == str(item.re_source.job_id)
    assert len(body["finding_ids"]) == 1
    assert body["decompilation"]["status"] == "ok" and body["decompilation"]["lines"] > 0

    resolve = await _get(reg, f"{_base(reg, item.job_id)}/functions/{h(RESOLVE)}")
    assert {s["value"] for s in resolve["strings"]} == {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }
    assert resolve["strings"][0]["address"].startswith("0x")

    detail = f"{_base(reg, item.job_id)}/functions"
    assert await _status(reg, f"{detail}/0x1") == (404, "function_not_found")
    for bad in ("401000", "0x", "0x" + "1" * 17, "0xzz"):
        assert (await _status(reg, f"{detail}/{bad}"))[0] in (404, 422), bad


async def test_function_code_is_json_text_and_never_cached(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    url = f"{_base(reg, item.job_id)}/functions/{h(INJECT)}/code"
    response = await reg.client.get(url)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    [fixture] = [
        o for o in rr.parsed() if o["kind"] == "decompiled" and o["function_entry"] == INJECT
    ]
    assert body["code"] == fixture["code"] and body["code_sha256"] == fixture["code_sha256"]
    assert (body["entry"], body["name"], body["status"]) == (h(INJECT), "inject_remote", "ok")
    truncated = await _get(reg, f"{_base(reg, item.job_id)}/functions/{h(DECODE)}/code")
    assert truncated["status"] == "truncated" and truncated["truncated_bytes"] > 0
    for entry in (BEACON, PRINT_BANNER):  # timeout (no code), not selected
        status = await _status(reg, f"{_base(reg, item.job_id)}/functions/{h(entry)}/code")
        assert status == (404, "code_not_available")


# --- imports and strings ---------------------------------------------------------------------


async def test_imports_and_strings_carry_their_functions(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    imports = await _get(reg, f"{_base(reg, item.job_id)}/imports", limit=100)
    assert imports["total"] == 8
    by_name = {i["name"]: i for i in imports["items"]}
    assert by_name["VirtualAllocEx"]["function_count"] == 1
    assert by_name["VirtualAllocEx"]["functions"] == [{"entry": h(INJECT), "name": "inject_remote"}]
    ordinal = by_name[None]
    assert ordinal["library"] == "WS2_32.DLL" and ordinal["functions"][0]["name"] == "beacon"
    kernel = await _get(reg, f"{_base(reg, item.job_id)}/imports", library="kernel32.dll")
    assert kernel["total"] == 5
    assert (await _get(reg, f"{_base(reg, item.job_id)}/imports", q="Remote"))["total"] == 1

    strings_url = f"{_base(reg, item.job_id)}/strings"
    everything = await _get(reg, strings_url, limit=100)
    referenced = await _get(reg, strings_url, referenced="true", limit=100)
    unreferenced = await _get(reg, strings_url, referenced="false", limit=100)
    assert referenced["total"] + unreferenced["total"] == everything["total"]
    assert all(s["function_count"] >= 1 for s in referenced["items"])
    assert all(s["function_count"] == 0 for s in unreferenced["items"])
    [gate] = (await _get(reg, strings_url, q="gate.php"))["items"]
    assert gate["functions"] == [{"entry": h(BEACON), "name": "beacon"}]


# --- capability -> functions -----------------------------------------------------------------


async def _capability_id(reg: Registered, static_job: uuid.UUID, name: str) -> uuid.UUID:
    async with tenant_session(reg.org_id, None) as session:
        found = await session.scalar(
            select(MalwareCapability.id).where(
                MalwareCapability.job_id == static_job, MalwareCapability.name == name
            )
        )
    assert found is not None
    return found


async def test_capabilities_link_to_functions_both_ways(sent: SentJobs) -> None:
    reg = await register(org_name="RE Capability Org")
    evidence_id, static_job = await rr.static_source(sent, reg)
    static_url = f"/api/v1/orgs/{reg.org_id}/analyses/{static_job}"
    inject = await _capability_id(reg, static_job, "inject thread")
    outside = await _capability_id(reg, static_job, "write file outside any function")

    # Before any RE job: locations, no function count, nothing linked.
    before = {i["name"]: i for i in (await _get(reg, f"{static_url}/capabilities"))["items"]}
    assert before["inject thread"]["functions"] is None
    empty = await _get(reg, f"{static_url}/capabilities/{inject}/functions")
    assert (empty["re_job_id"], empty["functions"], empty["unlocated"]) == (None, [], 2)
    assert empty["locations"] == ["0x140001280", "0x1400012a0"]

    _, item, _ = await _ingested(sent, reg, evidence_id)
    after = {i["name"]: i for i in (await _get(reg, f"{static_url}/capabilities"))["items"]}
    assert {name: i["functions"] for name, i in after.items()} == {
        "inject thread": 1,
        "link function at runtime on Windows": 1,
        "connect to URL": 0,
        "write file outside any function": 0,
    }
    linked = await _get(reg, f"{static_url}/capabilities/{inject}/functions")
    assert linked["re_job_id"] == str(item.job_id) and linked["unlocated"] == 0
    assert linked["capability"]["name"] == "inject thread"
    assert linked["functions"] == [
        {
            "re_job_id": str(item.job_id),
            "function": {"entry": h(INJECT), "name": "inject_remote"},
            "file_va": "0x140001280",
        }
    ]
    lone = await _get(reg, f"{static_url}/capabilities/{outside}/functions")
    assert (lone["functions"], lone["unlocated"]) == ([], 1)
    # A capability of another static job of the org is not this job's.
    _, other_static = await rr.static_source(sent, reg)
    other = await _capability_id(reg, other_static, "inject thread")
    assert (await _status(reg, f"{static_url}/capabilities/{other}/functions"))[0] == 404
    assert (await _status(reg, f"{static_url}/capabilities/{uuid.uuid4()}/functions"))[0] == 404


async def test_another_org_sees_nothing(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    attacker = await register(org_name="RE Attacker Org")
    paths = ("", "/functions", f"/functions/{h(INJECT)}", f"/functions/{h(INJECT)}/code",
             "/imports", "/strings")  # fmt: skip
    for path in paths:
        own_org = f"/api/v1/orgs/{attacker.org_id}/analyses/{item.job_id}/reverse{path}"
        assert (await _status(attacker, own_org))[0] == 404, path
        victim_org = _base(reg, item.job_id) + path
        assert (await _status(attacker, victim_org))[0] in (403, 404), path


# --- caps and precision ----------------------------------------------------------------------

Seed = Callable[[list[dict[str, Any]], list[dict[str, Any]]], Awaitable[uuid.UUID]]


@pytest.fixture
def seeded() -> Callable[[Registered], Seed]:
    """A succeeded RE job of `reg` with the given function and call-edge rows (no fixture)."""

    def for_org(reg: Registered) -> Seed:
        async def seed(functions: list[dict[str, Any]], edges: list[dict[str, Any]]) -> uuid.UUID:
            t = Tenant(reg.org_id, reg.user_id, uuid.UUID(await new_case(reg)))
            job_id = await seed_re_job(t, fixture=None)
            scope = {"organization_id": reg.org_id, "job_id": job_id}
            async with tenant_session(reg.org_id, reg.user_id) as s:
                for start in range(0, len(functions), 2000):
                    rows = [{**f, **scope} for f in functions[start : start + 2000]]
                    await s.execute(insert(ReFunction), rows)
                for start in range(0, len(edges), 2000):
                    rows = [{**e, **scope} for e in edges[start : start + 2000]]
                    await s.execute(insert(ReCallEdge), rows)
            return job_id

        return seed

    return for_org


def _function(entry: int, name: str, **fields: Any) -> dict[str, Any]:
    return {
        "entry": entry,
        "rva": entry & 0xFFFFFFFF,
        "name": name,
        "name_source": "generated",
        "size": 16,
        "body": [],
        "instructions": 4,
        "callers": 0,
        "callees": 0,
        "decompile_status": "not_selected",
        **fields,
    }


async def test_a_hub_function_keeps_its_lists_within_the_cap(
    seeded: Callable[[Registered], Seed],
) -> None:
    reg = await register(org_name="RE Hub Org")
    hub = 0x400000
    callers = [0x500000 + 16 * i for i in range(10_000)]
    functions = [_function(hub, "hub", callers=len(callers), callees=len(callers))]
    functions += [_function(c, f"FUN_{c:x}", callees=1, callers=1) for c in callers]
    edges = [{"caller_entry": c, "callee_entry": hub, "sites": 1} for c in callers]
    edges += [{"caller_entry": hub, "callee_entry": c, "sites": 1} for c in callers]
    job_id = await seeded(reg)(functions, edges)
    body = await _get(reg, f"{_base(reg, job_id)}/functions/{h(hub)}")
    assert len(body["callers"]) == len(body["callees"]) == 200
    assert body["callers"][0]["entry"] == h(callers[0])  # by entry
    assert (body["function"]["callers"], body["function"]["callees"]) == (10_000, 10_000)
    page = await _get(reg, f"{_base(reg, job_id)}/functions", limit=100, offset=9_950)
    assert page["total"] == 10_001 and len(page["items"]) == 51


async def test_addresses_above_2_53_stay_exact(seeded: Callable[[Registered], Seed]) -> None:
    reg = await register(org_name="RE Precision Org")
    top = 2**64 - 16
    job_id = await seeded(reg)([_function(top, "at_the_top", rva=2**53 + 1)], [])
    body = await _get(reg, f"{_base(reg, job_id)}/functions/{h(top)}")
    assert body["function"]["entry"] == "0xfffffffffffffff0"
    assert body["function"]["rva"] == h(2**53 + 1)
    listed = await _get(reg, f"{_base(reg, job_id)}/functions")
    assert _entries(listed) == ["0xfffffffffffffff0"]
