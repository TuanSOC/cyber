"""The memory read API (M8 phase 7) over jobs seeded from the phase-1 `memory.v1` fixtures:
the summary, processes (list, filters, `ref`, pagination, child counts), one process with
what references it, connections, private executable regions and artifacts; `404` for
unknown, foreign, pcap and static jobs; `409 analysis_not_ready` while queued or running;
raw command lines on the job pages (RT13 masks only the shared surfaces)."""

import secrets
import uuid
from typing import Any

from cyberlab_jobs.memory import OsHint
from httpx import AsyncClient

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.evidence.models import EvidenceHash, HashAlgorithm
from app.modules.memory_analysis.models import MemoryImage
from app.modules.organizations.models import MemberRole
from tests.case_helpers import seed_evidence, seed_job_on
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email
from tests.integration.seed import Tenant
from tests.memory_helpers import _rows, memory_fixture, seed_memory_job

ROUTES = ("", "/processes", "/processes/6112", "/connections", "/injections", "/artifacts")
SHA256 = "a" * 64


async def _tenant(reg: Registered) -> Tenant:
    created = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Memory case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(created.json()["id"]))


def _base(reg: Registered, job_id: uuid.UUID) -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/memory"


async def _get(client: AsyncClient, url: str, **params: Any) -> dict[str, Any]:
    response = await client.get(url, params=params)
    assert response.status_code == 200, (url, response.text)
    body: dict[str, Any] = response.json()
    return body


async def _job(
    t: Tenant,
    *,
    fixture: str | None = "windows_triage.ndjson",
    status: str = "succeeded",
    error_code: str | None = None,
    summary: dict[str, Any] | None = None,
    counts: dict[str, int] | None = None,
) -> uuid.UUID:
    """A terminal memory job written in one go, as the ingest would (the job guard makes a
    terminal job final): a hashed evidence record, the job with its summary and the
    fixture's `memory_*` rows."""
    evidence_id = await seed_evidence(t, filename="memory.raw")
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            EvidenceHash(
                organization_id=t.org_id,
                evidence_id=evidence_id,
                algorithm=HashAlgorithm.SHA256,
                value=SHA256,
            )
        )
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence_id,
            analyzer=Analyzer.MEMORY,
            profile=JobProfile.TRIAGE,
            os_hint=OsHint.AUTO,
            status=AnalysisStatus(status),
            error_code=error_code,
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
            summary=summary or {},
        )
        s.add(job)
        await s.flush()
        rows = _rows(t.org_id, job.id, memory_fixture(fixture)) if fixture else []
        for row in rows:
            if isinstance(row, MemoryImage) and counts is not None:
                row.counts = counts
        s.add_all(rows)
    return job.id


async def _windows(reg: Registered) -> tuple[uuid.UUID, str]:
    job = await seed_memory_job(await _tenant(reg))
    return job, _base(reg, job)


async def test_summary_shows_trusted_hashes_image_facts_and_plugin_status() -> None:
    reg = await register(org_name="Memory Summary Org")
    job = await _job(
        await _tenant(reg),
        summary={
            "tool_versions": {"volatility3": "2.28.2", "fixture": "synthetic"},
            "truncated": {"artifacts": True},
            "engine_errors": ["plugin_timeout"],
        },
        counts={"orphan_ref": 2, "processes": 999},
    )
    body = await _get(reg.client, _base(reg, job))
    assert body["job_id"] == str(job)
    assert (body["profile"], body["os"], body["engine"]) == ("triage", "windows", "replay")
    assert (body["arch"], body["nt_build"]) == ("x64", "19041")
    assert body["layer"] == "WindowsCrashDump64Layer>WindowsIntel32e"
    assert body["system_time"].startswith("2026-11-01T09:30:00")
    # The evidence record's values, never the worker's image line (sha256 b..b, 64 MiB).
    assert (body["size_bytes"], body["sha256"]) == (1024, SHA256)
    assert body["symbols"] == {
        "status": "resolved",
        "isf_sha256": "c" * 64,
        "windows_pdb": {
            "name": "ntkrnlmp.pdb",
            "guid": "0123456789ABCDEF0123456789ABCDEF",
            "age": 1,
        },
        "linux_banner": None,
    }
    assert body["tool_versions"] == {"volatility3": "2.28.2", "fixture": "synthetic"}
    assert len(body["plugins"]) == 10
    assert body["plugins"][0] == {
        "plugin": "windows.info",
        "status": "ok",
        "rows": 1,
        "truncated": False,
        "duration_ms": 1000,
        "error_code": None,
    }
    # Live counts win over stored ones; other stored keys are kept.
    assert body["counts"] == {
        "orphan_ref": 2,
        "processes": 40,
        "connections": 3,
        "injections": 1,
        "artifacts": 6,
        "findings": 0,
        "iocs": 0,
        "timeline": 0,
    }
    assert body["truncated"] == {"artifacts": True}
    assert body["engine_errors"] == ["plugin_timeout"]


async def test_summary_without_a_stored_job_summary_falls_back() -> None:
    reg = await register(org_name="Memory Summary Fallback Org")
    job, base = await _windows(reg)
    body = await _get(reg.client, base)
    assert body["tool_versions"] == {"volatility3": "2.28.2"}
    assert (body["truncated"], body["engine_errors"]) == ({}, [])


async def test_linux_summary_shows_the_banner_as_text_only() -> None:
    reg = await register(org_name="Memory Linux Org")
    job = await _job(await _tenant(reg), fixture="linux_triage.ndjson")
    body = await _get(reg.client, _base(reg, job))
    assert body["os"] == "linux" and body["nt_build"] is None
    assert body["symbols"]["windows_pdb"] is None
    assert body["symbols"]["linux_banner"]["banner"].startswith("Linux version 6.1.0-26-amd64")


async def test_symbols_missing_job_has_a_summary_and_no_rows() -> None:
    reg = await register(org_name="Memory Symbols Org")
    job = await _job(
        await _tenant(reg),
        fixture="symbols_missing.ndjson",
        status="failed",
        error_code="symbols_missing",
    )
    base = _base(reg, job)
    body = await _get(reg.client, base)
    assert body["symbols"]["status"] == "missing"
    assert body["symbols"]["windows_pdb"]["name"] == "ntkrnlmp.pdb"
    assert body["plugins"] == []
    assert body["counts"]["processes"] == 0
    for path in ROUTES[1:]:
        if path == "/processes/6112":
            assert (await reg.client.get(base + path)).status_code == 404
        else:
            assert await _get(reg.client, base + path) == {"items": [], "total": 0}, path


async def test_a_failed_job_without_a_result_has_no_summary() -> None:
    reg = await register(org_name="Memory Failed Org")
    memory_job = await _job(
        await _tenant(reg), fixture=None, status="failed", error_code="memory_parse_failed"
    )
    response = await reg.client.get(_base(reg, memory_job))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "results_not_available"
    assert await _get(reg.client, _base(reg, memory_job) + "/processes") == {
        "items": [],
        "total": 0,
    }


async def test_queued_and_running_jobs_are_not_ready() -> None:
    reg = await register(org_name="Memory Not Ready Org")
    t = await _tenant(reg)
    for status in ("queued", "running"):
        evidence_id = await seed_evidence(t, filename=f"{status}.raw")
        job = await seed_memory_job(t, evidence_id, status=status, fixture=None)
        for path in ROUTES:
            response = await reg.client.get(_base(reg, job) + path)
            assert response.status_code == 409, (status, path, response.text)
            assert response.json()["error"]["code"] == "analysis_not_ready"


async def test_unknown_foreign_pcap_and_static_jobs_are_404() -> None:
    reg = await register(org_name="Memory 404 Org")
    t = await _tenant(reg)
    job = await seed_memory_job(t)
    pcap = await seed_job_on(t, await seed_evidence(t), "pcap")
    static = await seed_job_on(t, await seed_evidence(t, filename="x.exe"), "static")
    other = await register(org_name="Memory 404 Other Org")
    for path in ROUTES:
        for job_id in (uuid.uuid4(), pcap, static):
            response = await reg.client.get(_base(reg, job_id) + path)
            assert response.status_code == 404, (job_id, path)
        foreign = await other.client.get(_base(other, job) + path)
        assert foreign.status_code == 404, path
        cross = await other.client.get(_base(reg, job) + path)
        assert cross.status_code == 404, path


async def test_process_list_filters_and_pages() -> None:
    reg = await register(org_name="Memory Process Org")
    _, base = await _windows(reg)
    c = reg.client
    first = await _get(c, f"{base}/processes", limit=5)
    second = await _get(c, f"{base}/processes", limit=5, offset=5)
    assert first["total"] == second["total"] == 40
    pids = [p["pid"] for p in first["items"] + second["items"]]
    assert pids == sorted(pids) and len(set(pids)) == 10
    system = first["items"][0]
    assert system["name"] == "System" and system["offset"] == 18446639134773608448
    assert system["sources"] == ["pslist", "psscan"] and system["children"] == 2

    hidden = await _get(c, f"{base}/processes", hidden="true")
    assert [(p["pid"], p["sources"]) for p in hidden["items"]] == [(6112, ["psscan"])]
    assert (await _get(c, f"{base}/processes", hidden="false"))["total"] == 39
    children = await _get(c, f"{base}/processes", ppid=3040)
    assert children["total"] == 7
    services = await _get(c, f"{base}/processes", q="services.exe")
    assert [p["children"] for p in services["items"]] == [14]
    # `q` covers name, image path and command line, case-insensitively, as a literal.
    assert (await _get(c, f"{base}/processes", q="SVCH0ST"))["total"] == 1
    assert (await _get(c, f"{base}/processes", q="windows defender"))["total"] == 1
    assert (await _get(c, f"{base}/processes", q="100%"))["total"] == 0
    assert (await _get(c, f"{base}/processes", q="svchost", ppid=804))["total"] == 0

    # Raw command lines on the job page (secrets are masked only on shared surfaces, RT13).
    shell = (await _get(c, f"{base}/processes", q="powershell"))["items"][0]
    assert "-enc SQBFAFgA" in shell["cmdline"]

    ref = await _get(c, f"{base}/processes", ref=shell["id"])
    assert [p["id"] for p in ref["items"]] == [shell["id"]] and ref["total"] == 1
    missing = await c.get(f"{base}/processes", params={"ref": str(uuid.uuid4())})
    assert missing.status_code == 404
    assert (await c.get(f"{base}/processes", params={"limit": 101})).status_code == 422
    assert (await c.get(f"{base}/processes", params={"q": "a\x00b"})).status_code == 422


async def test_process_detail_with_its_references() -> None:
    reg = await register(org_name="Memory Detail Org")
    _, base = await _windows(reg)
    c = reg.client
    body = await _get(c, f"{base}/processes/6112")
    assert body["process"]["name"] == "svch0st.exe"
    assert body["process"]["sources"] == ["psscan"]
    assert body["parent"]["pid"] == 3040 and body["parent"]["children"] == 7
    assert body["children"] == [] and body["instances"] == 1
    [conn] = body["connections"]
    assert (conn["remote_addr"], conn["remote_port"], conn["state"]) == (
        "203.0.113.50",
        443,
        "ESTABLISHED",
    )
    [region] = body["injections"]
    assert (region["start"], region["end"], region["has_pe"]) == (4194304, 4259839, True)
    assert region["head_hex"].startswith("4d5a9000")  # hex text, never bytes
    assert region["disasm"] == "0x400000: dec ebp\n0x400001: pop edx"
    assert [a["type"] for a in body["artifacts"]] == ["ldr_unlinked"]

    explorer = await _get(c, f"{base}/processes/3040")
    assert len(explorer["children"]) == 7 and explorer["parent"]["pid"] == 3004
    orphan = await _get(c, f"{base}/processes/544")  # wininit: its smss parent exited
    assert orphan["parent"] is None and len(orphan["children"]) == 3
    assert (await c.get(f"{base}/processes/99999")).status_code == 404
    assert (await c.get(f"{base}/processes/{2**32}")).status_code == 422


async def test_connections_filters() -> None:
    reg = await register(org_name="Memory Connection Org")
    _, base = await _windows(reg)
    c = reg.client
    everything = await _get(c, f"{base}/connections")
    assert everything["total"] == 3
    wildcard = "0.0.0.0"  # noqa: S104 - a fixture value, not a bind
    assert {x["local_addr"] for x in everything["items"]} == {"10.0.0.15", wildcard, "::"}
    assert everything["items"][0]["pid"] == 4  # ordered by pid
    assert (await _get(c, f"{base}/connections", pid=6112))["total"] == 1
    assert (await _get(c, f"{base}/connections", q="203.0.113"))["total"] == 1
    assert (await _get(c, f"{base}/connections", q="listen"))["total"] == 1
    assert (await _get(c, f"{base}/connections", q="msedge"))["total"] == 1
    assert (await _get(c, f"{base}/connections", q="/32"))["total"] == 0  # host(), no mask
    one = everything["items"][1]
    assert (await _get(c, f"{base}/connections", ref=one["id"]))["items"] == [one]


async def test_injection_rows_are_text() -> None:
    reg = await register(org_name="Memory Injection Org")
    _, base = await _windows(reg)
    c = reg.client
    body = await _get(c, f"{base}/injections")
    assert body["total"] == 1
    [region] = body["items"]
    assert region["protection"] == "PAGE_EXECUTE_READWRITE" and region["private"] is True
    assert isinstance(region["head_hex"], str)
    assert (await _get(c, f"{base}/injections", pid=4))["total"] == 0
    assert (await _get(c, f"{base}/injections", pid=6112, ref=region["id"]))["total"] == 1
    wrong = await c.get(f"{base}/injections", params={"pid": 4, "ref": region["id"]})
    assert wrong.status_code == 404


async def test_artifact_filters() -> None:
    reg = await register(org_name="Memory Artifact Org")
    _, base = await _windows(reg)
    c = reg.client
    body = await _get(c, f"{base}/artifacts")
    assert body["total"] == 6
    types = [a["type"] for a in body["items"]]
    assert types == sorted(types)
    assert (await _get(c, f"{base}/artifacts", type="service"))["total"] == 2
    assert (await _get(c, f"{base}/artifacts", type="service", pid=1388))["total"] == 1
    updater = await _get(c, f"{base}/artifacts", q="updater")
    assert [a["attributes"]["name"] for a in updater["items"]] == ["UpdaterSvc"]
    assert updater["items"][0]["pid"] is None
    # Values only, never keys.
    assert (await _get(c, f"{base}/artifacts", q="binary"))["total"] == 0
    assert (await _get(c, f"{base}/artifacts", type="bash"))["total"] == 0
    assert (await c.get(f"{base}/artifacts", params={"type": "yara"})).status_code == 422
    module = (await _get(c, f"{base}/artifacts", type="module"))["items"][0]
    assert module["attributes"]["base"] == 140715161255936  # scalars as stored


async def test_linux_bash_history_is_raw_on_the_job_page() -> None:
    reg = await register(org_name="Memory Bash Org")
    job = await _job(await _tenant(reg), fixture="linux_triage.ndjson")
    base = _base(reg, job)
    bash = await _get(reg.client, f"{base}/artifacts", type="bash")
    assert bash["total"] == 2
    assert {a["attributes"]["command"] for a in bash["items"]} >= {
        "mysql -u root -pHunter2pass appdb"
    }
    unix = await _get(reg.client, f"{base}/connections", q="journal")
    assert unix["items"][0]["proto"] == "unix" and unix["items"][0]["local_addr"] is None


async def test_viewer_reads_and_shared_routes_serve_memory_jobs() -> None:
    reg = await register(org_name="Memory Viewer Org")
    job, base = await _windows(reg)
    email = unique_email("memory-viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)
    assert (await _get(viewer, base))["os"] == "windows"
    for path in ROUTES[1:]:
        assert (await viewer.get(base + path)).status_code == 200, path
    shared = f"/api/v1/orgs/{reg.org_id}/analyses/{job}"
    for path in ("/findings", "/iocs", "/timeline"):
        assert (await reg.client.get(shared + path)).status_code == 200, path
