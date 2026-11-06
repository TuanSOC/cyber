"""The memory pipeline end to end (M8 phase 11): upload with `kind=memory` -> the request ->
the real broker -> `memory-worker-test` -> presigned result upload -> the real ingest
handler -> every read route; the sensitivity default, and AI / job TI `policy_blocked`.

Opt-in like the report pipeline: `MEMORY_E2E` names the engine `memory-worker-test` runs on
this lane's broker db (the gate: the default lane, see scripts/verify.mjs):

- `volatility3`: the phase-4 synthetic Linux image (generated in-process from
  `apps/workers/memory/samples`, mounted read-only) analysed by the real Volatility 2.28.2
  against the test symbol store, which holds our synthetic ISF (`pnpm memory:symbols --
  --store test import`); and the changed-banner image, whose ISF the store lacks, ends
  `failed / symbols_missing` with the banner visible through the summary route;
- `replay`: the replay engine (`MEMORY_TEST_ENGINE=replay`) with the Windows row fixtures
  (a `CYBERLAB-REPLAY windows` marker file), so the Windows normalizers, detections and
  tables go through the broker and the ingest too; the store holds the identity-only ISF of
  the fixtures' kernel PDB. The result says `engine: replay`.

Skipped everywhere else (lanes 2-8 have no memory consumer).
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ai_api_helpers import enable_ai, preview
from tests.analysis_helpers import jobs_for, new_case, purge_test_queues, run_ingest_until
from tests.factories import Registered, register
from tests.memory_results import run_memory, upload_memory
from tests.ti_api_helpers import capture_sends, enrich_job
from tests.ti_api_helpers import enable as enable_ti

ENGINE = os.environ.get("MEMORY_E2E", "")
MEMGEN = Path("/srv/memgen")
FINAL = {"succeeded", "failed"}
# Identify + four triage plugins, each a fresh Volatility process on a 16 MiB image.
TIMEOUT_S = 600.0

pytestmark = pytest.mark.skipif(
    ENGINE not in ("volatility3", "replay") or not (MEMGEN / "samples" / "memgen").is_dir(),
    reason="MEMORY_E2E=volatility3|replay with memory-worker-test consuming this lane",
)


def memgen() -> Any:
    if str(MEMGEN) not in sys.path:
        sys.path.insert(0, str(MEMGEN))
    import samples.memgen as module  # stdlib only

    return module


@pytest.fixture(autouse=True)
def _clean_queues() -> Iterator[None]:
    purge_test_queues()
    yield
    purge_test_queues()


def api(reg: Registered, job_id: str, path: str = "") -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/memory{path}"


async def analyse(reg: Registered, image: bytes, filename: str) -> tuple[str, str, list[str]]:
    """Upload, request triage, feed the reports to the ingest: (evidence id, job id, events)."""
    case = await new_case(reg)
    uploaded = await upload_memory(reg, case, image, filename)
    assert uploaded.status_code == 201, uploaded.text
    evidence = uploaded.json()
    # RT3: restricted from the upload, and no automatic job of any kind.
    read = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}")
    assert read.json()["memory_sensitivity"] == "restricted", read.text
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == []
    requested = await run_memory(reg, evidence["id"], profile="triage")
    assert requested.status_code in (201, 202), requested.text
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    seen = await run_ingest_until(job["id"], FINAL, timeout_s=TIMEOUT_S)
    return evidence["id"], job["id"], seen


async def assert_policy_blocked(reg: Registered, job_id: str, monkeypatch: Any) -> None:
    await enable_ai(reg.client, reg.org_id)
    blocked = await preview(reg.client, reg.org_id, task="ioc_correlation", job_id=job_id)
    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["error"]["code"] == "policy_blocked"
    sent = capture_sends(monkeypatch)
    await enable_ti(reg.client, reg.org_id)
    ti = await enrich_job(reg.client, reg.org_id, job_id)
    assert ti.status_code == 409 and ti.json()["error"]["code"] == "policy_blocked", ti.text
    assert sent.runs == []


@pytest.mark.skipif(ENGINE != "volatility3", reason="the real-engine run")
async def test_the_synthetic_linux_image_through_the_real_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gen = memgen()
    reg = await register()
    image = gen.image_bytes("linux_benign", "lime")
    _, job_id, seen = await analyse(reg, image, "synthetic.lime")
    assert seen == ["started:None:None", "finished:succeeded:None"], seen

    summary = (await reg.client.get(api(reg, job_id))).json()
    assert (summary["engine"], summary["os"], summary["layer"]) == ("volatility3", "linux",
                                                                    "LimeLayer")  # fmt: skip
    assert summary["symbols"]["status"] == "resolved" and summary["symbols"]["isf_sha256"]
    assert summary["tool_versions"]["volatility3"] == "2.28.2"
    statuses = {p["plugin"]: p["status"] for p in summary["plugins"]}
    assert statuses == {
        "linux.pslist": "ok",
        "linux.psaux": "ok",
        "linux.bash": "failed",
        "linux.sockstat": "failed",
    }
    assert summary["size_bytes"] == len(image)

    expected = {p.pid: p for p in gen.scenario("linux_benign").procs}
    page = (await reg.client.get(api(reg, job_id, "/processes"), params={"limit": 100})).json()
    assert page["total"] == len(expected)
    procs = {p["pid"]: p for p in page["items"]}
    assert set(procs) == set(expected)
    assert (procs[1]["name"], procs[1]["ppid"]) == ("systemd", 0)
    assert procs[1206]["cmdline"] == "-bash" and procs[2]["cmdline"] == "[kthreadd]"
    detail = await reg.client.get(api(reg, job_id, "/processes/1206"))
    assert detail.status_code == 200, detail.text
    tree = await reg.client.get(api(reg, job_id, "/processes"), params={"view": "tree"})
    assert tree.status_code == 200, tree.text
    for path in ("/connections", "/injections", "/artifacts"):
        response = await reg.client.get(api(reg, job_id, path))
        assert response.status_code == 200, (path, response.text)
        assert response.json()["total"] == 0  # the synthetic kernel describes none

    iocs = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/iocs")
    assert iocs.status_code == 200, iocs.text
    values = {i["value"] for i in iocs.json()["items"]}
    assert "updates.example.com" in values
    await assert_policy_blocked(reg, job_id, monkeypatch)


@pytest.mark.skipif(ENGINE != "volatility3", reason="the real-engine run")
async def test_a_banner_without_symbols_ends_symbols_missing() -> None:
    gen = memgen()
    reg = await register()
    image = gen.image_bytes("symbols_missing", "raw")
    _, job_id, seen = await analyse(reg, image, "unknown-kernel.raw")
    assert seen == ["started:None:None", "finished:failed:symbols_missing"], seen
    job = (await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}")).json()
    assert (job["status"], job["error_code"]) == ("failed", "symbols_missing")
    summary = (await reg.client.get(api(reg, job_id))).json()
    assert summary["symbols"]["status"] == "missing"
    assert summary["symbols"]["linux_banner"] == {"banner": gen.UNKNOWN_BANNER}
    assert summary["plugins"] == []


@pytest.mark.skipif(ENGINE != "replay", reason="the replay-engine run")
async def test_the_windows_rows_through_the_replay_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reg = await register()
    _, job_id, seen = await analyse(reg, b"CYBERLAB-REPLAY windows\n", "replay.vmem")
    assert seen == ["started:None:None", "finished:succeeded:None"], seen
    summary = (await reg.client.get(api(reg, job_id))).json()
    assert (summary["engine"], summary["os"]) == ("replay", "windows")
    assert summary["symbols"]["windows_pdb"]["name"] == "ntkrnlmp.pdb"
    assert all(p["status"] == "ok" for p in summary["plugins"]), summary["plugins"]
    hidden = await reg.client.get(api(reg, job_id, "/processes"), params={"hidden": "true"})
    assert hidden.status_code == 200 and hidden.json()["total"] >= 1, hidden.text
    for path in ("/connections", "/injections", "/artifacts"):
        response = await reg.client.get(api(reg, job_id, path))
        assert response.status_code == 200 and response.json()["total"] > 0, path
    findings = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/findings")
    assert findings.status_code == 200 and findings.json()["total"] > 0, findings.text
    await assert_policy_blocked(reg, job_id, monkeypatch)
