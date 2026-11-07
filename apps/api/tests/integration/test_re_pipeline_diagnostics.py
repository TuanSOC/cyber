"""M10 phase 12: refusals and diagnostics of reverse engineering on the real workers.

Runs with the pipeline tests (skipped unless `RE_PIPELINE_SAMPLES` names the generated set:
the real `static-worker-test` and `re-worker-test` run on the default lane only then). Both
inputs are built in memory by `tests/re_pipeline_helpers.py` and are never runnable:

- a 32-bit ARM ELF: its static `full` job succeeds, and the RE request is refused at request
  time with `422 unsupported_architecture` (nothing is queued);
- a PE32+ with a CLR runtime header but no `mscoree.dll` import: the API's managed-code check
  (an import of `_CorExeMain` / `_CorDllMain`) passes it, the worker's magic check ends it as
  a diagnostic result: the job fails `unsupported_managed_code` and its program line is
  stored (the summary route answers).
"""

import uuid
from collections.abc import Iterator

import pytest

from tests import re_pipeline_helpers as rp
from tests.analysis_helpers import jobs_for
from tests.factories import csrf, register

pytestmark = rp.requires_samples


@pytest.fixture(autouse=True)
def _clean_queues() -> Iterator[None]:
    rp.purge_re_queues()
    yield
    rp.purge_re_queues()


async def test_an_arm_elf_is_refused_at_request_time() -> None:
    reg = await register(org_name=f"RE ARM {uuid.uuid4().hex[:6]}")
    evidence_id, _ = await rp.static_job(reg, rp.arm_elf(), "arm.elf")
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "reverse", "profile": "full"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "unsupported_architecture"
    jobs = await jobs_for(reg.client, reg.org_id, evidence_id)
    assert [j["analyzer"] for j in jobs] == ["static"]


async def test_a_clr_pe_without_mscoree_ends_as_the_worker_diagnostic() -> None:
    reg = await register(org_name=f"RE CLR {uuid.uuid4().hex[:6]}")
    evidence_id, static_job = await rp.static_job(reg, rp.clr_pe(), "managed.exe")
    job = await rp.request_re(reg, evidence_id, profile="full")
    assert job["source_job_id"] == static_job
    done = await rp.finish(reg, evidence_id, job["id"])
    assert (done["status"], done["error_code"]) == ("failed", "unsupported_managed_code"), done

    summary = await rp.get(reg, f"/analyses/{job['id']}/reverse")
    assert (summary["format"], summary["arch"]) == ("pe", "x86_64"), summary
    assert summary["source_job_id"] == static_job
    # Nothing was analyzed: no function row exists (an empty page or no results at all).
    response = await reg.client.get(
        f"/api/v1/orgs/{reg.org_id}/analyses/{job['id']}/reverse/functions",
        params={"include_library": "true"},
    )
    assert response.status_code in {200, 404}, response.text
    if response.status_code == 200:
        assert response.json()["total"] == 0
