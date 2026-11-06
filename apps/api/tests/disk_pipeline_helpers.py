"""Helpers of the M9 phase-13 disk pipeline tests: real images, the real broker, the real
`disk-worker-test` (TSK / libewf / Plaso, offline) and the real `disk-ingest-worker-test`.

Setup (the gate, `scripts/verify.mjs`): `pnpm disk:gen -- --only <ids> --test-hashsets` wrote
the generated images into the `cyberlab_e2e_samples` volume under `disk/` (`disk/<id>/`: the
segments and `ground_truth.json`; `disk/hashsets/expected.json`) and imported the test lists
into the test hash-set store as `test-known-good` / `test-known-bad`; api-test then runs with
that volume mounted read-only and `DISK_PIPELINE_IMAGES=/samples/disk`, while
`disk-worker-test` and `disk-ingest-worker-test` consume this lane's broker db.

- `requires_images`: skip unless `DISK_PIPELINE_IMAGES` names that directory and this is the
  default test lane (the workers serve broker db 1 and `cyberlab_test`, like the M2 / M5
  pipeline tests);
- `TIMELINE_ENGINE`: the engine `disk-worker-test` runs (`DISK_PIPELINE_TIMELINE_ENGINE`,
  default `plaso`; the gate's second pass sets `replay` for the Windows artifact run);
- `small_budgets`: the triage / full artifact budgets lowered at dispatch (the API may only
  lower them): the worker's free-space check needs image + 3 x the artifact budget + its floor
  in `/work`, and the test worker's `/work` is a 1 GiB tmpfs (2 GiB triage budget otherwise);
- `upload_image` / `run_image` / `wait_for`: the API flow and the ingest loop (`test.ingest`
  handled in-process like the M2 pipeline test; the disk hand-off is really published to
  `test.ingest_disk`, which `disk-ingest-worker-test` consumes);
- read helpers over the disk routes (`pages`, `find_file`) and the stored findings.
"""

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
from cyberlab_jobs.disk import DiskProfile
from sqlalchemy import text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.disk_forensics import dispatch as disk_dispatch
from app.modules.disk_forensics import handoff
from app.workers import ingest
from tests.analysis_helpers import (
    _connection,
    broker_queue,
    drain_ingest,
    job_status,
    new_case,
    purge_test_queues,
)
from tests.disk_results import run_disk, upload_disk
from tests.factories import Registered

IMAGES_ENV = "DISK_PIPELINE_IMAGES"
IMAGES = Path(os.environ[IMAGES_ENV]) if os.environ.get(IMAGES_ENV) else None
TIMELINE_ENGINE = os.environ.get("DISK_PIPELINE_TIMELINE_ENGINE", "plaso")
FINAL = {"succeeded", "failed"}
# Real TSK + Plaso on a 1 GiB tmpfs with two CPUs: generous, never gated on timing.
JOB_TIMEOUT_S = 900.0
STATIC_TIMEOUT_S = 300.0
# The lowered budgets (`small_budgets`): far above what the generated trees hold.
ARTIFACT_MAX_BYTES = 96 * 1024**2
ARTIFACT_MAX_FILE_BYTES = 32 * 1024**2
KNOWN_GOOD_SET = "test-known-good"
KNOWN_BAD_SET = "test-known-bad"


def _default_lane() -> bool:
    return urlparse(get_settings().broker_url).path in ("/1", "")


requires_images = pytest.mark.skipif(
    IMAGES is None or not IMAGES.is_dir() or not _default_lane(),
    reason=(
        f"{IMAGES_ENV} (pnpm disk:gen output) with disk-worker-test and "
        "disk-ingest-worker-test on the default test lane"
    ),
)


def image_dir(image_id: str) -> Path:
    assert IMAGES is not None
    path = IMAGES / image_id
    if not (path / "ground_truth.json").is_file():
        pytest.skip(f"{image_id} was not generated (pnpm disk:gen -- --only {image_id})")
    return path


def truth(image_id: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((image_dir(image_id) / "ground_truth.json").read_text())
    return data


def expected_hashsets() -> dict[str, list[dict[str, str]]]:
    assert IMAGES is not None
    path = IMAGES / "hashsets" / "expected.json"
    if not path.is_file():
        pytest.skip("no test hash lists (pnpm disk:gen -- --test-hashsets)")
    data: dict[str, list[dict[str, str]]] = json.loads(path.read_text())
    return data


def norm(path: str) -> str:
    """Paths compared without the leading `/` (the walk writes `/a/b`, ground truth `/a/b`,
    some fixtures `a/b`)."""
    return path.lstrip("/")


# --- broker ------------------------------------------------------------------------------------


def purge_disk_queues() -> None:
    """The shared test queues plus the disk ones (a leftover job of an interrupted run must
    not be the next test's)."""
    purge_test_queues()
    with _connection() as conn:
        for name in ("disk", "ingest_disk"):
            conn.default_channel.client.delete(broker_queue(name))


@pytest.fixture
def clean_queues() -> Iterator[None]:
    purge_disk_queues()
    yield
    purge_disk_queues()


@pytest.fixture
def small_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    budgets: dict[DiskProfile, dict[str, int]] = {
        profile: dict(values) for profile, values in disk_dispatch.PROFILE_BUDGETS.items()
    }
    for profile in (DiskProfile.TRIAGE, DiskProfile.FULL):
        budgets[profile]["artifact_max_bytes"] = ARTIFACT_MAX_BYTES
        budgets[profile]["artifact_max_file_bytes"] = ARTIFACT_MAX_FILE_BYTES
    monkeypatch.setattr(disk_dispatch, "PROFILE_BUDGETS", budgets)


# --- API flow ----------------------------------------------------------------------------------


@dataclass
class Run:
    reg: Registered
    case_id: str
    image_id: str
    segments: list[str]  # evidence ids in the set's order
    job_id: str
    truth: dict[str, Any]

    @property
    def base(self) -> str:
        return f"/api/v1/orgs/{self.reg.org_id}/analyses/{self.job_id}/disk"

    @property
    def org(self) -> str:
        return f"/api/v1/orgs/{self.reg.org_id}"


async def upload_files(reg: Registered, case_id: str, files: list[Path]) -> list[str]:
    """Each file as one `kind=disk` upload, in order."""
    ids = []
    for path in files:
        response = await upload_disk(reg, case_id, path.read_bytes(), path.name)
        assert response.status_code == 201, (path.name, response.text)
        ids.append(str(response.json()["id"]))
    return ids


async def upload_image(reg: Registered, case_id: str, image_id: str) -> list[str]:
    """Every segment of a generated image, in the set's order."""
    d = image_dir(image_id)
    return await upload_files(reg, case_id, [d / name for name in truth(image_id)["segments"]])


async def start(reg: Registered, segments: list[str], **body: Any) -> str:
    response = await run_disk(reg, segments[0], segments, **body)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def handle(message: dict[str, Any]) -> None:
    """The shared ingest worker's task body; a busy hand-off is retried like the task does."""
    for attempt in range(10):
        try:
            await ingest.handle_event(message)
            return
        except handoff.HandOffBusy:
            if attempt == 9:
                raise
            await asyncio.sleep(1.0 + attempt)


async def wait_for(
    job_id: str,
    statuses: set[str] = FINAL,
    timeout_s: float = JOB_TIMEOUT_S,
    on_finished: Callable[[], Awaitable[None]] | None = None,
) -> list[str]:
    """Feed every report on `test.ingest` to the real ingest handler until `job_id` reaches
    `statuses` (the disk ingest itself runs on `disk-ingest-worker-test`). `on_finished` runs
    right after this job's `finished` report was handed off."""
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for message in drain_ingest(1.0):
            mine = message.get("job_id") == job_id
            if mine:
                outcome, code = message.get("outcome"), message.get("error_code")
                seen.append(f"{message['event']}:{outcome}:{code}")
            await handle(message)
            if mine and message["event"] == "finished" and on_finished is not None:
                hook, on_finished = on_finished, None
                await hook()
        if await job_status(job_id) in statuses:
            return seen
    raise AssertionError(f"job {job_id} did not reach {statuses}; messages: {seen}")


async def run_image(
    reg: Registered,
    image_id: str,
    *,
    case_id: str | None = None,
    profile: str = "triage",
    on_finished: Callable[[], Awaitable[None]] | None = None,
) -> Run:
    """Upload a generated image, request `profile` over its ordered segments, run it to the end."""
    case_id = case_id or await new_case(reg)
    segments = await upload_image(reg, case_id, image_id)
    job_id = await start(reg, segments, profile=profile)
    await wait_for(job_id, on_finished=on_finished)
    return Run(reg, case_id, image_id, segments, job_id, truth(image_id))


async def job_row(org_id: uuid.UUID, job_id: str | uuid.UUID) -> AnalysisJob:
    async with tenant_session(org_id, None) as s:
        job = await s.get(AnalysisJob, uuid.UUID(str(job_id)))
    assert job is not None
    return job


# --- reads -------------------------------------------------------------------------------------


async def get_json(run: Run, url: str, **params: Any) -> dict[str, Any]:
    response = await run.reg.client.get(url, params=params)
    assert response.status_code == 200, (url, response.text)
    body: dict[str, Any] = response.json()
    return body


async def pages(
    run: Run, url: str, max_pages: int = 100, **params: Any
) -> AsyncIterator[dict[str, Any]]:
    """Every item of a paged route (100 per page)."""
    offset = 0
    for _ in range(max_pages):
        body = await get_json(run, url, limit=100, offset=offset, **params)
        for item in body["items"]:
            yield item
        offset += len(body["items"])
        if not body["items"] or offset >= body["total"]:
            return
    raise AssertionError(f"{url}: more than {max_pages} pages")


async def all_items(run: Run, url: str, **params: Any) -> list[dict[str, Any]]:
    return [item async for item in pages(run, url, **params)]


async def find_files(
    run: Run, path: str, stream: str | None = None, **params: Any
) -> list[dict[str, Any]]:
    """Listed entries with exactly this path (and stream), searched by the base name."""
    name = norm(path).rsplit("/", 1)[-1]
    return [
        f
        for f in await all_items(run, f"{run.base}/files", q=name, include_known=True, **params)
        if norm(f["path"]) == norm(path) and f.get("stream") == stream
    ]


async def find_file(run: Run, path: str, stream: str | None = None) -> dict[str, Any]:
    found = await find_files(run, path, stream)
    assert found, (path, stream)
    return found[0]


@dataclass(frozen=True)
class StoredFinding:
    type: str
    detection_method: str
    title: str
    description: str
    attributes: dict[str, Any]

    def mentions(self, path: str) -> bool:
        """The finding names the file (by its base name: titles shorten long paths)."""
        name = norm(path).rsplit("/", 1)[-1]
        text_ = f"{self.title} {self.description} {json.dumps(self.attributes)}"
        return name in text_


async def findings(org_id: uuid.UUID, job_id: str | uuid.UUID) -> list[StoredFinding]:
    async with tenant_session(org_id, None) as s:
        rows = (
            await s.execute(
                text(
                    "SELECT type, detection_method, title, description, attributes "
                    "FROM analysis_findings WHERE job_id = :job"
                ),
                {"job": uuid.UUID(str(job_id))},
            )
        ).all()
    return [StoredFinding(r[0], r[1], r[2], r[3], dict(r[4] or {})) for r in rows]


async def evidence_sensitivity(run: Run, evidence_id: str) -> tuple[Any, Any, Any]:
    """(sensitivity state, its source, (ai_excluded, ti_excluded)) through the API."""
    sens = await get_json(run, f"{run.org}/evidence/{evidence_id}/sensitivity")
    policy = await get_json(run, f"{run.org}/evidence/{evidence_id}/share-policy")
    return sens["state"], sens["source"], (policy["ai_excluded"], policy["ti_excluded"])
