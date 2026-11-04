"""Shared helpers for analysis tests: minimal captures, case/evidence setup, broker access."""

import struct
import time
import uuid
from typing import Any

from httpx import AsyncClient
from kombu import Connection
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJobIndex
from app.workers import ingest
from tests.factories import Registered, csrf


def tiny_pcap(packets: int = 3) -> bytes:
    """A valid little-endian pcap (Ethernet) built by hand: no scapy in the API image."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = bytes(60)
    records = b"".join(
        struct.pack("<IIII", 1_700_000_000 + i, 0, len(frame), len(frame)) + frame
        for i in range(packets)
    )
    return header + records


async def new_case(reg: Registered) -> str:
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Analysis case", "severity": "medium"},
        headers=csrf(reg.client),
    )
    return str(response.json()["id"])


async def upload(client: AsyncClient, org_id: uuid.UUID, case_id: str, content: bytes) -> Any:
    response = await client.post(
        f"/api/v1/orgs/{org_id}/investigations/{case_id}/evidence",
        params={"filename": "capture.pcap"},
        content=content,
        headers={"Content-Type": "application/octet-stream", **csrf(client)},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def jobs_for(client: AsyncClient, org_id: uuid.UUID, evidence_id: str) -> list[Any]:
    response = await client.get(f"/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses")
    assert response.status_code == 200, response.text
    return list(response.json()["items"])


def broker_queue(name: str) -> str:
    prefix = get_settings().queue_prefix
    if not prefix.startswith("test."):
        raise RuntimeError("refusing to touch non-test broker queues")
    return f"{prefix}{name}"


def purge_test_queues() -> None:
    with Connection(get_settings().broker_url) as conn:
        for name in ("pcap", "ingest"):
            conn.default_channel.client.delete(broker_queue(name))
        # Declare the ingest binding (as the trusted side does in production): the analyzer
        # may only publish to it, never declare it.
        conn.SimpleQueue(broker_queue("ingest")).close()


def drain_ingest(timeout_s: float = 2.0) -> list[dict[str, Any]]:
    """Messages the analyzer sent to the (test) ingest queue, in order."""
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    with Connection(get_settings().broker_url) as conn:
        queue = conn.SimpleQueue(broker_queue("ingest"))
        try:
            while time.monotonic() < deadline:
                try:
                    message = queue.get(block=True, timeout=0.2)
                except queue.Empty:
                    continue
                _args, kwargs, _embed = message.decode()
                message.ack()
                out.append(kwargs["message"])
        finally:
            queue.close()
    return out


async def job_status(job_id: str) -> str:
    async with tenant_session(None, None) as session:
        status = await session.scalar(
            select(AnalysisJobIndex.status).where(AnalysisJobIndex.job_id == uuid.UUID(job_id))
        )
    return status.value if status else "missing"


async def run_ingest_until(job_id: str, statuses: set[str], timeout_s: float = 90.0) -> list[str]:
    """Feed analyzer messages to the real ingest handler until the job reaches `statuses`."""
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for message in drain_ingest(1.0):
            seen.append(f"{message['event']}:{message.get('outcome')}:{message.get('error_code')}")
            await ingest.handle_event(message)
        if await job_status(job_id) in statuses:
            return seen
    raise AssertionError(f"job {job_id} did not reach {statuses}; messages: {seen}")


class SentJobs(list[dispatch.DispatchInput]):
    """Dispatches captured instead of sent (API tests don't need the analyzer)."""
