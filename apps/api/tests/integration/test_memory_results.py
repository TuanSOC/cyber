"""M8 phase 6: what the memory ingest stores, row by row (the shapes phases 7-9 read)."""

from decimal import Decimal

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.memory_analysis.models import (
    SOURCE_BITS,
    MemoryArtifact,
    MemoryConnection,
    MemoryImage,
    MemoryInjection,
    MemoryProcess,
)
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc, TimelineEntry
from tests import memory_results as mr
from tests.analysis_helpers import SentJobs


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


def _addr(value: object) -> str | None:
    """An INET value as its address text (the driver may hand back an interface)."""
    return None if value is None else str(value).split("/")[0]


@pytest.fixture
async def ingested(sent: SentJobs) -> dispatch.DispatchInput:
    _, _, item = await mr.queued_job(sent)
    await mr.deliver(item, mr.image_stream(item))
    assert (await mr.job_of(item)).status == "succeeded"
    return item


async def test_the_image_row(ingested: dispatch.DispatchInput) -> None:
    item = ingested
    async with tenant_session(item.organization_id, None) as session:
        image = await session.get(MemoryImage, item.job_id)
    assert image is not None
    assert (image.os, image.arch, image.engine, image.symbols_status) == (
        "windows",
        "x64",
        "replay",
        "resolved",
    )
    assert image.layer == "WindowsCrashDump64Layer>WindowsIntel32e"
    assert (image.pdb_name, image.pdb_guid, image.pdb_age) == (
        "ntkrnlmp.pdb",
        "0123456789ABCDEF0123456789ABCDEF",
        1,
    )
    assert image.kernel_banner is None and image.nt_build == "19041"
    assert image.isf_sha256 == "c" * 64 and image.volatility_version == "2.28.2"
    assert [p["plugin"] for p in image.plugins][:2] == ["windows.info", "windows.pslist"]
    assert all(p["status"] == "ok" for p in image.plugins)
    assert image.counts == mr.WINDOWS_COUNTS


async def test_process_rows(ingested: dispatch.DispatchInput) -> None:
    item = ingested
    expected = {o["pid"]: o for o in mr.parsed(mr.WINDOWS) if o["kind"] == "process"}
    async with tenant_session(item.organization_id, None) as session:
        rows = (
            (
                await session.execute(
                    select(MemoryProcess).where(MemoryProcess.job_id == item.job_id)
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == len(expected) == 40
    for row in rows:
        source = expected[row.pid]
        assert row.organization_id == item.organization_id
        assert row.sources == sum(SOURCE_BITS[s] for s in source["sources"])
        assert row.name == source["name"] and row.cmdline == source["cmdline"]
        # Unsigned 64-bit kernel addresses survive as NUMERIC.
        assert row.offset == Decimal(source["offset"])
    system = next(r for r in rows if r.pid == 4)
    assert system.offset is not None and system.offset > 2**63


async def test_connection_injection_and_artifact_rows(ingested: dispatch.DispatchInput) -> None:
    item = ingested
    objs = mr.parsed(mr.WINDOWS)
    async with tenant_session(item.organization_id, None) as session:
        connections = (
            (
                await session.execute(
                    select(MemoryConnection).where(MemoryConnection.job_id == item.job_id)
                )
            )
            .scalars()
            .all()
        )
        [injection] = (
            (
                await session.execute(
                    select(MemoryInjection).where(MemoryInjection.job_id == item.job_id)
                )
            )
            .scalars()
            .all()
        )
        artifacts = (
            (
                await session.execute(
                    select(MemoryArtifact).where(MemoryArtifact.job_id == item.job_id)
                )
            )
            .scalars()
            .all()
        )
    remote = {o.get("remote_addr") for o in objs if o["kind"] == "connection"}
    assert {_addr(c.remote_addr) for c in connections} == remote
    source = objs[mr.index_of(objs, "injection")]
    assert injection.pid == source["pid"] and injection.head_hex == source["head_hex"]
    assert injection.start == Decimal(source["start"]) and injection.end == Decimal(source["end"])
    assert sorted(a.type for a in artifacts) == sorted(
        o["type"] for o in objs if o["kind"] == "artifact"
    )
    service = next(a for a in artifacts if a.type == "service")
    assert service.attributes["name"] == "UpdaterSvc"


async def test_shared_findings_iocs_and_timeline(ingested: dispatch.DispatchInput) -> None:
    item = ingested
    async with tenant_session(item.organization_id, None) as session:
        findings = (
            (
                await session.execute(
                    select(AnalysisFinding).where(AnalysisFinding.job_id == item.job_id)
                )
            )
            .scalars()
            .all()
        )
        iocs = (await session.execute(select(Ioc).where(Ioc.job_id == item.job_id))).scalars().all()
        timeline = (
            (
                await session.execute(
                    select(TimelineEntry).where(TimelineEntry.job_id == item.job_id)
                )
            )
            .scalars()
            .all()
        )
    assert {f.detection_method for f in findings} == {
        "heuristic:mem_hidden_process@1",
        "heuristic:mem_suspicious_cmdline@1",
    }
    assert all(f.severity in ("info", "low", "medium") for f in findings)  # never `high`
    assert {(i.type, i.value) for i in iocs} == {
        ("ip", "203.0.113.50"),
        ("file_path", "C:\\Users\\Public\\svch0st.exe"),
    }
    events = {t.event: t for t in timeline}
    assert set(events) == {"system_time", "process_start", "connection", "finding"}
    assert events["process_start"].ref == "6112"
    # A pid without a ref of its own becomes the ref; the remote address is the destination.
    assert events["connection"].ref == "6112"
    assert _addr(events["connection"].dst_ip) == "203.0.113.50"
    assert events["connection"].src_ip is None
