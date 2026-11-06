"""The disk read API (M9 phase 8) over jobs seeded from the phase-1 `disk.v1` Windows fixture:
the summary (segments with the API's own hashes, unsigned 64-bit values as decimal text),
partitions, files (filters, `ref`, pagination, known-good hiding), one file with its other
names and export eligibility, events; `404` for unknown, foreign, pcap, memory and extract
jobs and for a file of another job; `409 analysis_not_ready` while queued or running.

The helpers here (`tenant`, `base`, `get`, `add_file`, `file_id_of`) are shared by the other
`test_disk_*` read modules."""

import secrets
import uuid
from typing import Any

from cyberlab_jobs.disk import OsHint
from httpx import AsyncClient
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.disk_forensics.models import DiskFile
from app.modules.evidence.models import EvidenceHash, HashAlgorithm
from tests.case_helpers import seed_evidence, seed_job_on
from tests.disk_helpers import seed_disk_job, seed_segment_set
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant
from tests.memory_helpers import seed_memory_job

ROUTES = ("", "/partitions", "/files", "/dirs", "/events", "/timeline", "/exports/bodyfile")
FILES = 306  # windows_triage.ndjson
KNOWN_GOOD = 1  # Users/alice/Documents/report.docx
EVENTS = 8
U64_MAX = 2**64 - 1


async def tenant(reg: Registered) -> Tenant:
    created = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Disk case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(created.json()["id"]))


def base(reg: Registered, job_id: uuid.UUID) -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/disk"


async def get(client: AsyncClient, url: str, **params: Any) -> dict[str, Any]:
    response = await client.get(url, params=params)
    assert response.status_code == 200, (url, response.text)
    body: dict[str, Any] = response.json()
    return body


async def windows(reg: Registered) -> tuple[Tenant, uuid.UUID, str]:
    t = await tenant(reg)
    job = await seed_disk_job(t)
    return t, job, base(reg, job)


async def add_file(t: Tenant, job_id: uuid.UUID, **fields: Any) -> uuid.UUID:
    """One more listed entry of the job (result tables are insert-only)."""
    row = DiskFile(
        organization_id=t.org_id,
        job_id=job_id,
        **{
            "partition_index": 1,
            "meta_addr": 90_000,
            "path": "extra.bin",
            "name": "extra.bin",
            "type": "reg",
            "flags": 1,
            **fields,
        },
    )
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(row)
        await s.flush()
        return row.id


async def file_id_of(t: Tenant, job_id: uuid.UUID, path: str) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        found = await s.scalar(
            select(DiskFile.id).where(DiskFile.job_id == job_id, DiskFile.path == path)
        )
    assert found is not None, path
    return found


async def test_summary_shows_trusted_segment_hashes_and_image_facts() -> None:
    reg = await register(org_name="Disk Summary Org")
    t = await tenant(reg)
    segments = await seed_segment_set(t, 2)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            EvidenceHash(
                organization_id=t.org_id,
                evidence_id=segments[0],
                algorithm=HashAlgorithm.SHA256,
                value="e" * 64,
            )
        )
    job = await seed_disk_job(t, segments)
    body = await get(reg.client, base(reg, job))
    assert body["job_id"] == str(job)
    assert (body["profile"], body["format"], body["engine"]) == ("triage", "raw", "tsk")
    assert body["timeline_engine"] == "replay"
    assert [(s["ordinal"], s["evidence_id"]) for s in body["segments"]] == [
        (0, str(segments[0])),
        (1, str(segments[1])),
    ]
    first, second = body["segments"]
    assert (first["original_filename"], first["size_bytes"], first["sha256"]) == (
        "image.E01",
        1024,
        "e" * 64,
    )
    assert second["sha256"] == ""  # not hashed yet: never the worker's value
    # Unsigned 64-bit values as decimal text; the worker's media hash only as reported.
    assert body["media_size"] == "67108864"
    assert body["media_sha256"] == "a" * 64 and body["media_hash_status"] is None
    assert body["tool_versions"]["pytsk3"] == "20260715"
    assert [h["name"] for h in body["hashsets"]] == ["nsrl-minimal"]
    assert [s["stage"] for s in body["stages"]][:3] == ["download", "layout", "walk"]
    counts = body["counts"]
    assert (counts["partitions"], counts["files"], counts["events"]) == (2, FILES, EVENTS)
    assert body["truncated"] is False


async def test_a_terminal_job_without_an_image_has_no_summary() -> None:
    reg = await register(org_name="Disk Failed Org")
    t = await tenant(reg)
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=await seed_evidence(t, filename="broken.E01"),
            analyzer=Analyzer.DISK,
            profile=JobProfile.TRIAGE,
            os_hint=OsHint.AUTO,
            status=AnalysisStatus.FAILED,
            error_code="disk_parse_failed",
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(row)
    job = row.id
    response = await reg.client.get(base(reg, job))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "results_not_available"
    assert await get(reg.client, base(reg, job) + "/files") == {"items": [], "total": 0}


async def test_queued_and_running_jobs_are_not_ready() -> None:
    reg = await register(org_name="Disk Not Ready Org")
    t = await tenant(reg)
    for status in ("queued", "running"):
        job = await seed_disk_job(t, status=status, fixture=None)
        for path in (*ROUTES, f"/files/{uuid.uuid4()}"):
            response = await reg.client.get(base(reg, job) + path)
            assert response.status_code == 409, (status, path, response.text)
            assert response.json()["error"]["code"] == "analysis_not_ready"


async def test_unknown_foreign_other_analyzer_and_extract_jobs_are_404() -> None:
    reg = await register(org_name="Disk 404 Org")
    t = await tenant(reg)
    job = await seed_disk_job(t)
    pcap = await seed_job_on(t, await seed_evidence(t), "pcap")
    memory = await seed_memory_job(t, fixture=None)
    extract = await seed_disk_job(t, profile="extract", fixture=None)
    other = await register(org_name="Disk 404 Other Org")
    for path in (*ROUTES, f"/files/{uuid.uuid4()}"):
        for job_id in (uuid.uuid4(), pcap, memory, extract):
            response = await reg.client.get(base(reg, job_id) + path)
            assert response.status_code == 404, (job_id, path)
        assert (await other.client.get(base(other, job) + path)).status_code == 404, path
        assert (await other.client.get(base(reg, job) + path)).status_code == 404, path


async def test_partitions_with_sector_numbers_as_text() -> None:
    reg = await register(org_name="Disk Partition Org")
    _, _, url = await windows(reg)
    body = await get(reg.client, f"{url}/partitions")
    assert body["total"] == 2
    unalloc, ntfs = body["items"]
    assert (unalloc["index"], unalloc["fs_status"]) == (0, "undetermined")
    assert unalloc["vs_flags"] == "unalloc"
    assert (ntfs["start_sector"], ntfs["length_sectors"]) == ("2048", "129024")
    assert (ntfs["fs_type"], ntfs["os"], ntfs["fs_label"]) == ("ntfs", "windows", "Windows")
    assert ntfs["counts"] == {"files": 300, "deleted": 1, "orphans": 1}


async def test_file_list_filters_and_pages() -> None:
    reg = await register(org_name="Disk Files Org")
    t, job, url = await windows(reg)
    c = reg.client
    first = await get(c, f"{url}/files", limit=100)
    rest = [
        await get(c, f"{url}/files", limit=100, offset=offset) for offset in (100, 200, 300)
    ]
    assert first["total"] == FILES - KNOWN_GOOD  # known-good hidden by default (RT18)
    ids = [f["id"] for page in (first, *rest) for f in page["items"]]
    assert len(ids) == len(set(ids)) == FILES - KNOWN_GOOD
    keys = [
        (f["partition_index"], int(f["meta_addr"]))
        for page in (first, *rest)
        for f in page["items"]
    ]
    assert keys == sorted(keys)
    assert (await get(c, f"{url}/files", include_known="true"))["total"] == FILES

    def total(**params: Any) -> Any:
        return get(c, f"{url}/files", **params)

    [deleted] = (await total(flag="deleted"))["items"]
    assert deleted["path"] == "Users/alice/Downloads/old_tool.exe"
    assert (await total(flag="orphan"))["total"] == 1
    hard = await total(flag="hard_linked")
    assert {f["path"] for f in hard["items"]} == {
        "Users/alice/link_a.txt",
        "Users/alice/Documents/link_b.txt",
    }
    assert hard["items"][0]["flags"] == ["allocated", "hard_linked"]
    assert (await total(flag="stream"))["items"][0]["stream"] == "payload"
    [yara] = (await total(flag="yara"))["items"]
    assert yara["yara_rules"] == ["image.cyberlab_baseline.CyberLab_Suspicious_Packer"]
    assert (await total(flag="known"))["total"] == 0
    assert (await total(hash=yara["md5"].upper()))["items"][0]["id"] == yara["id"]
    assert (await total(hash=yara["sha1"]))["total"] == 1
    assert (await total(sha256=hard["items"][0]["sha256"]))["total"] == 2
    assert (await total(ext="EXE"))["total"] == 3
    assert (await total(q="ALICE/DOWNLOADS"))["total"] == 3  # case-insensitive substring
    assert (await total(q="100%"))["total"] == 0  # a literal
    window = await total(**{"from": "2026-10-01T08:50:00Z", "to": "2026-10-01T08:50:59Z"})
    assert "Users/alice/Downloads/invoice.pdf.exe" in {f["path"] for f in window["items"]}
    assert (await total(partition=0))["total"] == 0
    one = await total(ref=yara["id"])
    assert [f["id"] for f in one["items"]] == [yara["id"]]
    assert (await c.get(f"{url}/files", params={"ref": str(uuid.uuid4())})).status_code == 404

    for bad in (
        {"hash": "abc"},
        {"hash": "g" * 32},
        {"q": "a\x00b"},
        {"q": "x" * 129},
        {"from": "2026-10-01T08:00:00"},  # naive
        {"from": "2026-10-02T00:00:00Z", "to": "2026-10-01T00:00:00Z"},
        {"flag": "evil"},
        {"limit": 101},
    ):
        assert (await c.get(f"{url}/files", params=bad)).status_code == 422, bad

    # The largest unsigned 64-bit inode survives as text (no JSON number above 2**53).
    big = await add_file(t, job, meta_addr=U64_MAX, parent_addr=U64_MAX - 1, path="big.bin")
    [row] = (await total(ref=str(big)))["items"]
    assert (row["meta_addr"], row["parent_addr"]) == (str(U64_MAX), str(U64_MAX - 1))


async def test_file_detail_other_names_streams_and_export_eligibility() -> None:
    reg = await register(org_name="Disk Detail Org")
    t, job, url = await windows(reg)
    c = reg.client
    link_a = await file_id_of(t, job, "Users/alice/link_a.txt")
    body = await get(c, f"{url}/files/{link_a}")
    assert body["other_names"] == ["Users/alice/Documents/link_b.txt"]  # RT7
    assert (body["meta_addr"], body["meta_seq"]) == ("369", 1)
    assert (body["exportable"], body["not_exportable_reason"]) == (True, None)

    base_name = await add_file(
        t, job, meta_addr=366, meta_seq=1, path="Users/alice/Documents/notes.txt", size=10
    )
    notes = await get(c, f"{url}/files/{base_name}")
    assert notes["streams"] == ["payload"] and notes["other_names"] == []

    for path, reason in (
        ("Windows/System32/config/SAM", "never_collected"),
        ("Users/alice/Downloads/old_tool.exe", "not_allocated"),
        ("Windows/System32", "not_regular"),
    ):
        detail = await get(c, f"{url}/files/{await file_id_of(t, job, path)}")
        assert (detail["exportable"], detail["not_exportable_reason"]) == (False, reason), path

    # A name of the same inode on the never-collected list refuses every name (RT7).
    alias = await add_file(t, job, meta_addr=91_000, path="Users/alice/copy.bin", size=10)
    await add_file(t, job, meta_addr=91_000, path="Windows/System32/config/SECURITY", size=10)
    refused = await get(c, f"{url}/files/{alias}")
    assert refused["not_exportable_reason"] == "never_collected"

    too_big = await add_file(t, job, meta_addr=92_000, path="big.iso", size=2**40)
    assert (await get(c, f"{url}/files/{too_big}"))["not_exportable_reason"] == "too_large"

    assert (await c.get(f"{url}/files/{uuid.uuid4()}")).status_code == 404
    other_job = await seed_disk_job(t)
    foreign_file = await file_id_of(t, other_job, "Users/alice/link_a.txt")
    assert (await c.get(f"{url}/files/{foreign_file}")).status_code == 404


async def test_events_in_time_order_with_filters() -> None:
    reg = await register(org_name="Disk Events Org")
    _, _, url = await windows(reg)
    c = reg.client
    body = await get(c, f"{url}/events")
    assert body["total"] == EVENTS
    stamps = [e["ts"] for e in body["items"]]
    assert stamps == sorted(stamps)
    assert body["items"][0]["artifact"] == "lnk"  # 08:21, the earliest
    assert (await get(c, f"{url}/events", artifact="evtx"))["total"] == 3
    [cleared] = (await get(c, f"{url}/events", q="AUDIT LOG"))["items"]
    assert cleared["attributes"] == {"event_identifier": 1102}
    window = await get(
        c, f"{url}/events", **{"from": "2026-10-01T08:54:00Z", "to": "2026-10-01T08:55:00Z"}
    )
    assert window["total"] == 3
    assert (await get(c, f"{url}/events", ref=cleared["id"]))["total"] == 1
    assert (await c.get(f"{url}/events", params={"artifact": "EVTX"})).status_code == 422
