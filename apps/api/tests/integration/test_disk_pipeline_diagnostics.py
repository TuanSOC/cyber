"""Diagnostic and integrity paths of the disk analyzer end to end (M9 phase 13), on generated
images through the real `disk-worker-test` and `disk-ingest-worker-test`:

- `multi_gpt` with its two supported file systems wiped (the GPT, the HFS+ and the LUKS
  signatures kept): `no_supported_filesystem`, with the partitions stored and readable;
- a VMDK-magic file: `unsupported_disk_format` from root's magic check, before any probe;
- `ewf_bad_hash` (the stored MD5 patched): the job succeeds with the media hash `mismatch`
  (worker-reported) and the `integrity:ewf_media_hash@1` finding;
- an E01 set whose first segment belongs to another acquisition: refused by libewf.

See `tests/disk_pipeline_helpers.py` for the setup. Skipped outside the gate's default lane.
"""

import uuid

import pytest

from app.core.tenancy import tenant_session
from app.modules.disk_forensics.models import DiskImage
from tests import disk_pipeline_helpers as dp
from tests.analysis_helpers import new_case
from tests.disk_pipeline_helpers import clean_queues as clean_queues  # noqa: F401 (fixture)
from tests.disk_pipeline_helpers import small_budgets as small_budgets  # noqa: F401 (fixture)
from tests.disk_results import upload_disk
from tests.factories import register

pytestmark = [dp.requires_images, pytest.mark.usefixtures("clean_queues", "small_budgets")]

SECTOR = 512
WIPE = 1024 * 1024  # the boot sector / superblock region of a file system
# libewf's refusal of a mixed set surfaces as the layout's `unsupported` (a diagnostic) or as
# the probe's parse failure; either is a refusal with the stage's reason.
EWF_REFUSED = {"unsupported_disk_format", "disk_parse_failed"}


async def _run_bytes(name: str, content: bytes, reg_name: str) -> dp.Run:
    reg = await register(org_name=reg_name)
    case_id = await new_case(reg)
    response = await upload_disk(reg, case_id, content, name)
    assert response.status_code == 201, response.text
    evidence_id = str(response.json()["id"])
    job_id = await dp.start(reg, [evidence_id], profile="triage")
    await dp.wait_for(job_id)
    return dp.Run(reg, case_id, name, [evidence_id], job_id, {})


async def _has_image(run: dp.Run) -> bool:
    async with tenant_session(run.reg.org_id, None) as s:
        return (await s.get(DiskImage, uuid.UUID(run.job_id))) is not None


async def test_no_supported_file_system_keeps_the_partitions() -> None:
    truth = dp.truth("multi_gpt")
    data = bytearray((dp.image_dir("multi_gpt") / truth["segments"][0]).read_bytes())
    wiped = [p for p in truth["partitions"] if p["fs_type"]]
    assert wiped, "multi_gpt has no supported file system to wipe"
    for p in wiped:
        start = p["start_sector"] * SECTOR
        size = min(WIPE, p["length_sectors"] * SECTOR)
        data[start : start + size] = bytes(size)
    run = await _run_bytes("image.raw", bytes(data), "Disk Pipeline No FS Org")

    job = await dp.job_row(run.reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("failed", "no_supported_filesystem"), job.summary
    summary = await dp.get_json(run, run.base)
    assert summary["format"] == "raw"
    partitions = (await dp.get_json(run, f"{run.base}/partitions"))["items"]
    statuses = {p["fs_status"] for p in partitions}
    assert "ok" not in statuses, partitions
    assert {"encrypted", "unsupported"} <= statuses, partitions  # LUKS and HFS+ signatures
    assert (await dp.get_json(run, f"{run.base}/files"))["total"] == 0


async def test_a_vmdk_is_refused_before_any_probe() -> None:
    content = b"KDMV" + bytes(64 * 1024 - 4)  # a VMDK sparse extent's magic, nothing else
    run = await _run_bytes("disk.vmdk", content, "Disk Pipeline VMDK Org")
    job = await dp.job_row(run.reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("failed", "unsupported_disk_format"), job.summary
    # Root's magic check refused it: no probe ran, so no image or partition was stored.
    assert not await _has_image(run)
    missing = await run.reg.client.get(run.base)
    assert missing.status_code == 404, missing.text


async def test_a_stored_hash_mismatch_is_a_finding() -> None:
    reg = await register(org_name="Disk Pipeline Bad Hash Org")
    run = await dp.run_image(reg, "ewf_bad_hash")
    job = await dp.job_row(reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("succeeded", None), job.summary
    summary = await dp.get_json(run, run.base)
    assert (summary["format"], summary["media_hash_status"]) == ("ewf", "mismatch")
    assert summary["ewf_md5"] == run.truth["stored_md5_patched"]
    [finding] = [
        f
        for f in await dp.findings(reg.org_id, run.job_id)
        if f.detection_method == "integrity:ewf_media_hash@1"
    ]
    assert finding.type == "ewf_media_hash_mismatch"


async def test_a_foreign_e01_segment_is_refused_by_libewf() -> None:
    single, multi = dp.truth("ewf_single"), dp.truth("ewf_multi")
    files = [dp.image_dir("ewf_single") / single["segments"][0]]
    files += [dp.image_dir("ewf_multi") / name for name in multi["segments"][1:]]
    assert len(files) > 1, "ewf_multi must have several segments"
    reg = await register(org_name="Disk Pipeline Foreign Segment Org")
    case_id = await new_case(reg)
    segments = await dp.upload_files(reg, case_id, files)
    job_id = await dp.start(reg, segments, profile="triage")
    await dp.wait_for(job_id)
    run = dp.Run(reg, case_id, "foreign", segments, job_id, {})

    job = await dp.job_row(reg.org_id, job_id)
    assert job.status == "failed" and job.error_code in EWF_REFUSED, (job.error_code, job.summary)
    if await _has_image(run):  # a diagnostic: the refusing stage carries libewf's reason
        stages = (await dp.get_json(run, run.base))["stages"]
        refused = [s for s in stages if s["status"] not in ("ok", "skipped")]
        assert refused and refused[0]["reason"], stages
