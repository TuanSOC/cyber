"""The disk analyzer end to end (M9 phase 13): generated images (`pnpm disk:gen`), the real
broker, the real `disk-worker-test` (TSK, libewf and Plaso, offline, the test hash-set store),
the shared ingest handler in-process and the real `disk-ingest-worker-test`.

- `ext4_linux` (triage, Plaso): every read route and interop export answers; the restricted
  default is on every segment; AI and job-scope TI are `policy_blocked`; the ground truth's
  findings are present (the executable in a user-writable path, the known-bad hash match, the
  sshd remote logon from auth.log), the known-good file is hidden by default; the hard link to
  `etc/shadow`, every never-collected dummy and the compressed / `full`-only logs are absent
  from the events; a pcap result ingests on the shared path right after the disk hand-off;
- `ewf_multi` (an E01 set in order): the media hash `matched` (worker-reported), the
  partitions, the segments in the analyst's order with the API's own hashes;
- `ntfs_windows` with the replay timeline engine (the gate's second pass, labelled
  `timeline_engine: replay`): the EVTX / registry / Prefetch / LNK rows reach the tables and
  the Windows event detections.

See `tests/disk_pipeline_helpers.py` for the setup. Skipped outside the gate's default lane.
"""

from typing import Any

import pytest

from app.modules.analysis import dispatch
from tests import disk_pipeline_helpers as dp
from tests import pcap_results as pr
from tests.ai_api_helpers import capture_ai_sends, enable_ai, preview
from tests.analysis_helpers import job_status, new_case, tiny_pcap, upload
from tests.disk_pipeline_helpers import clean_queues as clean_queues  # noqa: F401 (fixture)
from tests.disk_pipeline_helpers import small_budgets as small_budgets  # noqa: F401 (fixture)
from tests.factories import register
from tests.ti_api_helpers import capture_sends, enrich_job
from tests.ti_api_helpers import enable as enable_ti

pytestmark = [dp.requires_images, pytest.mark.usefixtures("clean_queues", "small_budgets")]

READ_ROUTES = ("", "/partitions", "/files", "/dirs", "/events", "/timeline")
INTEROP = ("bodyfile", "timeline.csv", "timeline.jsonl", "notable-hashes.txt")
# Ground-truth findings that need more than TSK and Plaso on the generated tree (a hivex-built
# hive; a timeline window around the file times): asserted elsewhere, not here.
UNMET = {"hivex", "timeline_window"}


def _code(response: Any) -> tuple[int, str | None, str | None]:
    error = response.json().get("error", {}) if response.status_code >= 400 else {}
    return response.status_code, error.get("code"), error.get("reason")


async def _reads_answer(run: dp.Run) -> None:
    for route in READ_ROUTES:
        await dp.get_json(run, f"{run.base}{route}")
    files = await dp.get_json(run, f"{run.base}/files", limit=1)
    assert files["total"] > 0
    await dp.get_json(run, f"{run.base}/files/{files['items'][0]['id']}")
    for route in ("findings", "iocs"):
        await dp.get_json(run, f"{run.org}/analyses/{run.job_id}/{route}")
    for name in INTEROP:
        response = await run.reg.client.get(f"{run.base}/exports/{name}")
        assert response.status_code == 200, (name, response.text[:200])
        assert response.headers.get("x-cyberlab-sensitivity"), name


async def _restricted_everywhere(run: dp.Run) -> None:
    for evidence_id in run.segments:
        state, source, flags = await dp.evidence_sensitivity(run, evidence_id)
        assert (state, source, flags) == ("restricted", "disk", (True, True)), evidence_id


async def _expected_findings(run: dp.Run, engine: str) -> None:
    found = await dp.findings(run.reg.org_id, run.job_id)
    for expected in run.truth.get("expected_findings", []):
        needs = set(expected.get("requires", []))
        if needs & UNMET or ("plaso" in needs and engine != "plaso"):
            continue
        matching = [f for f in found if f.type == expected["type"]]
        assert matching, (expected, [f.type for f in found])
        assert matching[0].detection_method == expected["method"], expected
        if not needs:  # a file finding names its file
            assert any(f.mentions(expected["path"]) for f in matching), expected


@pytest.mark.skipif(dp.TIMELINE_ENGINE != "plaso", reason="the Plaso pass of the gate")
async def test_a_linux_image_runs_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register(org_name="Disk Pipeline Linux Org")
    case_id = await new_case(reg)

    # A pcap job whose result the "shared ingest worker" (this process) handles right after
    # the disk report was handed off: the disk ingest runs on its own worker, never here.
    with monkeypatch.context() as m:
        captured: list[dispatch.DispatchInput] = []

        async def capture(item: dispatch.DispatchInput) -> None:
            captured.append(item)

        m.setattr(dispatch, "send", capture)
        await upload(reg.client, reg.org_id, case_id, tiny_pcap())
    [pcap] = captured

    async def pcap_meanwhile() -> None:
        await pr.deliver(pcap, pr.stream(pcap.job_id))
        assert await job_status(str(pcap.job_id)) == "succeeded"

    run = await dp.run_image(reg, "ext4_linux", case_id=case_id, on_finished=pcap_meanwhile)
    job = await dp.job_row(reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("succeeded", None), job.summary
    assert await job_status(str(pcap.job_id)) == "succeeded"

    summary = await dp.get_json(run, run.base)
    assert (summary["format"], summary["profile"]) == ("raw", "triage")
    assert summary["timeline_engine"] == "plaso"
    assert summary["media_sha256"] == run.truth["media_sha256"]
    assert {h["name"] for h in summary["hashsets"]} >= {dp.KNOWN_GOOD_SET, dp.KNOWN_BAD_SET}
    for segment, evidence_id in zip(summary["segments"], run.segments, strict=True):
        evidence = await dp.get_json(run, f"{run.org}/evidence/{evidence_id}")
        assert segment["sha256"] == evidence["hashes"]["sha256"]  # the API's own hash
    # The GPT's own entries (protective MBR, header, unallocated) may be listed beside it.
    partitions = (await dp.get_json(run, f"{run.base}/partitions"))["items"]
    [part] = [p for p in partitions if p["fs_type"]]
    assert (part["fs_type"], part["fs_status"], part["os"]) == ("ext4", "ok", "linux")

    await _reads_answer(run)
    await _restricted_everywhere(run)

    # AI and job-scope TI on restricted evidence: blocked by the share policy.
    capture_ai_sends(monkeypatch)
    sent = capture_sends(monkeypatch, analyses=False)
    await enable_ai(reg.client, reg.org_id)
    blocked = await preview(reg.client, reg.org_id, task="ioc_correlation", job_id=run.job_id)
    assert _code(blocked) == (409, "policy_blocked", "evidence_ai_excluded"), blocked.text
    await enable_ti(reg.client, reg.org_id)
    blocked = await enrich_job(reg.client, reg.org_id, run.job_id)
    assert _code(blocked) == (409, "policy_blocked", "evidence_ti_excluded"), blocked.text
    assert sent.runs == []

    # Findings: the ground truth's, the known-bad match and the sshd logon from auth.log.
    await _expected_findings(run, "plaso")
    found = await dp.findings(reg.org_id, run.job_id)
    sets = dp.expected_hashsets()
    for bad in (b for b in sets["known_bad"] if b["image"] == "ext4_linux"):
        [listed] = await dp.find_files(run, bad["path"])
        assert (listed["known"], listed["known_set"]) == ("bad", dp.KNOWN_BAD_SET)
        assert listed["sha256"] == bad["sha256"]
        hits = [f for f in found if f.type == "disk_hashset_match" and f.mentions(bad["path"])]
        assert hits and hits[0].detection_method == "known_file:hashset@1", found
    assert any(f.type == "disk_remote_logon" for f in found), [f.type for f in found]
    for good in (g for g in sets["known_good"] if g["image"] == "ext4_linux"):
        name = dp.norm(good["path"]).rsplit("/", 1)[-1]
        hidden = await dp.all_items(run, f"{run.base}/files", q=name)
        assert all(dp.norm(f["path"]) != dp.norm(good["path"]) for f in hidden)
        [listed] = await dp.find_files(run, good["path"])
        assert (listed["known"], listed["known_set"]) == ("good", dp.KNOWN_GOOD_SET)

    # The collected tree: only the catalog's files; never a never-collected name, the second
    # name of etc/shadow, a compressed-content log or a `full`-only rotated log.
    events = await dp.all_items(run, f"{run.base}/events")
    assert events, "Plaso produced no stored event"
    event_paths = {dp.norm(e["path"]) for e in events}
    collect = run.truth["collect_expected"]
    allowed = {dp.norm(p) for p in collect["triage"]}
    assert event_paths <= allowed, event_paths - allowed
    banned = {dp.norm(p) for p in collect["never"] + collect["full_only"]}
    banned |= {dp.norm(p) for p in collect["dropped_compressed_content"]}
    for meta in run.truth["never_collect_meta"]:
        banned |= {dp.norm(meta["path"]), dp.norm(meta["link_to"])}
    assert not event_paths & banned, event_paths & banned
    data_types = {e["data_type"] for e in events}
    for expected in run.truth["plaso_expected"]:
        prefix = expected["data_type"].removesuffix("*")
        assert any(t.startswith(prefix) for t in data_types), (expected, data_types)

    # The hard link is listed (it is a name in the file system), never exportable.
    for meta in run.truth["never_collect_meta"]:
        listed = await dp.find_file(run, meta["path"])
        assert "hard_linked" in listed["flags"], listed
        detail = await dp.get_json(run, f"{run.base}/files/{listed['id']}")
        assert dp.norm(meta["link_to"]) in {dp.norm(n) for n in detail["other_names"]}
        assert detail["exportable"] is False and detail["not_exportable_reason"]

    # The merged timeline carries both sources.
    timeline = await dp.all_items(run, f"{run.base}/timeline", max_pages=400)
    assert {item["source"] for item in timeline} == {"file", "event"}


async def test_an_e01_set_runs_with_its_media_hash_matched() -> None:
    reg = await register(org_name="Disk Pipeline E01 Org")
    run = await dp.run_image(reg, "ewf_multi")
    assert len(run.segments) > 1, "ewf_multi must have several segments"
    job = await dp.job_row(reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("succeeded", None), job.summary

    summary = await dp.get_json(run, run.base)
    assert summary["format"] == "ewf"
    assert summary["media_hash_status"] == "matched"  # worker-reported (RT17)
    assert summary["ewf_md5"] or summary["ewf_sha1"]
    listed = [(s["ordinal"], s["original_filename"]) for s in summary["segments"]]
    assert listed == list(enumerate(run.truth["segments"]))
    assert [str(s["evidence_id"]) for s in summary["segments"]] == run.segments
    partitions = (await dp.get_json(run, f"{run.base}/partitions"))["items"]
    expected = run.truth["partitions"]
    assert [p["fs_type"] for p in partitions if p["fs_type"]] == [
        p["fs_type"] for p in expected if p["fs_type"]
    ]
    assert any(p["os"] == "windows" for p in partitions)
    await _reads_answer(run)
    await _restricted_everywhere(run)
    found = {f.type for f in await dp.findings(reg.org_id, run.job_id)}
    assert "ewf_media_hash_mismatch" not in found
    await _expected_findings(run, dp.TIMELINE_ENGINE)


@pytest.mark.skipif(dp.TIMELINE_ENGINE != "replay", reason="the replay pass of the gate")
async def test_windows_artifacts_through_the_replay_engine() -> None:
    """Hand-written psort-shaped rows replayed on the Windows partition (no Linux writer of
    EVTX, registry, Prefetch or LNK exists): the normalizers, the detections and the tables,
    labelled `timeline_engine: replay` (never real analysis)."""
    reg = await register(org_name="Disk Pipeline Replay Org")
    run = await dp.run_image(reg, "ntfs_windows")
    job = await dp.job_row(reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("succeeded", None), job.summary
    summary = await dp.get_json(run, run.base)
    assert summary["timeline_engine"] == "replay"

    events = await dp.all_items(run, f"{run.base}/events")
    artifacts = {e["artifact"] for e in events}
    assert {"evtx", "prefetch", "lnk"} <= artifacts, artifacts
    assert artifacts & {"registry_system", "registry_user"}, artifacts
    evtx = await dp.get_json(run, f"{run.base}/events", artifact="evtx")
    assert evtx["total"] > 0
    timeline = await dp.get_json(run, f"{run.base}/timeline", source="event")
    assert timeline["total"] > 0
    found = {f.type for f in await dp.findings(reg.org_id, run.job_id)}
    assert {"disk_service_installed", "disk_log_cleared"} <= found, found
    await _expected_findings(run, "replay")
    await _reads_answer(run)
