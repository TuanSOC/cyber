"""The whole report pipeline (M6 phase 9), opt-in like `test_end_to_end_pdf`: a case with a
seeded capture analysis, a note, an IOC collection and a confirmed ATT&CK technique -> a
draft citing them -> finalize through the API (real signing, real dispatch) -> the real
broker -> `report-worker-test` (sandboxed WeasyPrint) -> presigned upload -> `report.rendered`
-> trusted ingest -> downloads.

Checks: the PDF re-hashes to `report_renders.sha256`; `scripts/verify_report.py --pdf`
accepts the downloaded PDF and refuses it with one byte of the embedded snapshot flipped;
HTML and Markdown render on demand and download as sandboxed attachments; v2 after a draft
change leaves v1's row and objects as they were.

Needs REPORT_E2E=1 and report-worker-test consuming this lane's broker db (the gate's
default lane: `docker compose --profile test up -d report-worker-test`).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.core.tenancy import tenant_session
from app.modules.reports import render_ingest
from app.modules.reports import storage as report_storage
from app.modules.reports.models import ReportVersion
from tests.analysis_helpers import drain_ingest, purge_test_queues
from tests.factories import Registered, csrf
from tests.report_helpers import SigningKeys, purge_reports_test_bucket, use_signing_keys
from tests.security.idor_cases_reports import (
    API,
    api_create,
    api_finalize,
    api_get,
    api_patch,
    owner_case,
    pcap_job,
)
from tests.unit.test_verify_report_script import SCRIPT

pytestmark = pytest.mark.skipif(
    not os.environ.get("REPORT_E2E") or SCRIPT is None,
    reason="REPORT_E2E=1 with report-worker-test consuming this lane's broker db",
)

RENDER_WAIT_S = 240


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    yield use_signing_keys(monkeypatch, tmp_path)
    purge_reports_test_bucket()


async def _post(reg: Registered, path: str, body: dict[str, Any]) -> dict[str, Any]:
    url = f"{API}/{reg.org_id}{path}"
    response = await reg.client.post(url, json=body, headers=csrf(reg.client))
    assert response.status_code in (200, 201, 202), response.text
    data: dict[str, Any] = response.json()
    return data


async def _wait_render(reg: Registered, render_id: str) -> dict[str, Any]:
    url = f"{API}/{reg.org_id}/report-renders/{render_id}"
    deadline = time.monotonic() + RENDER_WAIT_S
    body: dict[str, Any] = (await reg.client.get(url)).json()
    while time.monotonic() < deadline and body["status"] in ("queued", "running"):
        for message in drain_ingest(2.0):
            await render_ingest.handle_rendered_message(message)
        body = (await reg.client.get(url)).json()
    assert body["status"] == "succeeded", body
    return body


async def _download(reg: Registered, render: dict[str, Any]) -> bytes:
    response = await reg.client.get(f"{API}/{reg.org_id}/report-renders/{render['id']}/download")
    assert response.status_code == 200, response.text
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]
    assert hashlib.sha256(response.content).hexdigest() == render["sha256"]
    assert len(response.content) == render["bytes"]
    return response.content


def _verify(pdf: Path, keys_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--pdf", str(pdf), "--keys", str(keys_file)],
        capture_output=True,
        text=True,
        check=False,
    )


_OBJ = re.compile(rb"(\d+\s+\d+\s+obj\b)(.*?)(\bendobj)", re.DOTALL)


def _flip_embedded_snapshot(pdf: bytes, snapshot: bytes) -> bytes:
    """The PDF with one byte of its embedded snapshot flipped (re-compressed in place with
    a direct /Length, as the offline verifier's reader expects)."""
    for match in _OBJ.finditer(pdf):
        head, sep, rest = match.group(2).partition(b"stream")
        if not sep or b"/EmbeddedFile" not in head:
            continue
        raw = rest.removeprefix(b"\r\n").removeprefix(b"\n").rsplit(b"endstream", 1)[0]
        # A decompressor object stops at the end of the zlib stream (the EOL before
        # `endstream` is left over), so no /Length lookup is needed.
        content = zlib.decompressobj().decompress(raw) if b"/FlateDecode" in head else raw
        if content != snapshot:
            continue
        at = snapshot.index(b'"title":"') + len(b'"title":"')
        tampered = bytearray(snapshot)
        tampered[at] ^= 0x20  # an ASCII letter changes case: still valid JSON
        packed = zlib.compress(bytes(tampered)) if b"/FlateDecode" in head else bytes(tampered)
        head = re.sub(rb"/Length\s+(\d+\s+\d+\s+R|\d+)", b"/Length %d" % len(packed), head)
        body = head + b"stream\n" + packed + b"\nendstream\n"
        return pdf[: match.start(2)] + body + pdf[match.end(2) :]
    raise AssertionError("the PDF embeds no snapshot.json stream equal to the signed bytes")


async def test_the_whole_report_pipeline(keys: SigningKeys, tmp_path: Path) -> None:
    purge_test_queues()
    reg, t = await owner_case(title="Pipeline case")
    case = f"/investigations/{t.investigation_id}"
    await pcap_job(reg, t)
    body = {"body": "Pipeline note: beacon interval.", "include_in_reports": True}
    note = await _post(reg, f"{case}/notes", body)
    collection = await _post(reg, f"{case}/ioc-collections", {"name": "Pipeline blocklist"})
    await _post(
        reg,
        f"/ioc-collections/{collection['id']}/items",
        {"items": [{"type": "domain", "value": "pipeline-c2.example"}]},
    )
    await _post(reg, f"{case}/attack", {"technique_id": "T1071.001", "status": "confirmed"})

    report = (await api_create(reg, t, title="Pipeline report")).json()
    draft = {
        "sections": {"executive_summary": "Beaconing to one destination."},
        "include": {
            "iocs": {"case_iocs": False, "collections": [collection["id"]]},
            "notes": [note["id"]],
        },
    }
    patched = await api_patch(reg, report["id"], draft=draft)
    assert patched.status_code == 200, patched.text
    finalized = await api_finalize(reg, report["id"], change_note="First issue")
    assert finalized.status_code == 201, finalized.text
    base = f"{API}/{reg.org_id}/reports/{report['id']}/versions/1"
    renders = (await reg.client.get(f"{base}/renders")).json()["items"]
    assert [r["format"] for r in renders] == ["pdf"]

    # The PDF queued at finalize: real renderer, re-hashed download.
    pdf_render = await _wait_render(reg, renders[0]["id"])
    assert pdf_render["pages"] >= 1
    pdf = await _download(reg, pdf_render)
    assert pdf.startswith(b"%PDF-")

    # Offline verification of the downloaded PDF, and of a tampered copy.
    snapshot = (await reg.client.get(f"{base}/content")).content
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(json.dumps({keys.kid: keys.public_b64}), encoding="utf-8")
    good = tmp_path / "report.pdf"
    good.write_bytes(pdf)
    result = _verify(good, keys_file)
    assert result.returncode == 0, result.stdout + result.stderr
    bad = tmp_path / "tampered.pdf"
    bad.write_bytes(_flip_embedded_snapshot(pdf, snapshot))
    assert _verify(bad, keys_file).returncode == 1

    # HTML and Markdown on demand.
    # The Markdown escaper escapes `:` (`**TLP\:AMBER**`).
    for fmt, marker in (("html", b"<html"), ("md", rb"TLP\:AMBER")):
        queued = await _post(reg, f"/reports/{report['id']}/versions/1/renders", {"format": fmt})
        rendered = await _wait_render(reg, queued["id"])
        data = await _download(reg, rendered)
        head = data[:2048].lower() if fmt == "html" else data[:2048]
        assert marker in head
        assert b"Pipeline note" in data

    # v2 after a draft change: v1's row and stored snapshot are unchanged.
    async with tenant_session(t.org_id, t.owner_id) as s:
        v1 = await s.get(ReportVersion, uuid.UUID(finalized.json()["id"]))
    assert v1 is not None
    v1_row = (v1.snapshot_sha256, v1.object_key, v1.object_version_id, v1.signature)
    draft["sections"] = {"executive_summary": "Beaconing to one destination; contained."}
    assert (await api_patch(reg, report["id"], draft=draft)).status_code == 200
    second = await api_finalize(reg, report["id"], change_note="Containment")
    assert second.status_code == 201, second.text
    assert second.json()["version"] == 2
    async with tenant_session(t.org_id, t.owner_id) as s:
        again = await s.get(ReportVersion, v1.id)
    assert again is not None
    assert (again.snapshot_sha256, again.object_key, again.object_version_id, again.signature) == (
        v1_row
    )
    assert await report_storage.hash_snapshot(v1.object_key, v1.object_version_id) == (
        v1.snapshot_bytes,
        v1.snapshot_sha256,
    )
    assert (await reg.client.get(f"{base}/content")).content == snapshot
    detail = await api_get(reg, report["id"])
    assert sorted(v["version"] for v in detail["versions"]) == [1, 2]
    # v2's PDF goes through the same pipeline (left to finish so the queue is clean).
    v2_base = f"{API}/{reg.org_id}/reports/{report['id']}/versions/2"
    v2_renders = (await reg.client.get(f"{v2_base}/renders")).json()["items"]
    await _wait_render(reg, v2_renders[0]["id"])
