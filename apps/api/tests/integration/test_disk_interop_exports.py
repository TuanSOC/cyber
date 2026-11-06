"""The disk interop exports (M9 phase 8, RT12): the TSK body file (11 fields, names that
cannot break a line), the merged timeline as CSV / JSONL in Timesketch's columns
(formula-safe, BOM only with `excel=1`), the plain md5 list for an Autopsy hash set; every
download audited `disk.interop_exported` with its row count, labelled in
`X-CyberLab-Sensitivity` and the file name (`-TLP-RED` for restricted evidence)."""

import csv
import io
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.disk_forensics.exports_interop import (
    AUDIT_ACTION,
    TIMELINE_COLUMNS,
    parse_bodyfile_line,
)
from app.modules.pcap_analysis.models import AnalysisFinding
from tests.disk_helpers import restricted_disk_evidence, seed_disk_job, seed_segment_set
from tests.factories import register
from tests.integration.test_disk_reads import (
    EVENTS,
    FILES,
    add_file,
    base,
    file_id_of,
    tenant,
    windows,
)

YARA_MD5 = "d500ebecc3a1cdd1422c1352c998c271"  # updater.exe
INVOICE = "Users/alice/Downloads/invoice.pdf.exe"
INVOICE_MD5 = "1f42344f7e14eebb4479ad7a299bd949"
# (inode, md5, set kind): known-bad and notable are listed (md5 lowercased), known-good not.
FLAGGED = ((95_000, "A" * 32, "bad"), (95_001, "b" * 32, "notable"), (95_002, "c" * 32, "good"))


async def _audits(org_id: uuid.UUID) -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.action == AUDIT_ACTION)
            .order_by(AuditLog.occurred_at, AuditLog.id)
        )
        return list(rows)


async def test_bodyfile_has_eleven_fields_and_escapes_names() -> None:
    reg = await register(org_name="Disk Bodyfile Org")
    t, job, url = await windows(reg)
    await add_file(t, job, meta_addr=93_000, path="evil|name\nnext", name="evil|name\nnext")
    response = await reg.client.get(f"{url}/exports/bodyfile")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-cyberlab-sensitivity"] == "TLP:AMBER"
    disposition = response.headers["content-disposition"]
    assert "bodyfile-TLP-AMBER.body" in disposition and "CASE-" in disposition
    lines = response.text.split("\n")
    assert lines[-1] == ""  # every line ends with a newline
    rows = [parse_bodyfile_line(line) for line in lines[:-1]]
    assert len(rows) == FILES + 1
    by_name = {r[1]: r for r in rows}
    evil = by_name["/p1/evil|name\nnext"]
    assert "\\x7c" in next(line for line in lines if "evil" in line)
    assert evil[2] == "93000"
    link = by_name["/p1/Users/alice/link_a.txt"]
    assert link[0] == "cc5828858fd71199f183684ae6e1481b"
    assert (link[2], link[3]) == ("369-1", "r/r---------")
    assert link[6] == "1024"
    assert link[8] == str(int(datetime(2026, 10, 1, 8, 5, tzinfo=UTC).timestamp()))  # mtime
    assert by_name["/p1/Users/alice/Documents/notes.txt:payload"][2] == "366-1-payload"
    deleted = by_name["/p1/Users/alice/Downloads/old_tool.exe (deleted)"]
    assert deleted[0] == "0"  # not hashed
    assert by_name["/p1/Windows"][3].startswith("d/d")

    [audit] = await _audits(t.org_id)
    assert audit.target_id == job
    assert audit.details["kind"] == "bodyfile" and audit.details["rows"] == FILES + 1


async def test_timeline_csv_and_jsonl_in_timesketch_columns() -> None:
    reg = await register(org_name="Disk Timeline Export Org")
    t, job, url = await windows(reg)
    when = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
    await add_file(t, job, meta_addr=94_000, path="=cmd|' /C calc'!A0", name="x", mtime=when)
    c = reg.client

    plain = await c.get(f"{url}/exports/timeline.csv")
    assert plain.status_code == 200
    assert plain.headers["content-type"].startswith("text/csv")
    assert not plain.content.startswith(b"\xef\xbb\xbf")
    assert plain.content.startswith(b"message,datetime,timestamp_desc,")
    records = list(csv.reader(io.StringIO(plain.content.decode("utf-8"))))
    assert tuple(records[0]) == TIMELINE_COLUMNS
    body = records[1:]
    assert len(body) == FILES * 4 + EVENTS + 1  # the new entry has an mtime only
    stamps = [r[1] for r in body]
    assert stamps == sorted(stamps)
    assert all(r[1].endswith("+00:00") for r in body)
    formula = [r for r in body if "calc" in r[0]]
    assert formula and all(r[0].startswith("'=") and r[6].startswith("'=") for r in formula)
    event = next(r for r in body if r[3] == "event")
    assert event[4] in {"evtx", "lnk", "registry_user", "registry_system", "prefetch", "amcache"}

    excel = await c.get(f"{url}/exports/timeline.csv", params={"excel": "1"})
    assert excel.content.startswith(b"\xef\xbb\xbfmessage,datetime,timestamp_desc,")

    jsonl = await c.get(f"{url}/exports/timeline.jsonl")
    assert jsonl.headers["content-type"].startswith("application/x-ndjson")
    objects = [json.loads(line) for line in jsonl.text.splitlines()]
    assert len(objects) == len(body)
    assert list(objects[0]) == list(TIMELINE_COLUMNS)
    assert objects[0]["source"] == "file" and objects[0]["artifact"] is None

    audits = await _audits(t.org_id)
    kinds = [a.details["kind"] for a in audits]
    assert kinds == ["timeline.csv", "timeline.csv", "timeline.jsonl"]
    assert {a.details["rows"] for a in audits} == {len(body)}


async def test_notable_hashes_list_flagged_files_once() -> None:
    reg = await register(org_name="Disk Hashes Org")
    t, job, url = await windows(reg)
    invoice = await file_id_of(t, job, INVOICE)
    async with tenant_session(t.org_id, None) as s:
        for refs in ([f"file:{invoice}"], [f"file:1:{INVOICE}", "event:1"]):
            s.add(
                AnalysisFinding(
                    organization_id=t.org_id,
                    job_id=job,
                    finding_id=uuid.uuid4(),
                    ts=datetime.now(UTC),
                    type="disk_double_extension",
                    title="Double extension",
                    description="synthetic",
                    severity="low",
                    confidence=0.6,
                    detection_method="heuristic:disk_double_extension@1",
                    evidence_refs=refs,
                    attributes={},
                )
            )
    for addr, md5, known in FLAGGED:
        await add_file(
            t,
            job,
            meta_addr=addr,
            path=f"{known}.exe",
            md5=md5,
            known=known,
            known_set=f"{known}-set",
            hash_status="hashed",
        )
    response = await reg.client.get(f"{url}/exports/notable-hashes.txt")
    assert response.status_code == 200
    assert response.text.splitlines() == sorted([YARA_MD5, INVOICE_MD5, "a" * 32, "b" * 32])
    [audit] = await _audits(t.org_id)
    assert audit.details["rows"] == 4


async def test_restricted_evidence_is_labelled_tlp_red() -> None:
    reg = await register(org_name="Disk Restricted Export Org")
    t = await tenant(reg)
    segments = await seed_segment_set(t, 1)
    await restricted_disk_evidence(t, segments[0])
    job = await seed_disk_job(t, segments)
    response = await reg.client.get(base(reg, job) + "/exports/notable-hashes.txt")
    assert response.status_code == 200
    assert response.headers["x-cyberlab-sensitivity"] == "restricted"
    assert "notable-hashes-TLP-RED.txt" in response.headers["content-disposition"]
    [audit] = await _audits(t.org_id)
    assert audit.details["sensitivity"] == "restricted"


async def test_unknown_export_names_are_404_and_unaudited() -> None:
    reg = await register(org_name="Disk Export Name Org")
    t, _, url = await windows(reg)
    for name in ("timeline.xlsx", "..%2Fbodyfile", "BODYFILE"):
        response = await reg.client.get(f"{url}/exports/{name}")
        assert response.status_code in (404, 422), name
    assert await _audits(t.org_id) == []
