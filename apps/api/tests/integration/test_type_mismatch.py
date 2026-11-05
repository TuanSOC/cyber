"""Declared type vs detected type at upload (M7 phase 6): flagged and audited in the upload's
transaction, never rejected; the columns are write-once (evidence_immutable)."""

import uuid
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.evidence.models import Evidence
from tests.factories import Registered, csrf, register

PE = b"MZ" + bytes(0x3A) + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(512)
PCAPNG = (
    bytes.fromhex("0a0d0d0a") + bytes.fromhex("1c000000") + bytes.fromhex("4d3c2b1a") + bytes(64)
)
PDF = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << >>\n%%EOF\n"

# The names of tests/security/test_malicious_filenames.py (hostile input never crashes).
HOSTILE_NAMES = [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "a\r\nSet-Cookie: pwned=1.bin",
    "invoice‮fdp.exe",
    "zero​width﻿.doc",
    "<img src=x onerror=alert(1)>.html",
    "x" * 300 + ".pcapng",
    "文" * 300 + ".pcap",
    "...",
    "evil.pdf.",
    "%00.pdf",
]


async def _case(reg: Registered) -> str:
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Type case", "severity": "low"},
        headers=csrf(reg.client),
    )
    return str(response.json()["id"])


async def _upload(reg: Registered, case_id: str, filename: str, data: bytes) -> Any:
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}/evidence",
        params={"filename": filename},
        content=data,
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _row(org_id: uuid.UUID, evidence_id: str) -> Evidence:
    async with tenant_session(org_id, None) as s:
        return (await s.execute(select(Evidence).where(Evidence.id == evidence_id))).scalar_one()


async def _mismatch_audits(org_id: uuid.UUID) -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        stmt = select(AuditLog).where(AuditLog.action == "evidence.type_mismatch")
        return list((await s.execute(stmt)).scalars())


async def test_exe_named_pdf_is_flagged_and_audited_not_rejected() -> None:
    reg = await register()
    case_id = await _case(reg)
    body = await _upload(reg, case_id, "invoice.pdf", PE)
    assert (body["declared_type"], body["type_mismatch"]) == ("pdf", True)
    row = await _row(reg.org_id, body["id"])
    assert (row.declared_type, row.type_mismatch) == ("pdf", True)
    [log] = await _mismatch_audits(reg.org_id)
    assert log.target_type == "evidence" and str(log.target_id) == body["id"]
    assert log.actor_id == reg.user_id
    assert log.details == {"declared_type": "pdf", "detected_type": "pe"}
    # Still stored and downloadable byte for byte (flag only).
    download = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{body['id']}/download")
    assert download.content == PE


@pytest.mark.parametrize(
    ("filename", "data", "declared"),
    [
        ("capture.pcap", PCAPNG, "pcap"),  # a pcapng named .pcap
        ("report.pdf", PDF, "pdf"),
        ("notes.txt", b"plain analyst notes\n", "text"),
        ("iocs.json", b'{"ioc": "1.2.3.4"}\n', "text"),
    ],
)
async def test_matching_types_are_not_flagged(filename: str, data: bytes, declared: str) -> None:
    reg = await register()
    body = await _upload(reg, await _case(reg), filename, data)
    assert (body["declared_type"], body["type_mismatch"]) == (declared, False)
    row = await _row(reg.org_id, body["id"])
    assert (row.declared_type, row.type_mismatch) == (declared, False)
    assert await _mismatch_audits(reg.org_id) == []


async def test_no_extension_declares_nothing() -> None:
    reg = await register()
    body = await _upload(reg, await _case(reg), "dropper", PE)
    assert (body["declared_type"], body["type_mismatch"]) == (None, False)
    row = await _row(reg.org_id, body["id"])
    assert (row.declared_type, row.type_mismatch) == (None, False)
    assert await _mismatch_audits(reg.org_id) == []


async def test_hostile_filenames_never_crash_the_classification() -> None:
    reg = await register()
    case_id = await _case(reg)
    for name in HOSTILE_NAMES:
        body = await _upload(reg, case_id, name, PE)
        assert isinstance(body["type_mismatch"], bool)
        row = await _row(reg.org_id, body["id"])
        assert row.type_mismatch is body["type_mismatch"]
        assert row.declared_type == body["declared_type"]
    # The RLO name keeps its real extension (.exe): a PE named as a PE is no mismatch.
    rows = await _upload(reg, case_id, "invoice‮fdp.exe", PE)
    assert (rows["declared_type"], rows["type_mismatch"]) == ("pe", False)


@pytest.mark.parametrize(
    "assignment",
    [
        "declared_type = 'pe'",
        "type_mismatch = false",
        "declared_type = NULL",
        "type_mismatch = NULL",
    ],
)
async def test_type_columns_are_write_once_after_upload(assignment: str) -> None:
    reg = await register()
    body = await _upload(reg, await _case(reg), "invoice.pdf", PE)
    with pytest.raises(DBAPIError, match="write-once"):
        async with tenant_session(reg.org_id, reg.user_id) as s:
            await s.execute(
                text(f"UPDATE evidence SET {assignment} WHERE id = :e"), {"e": body["id"]}
            )
    row = await _row(reg.org_id, body["id"])
    assert (row.declared_type, row.type_mismatch) == ("pdf", True)
