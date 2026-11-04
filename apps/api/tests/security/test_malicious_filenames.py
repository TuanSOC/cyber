"""Hostile upload metadata: names are stored as inert metadata, never as paths or raw headers."""

import io
import zipfile
from urllib.parse import quote

import pytest

from tests.factories import csrf, register


async def _upload(filename: str, content: bytes = b"payload") -> tuple[int, dict[str, object]]:
    reg = await register()
    c = reg.client
    case = (
        await c.post(
            f"/api/v1/orgs/{reg.org_id}/investigations",
            json={"title": "Filename case", "severity": "low"},
            headers=csrf(c),
        )
    ).json()
    response = await c.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case['id']}/evidence",
        params={"filename": filename},
        content=content,
        headers={"Content-Type": "application/octet-stream", **csrf(c)},
    )
    body = response.json()
    if response.status_code == 201:
        download = await c.get(f"/api/v1/orgs/{reg.org_id}/evidence/{body['id']}/download")
        body["_disposition"] = download.headers["content-disposition"]
        body["_bytes"] = download.content
    return response.status_code, body


@pytest.mark.parametrize(
    ("filename", "stored"),
    [
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\drivers\\etc\\hosts", "hosts"),
        ("a\r\nSet-Cookie: pwned=1.bin", "aSet-Cookie: pwned=1.bin"),
        ("invoice\u202efdp.exe", "invoicefdp.exe"),
        ("zero\u200bwidth\ufeff.doc", "zerowidth.doc"),
        ("<img src=x onerror=alert(1)>.html", "<img src=x onerror=alert(1)>.html"),
        ("x" * 300 + ".pcapng", "x" * 248 + ".pcapng"),  # 255 chars, extension kept
        ("文" * 300 + ".pcap", "文" * 250 + ".pcap"),  # non-ASCII: capped by characters
        ("...", "evidence.bin"),
    ],
)
async def test_hostile_filenames_are_neutralized(filename: str, stored: str) -> None:
    status, body = await _upload(filename)
    assert status == 201
    assert body["original_filename"] == stored
    disposition = str(body["_disposition"])
    assert "\r" not in disposition and "\n" not in disposition
    assert disposition.startswith("attachment;")
    assert disposition.count('"') == 2  # exactly one quoted ASCII fallback
    # RFC 5987 form carries the exact stored name, percent-encoded (no raw non-ASCII in headers).
    assert disposition.endswith(f"filename*=UTF-8''{quote(stored, safe='')}")
    assert disposition.isascii()


@pytest.mark.parametrize("filename", ["evil\x00.exe", ""])
async def test_nul_or_empty_filename_is_rejected(filename: str) -> None:
    status, body = await _upload(filename)
    assert status == 422
    assert body["error"]["code"] == "validation_error"


async def test_zero_byte_evidence_is_accepted_and_hashed() -> None:
    status, body = await _upload("empty.bin", b"")
    assert status == 201
    assert body["size_bytes"] == 0
    hashes = body["hashes"]
    assert isinstance(hashes, dict)
    assert hashes["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert body["_bytes"] == b""


async def test_archive_bytes_are_stored_opaque_never_extracted() -> None:
    """A zip (bomb or not) is evidence like any other: stored and hashed, never opened."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.bin", b"\0" * (20 * 1024 * 1024))  # 20 MiB -> ~20 KiB
    data = buffer.getvalue()
    status, body = await _upload("bomb.zip", data)
    assert status == 201
    assert body["size_bytes"] == len(data)  # compressed size: nothing was inflated
    assert body["_bytes"] == data
