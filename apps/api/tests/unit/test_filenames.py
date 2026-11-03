import pytest

from app.core.filenames import FALLBACK, MAX_FILENAME, content_disposition, sanitize_filename


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("capture.pcap", "capture.pcap"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\victim\\dump.raw", "dump.raw"),
        ("a\r\nSet-Cookie: x=1.bin", "aSet-Cookie: x=1.bin"),
        ("nul\x00byte.exe", "nulbyte.exe"),
        ("invoice\u202etxt.exe", "invoicetxt.exe"),  # RTL override removed
        ("zero\u200bwidth.doc", "zerowidth.doc"),
        ("   ", FALLBACK),
        ("", FALLBACK),
        ("...", FALLBACK),
        ("dir/", FALLBACK),
        ("Ma\u0301lware.pdf", "Málware.pdf"),  # NFC normalized
    ],
)
def test_sanitize_filename(raw: str, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def test_long_name_keeps_extension() -> None:
    name = sanitize_filename("a" * 400 + ".pcapng")
    assert len(name) == MAX_FILENAME and name.endswith(".pcapng")


def test_content_disposition_is_header_safe() -> None:
    header = content_disposition('evil"; filename="x.html\r\n.pdf')
    assert "\r" not in header and "\n" not in header
    assert header.startswith('attachment; filename="')
    assert header.count('"') == 2


def test_content_disposition_unicode_uses_rfc5987() -> None:
    header = content_disposition("báo cáo.pdf")
    assert "filename*=UTF-8''b%C3%A1o%20c%C3%A1o.pdf" in header
    assert 'filename="bo co.pdf"' in header
