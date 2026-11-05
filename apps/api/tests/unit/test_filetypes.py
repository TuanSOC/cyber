"""Declared vs detected file families (M7 phase 6): pure, never raising, flag-only."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.core import filetypes
from app.core.filenames import sanitize_filename

PCAP = bytes.fromhex("d4c3b2a1") + bytes(20)
PCAPNG = bytes.fromhex("0a0d0d0a") + bytes(20)
PE = b"MZ" + bytes(0x3A) + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(64)
ELF = bytes.fromhex("7f454c46") + bytes([2, 1, 1]) + bytes(9) + (2).to_bytes(2, "little") + bytes(8)


@pytest.mark.parametrize(
    ("filename", "family"),
    [
        ("capture.pcap", "pcap"),
        ("capture.PCAPNG", "pcap"),
        ("trace.cap", "pcap"),
        ("setup.exe", "pe"),
        ("x.dll", "pe"),
        ("driver.sys", "pe"),
        ("screen.scr", "pe"),
        ("panel.cpl", "pe"),
        ("ctl.ocx", "pe"),
        ("libc.so", "elf"),
        ("payload.elf", "elf"),
        ("invoice.pdf", "pdf"),
        ("a.zip", "zip"),
        ("a.jar", "zip"),
        ("a.apk", "zip"),
        ("a.docx", "zip"),
        ("a.xlsx", "zip"),
        ("a.pptx", "zip"),
        ("a.doc", "office_legacy"),
        ("a.xls", "office_legacy"),
        ("a.ppt", "office_legacy"),
        ("a.png", "image"),
        ("a.JPEG", "image"),
        ("notes.txt", "text"),
        ("syslog.log", "text"),
        ("rows.csv", "text"),
        ("ioc.json", "text"),
        ("a.7z", "archive"),
        ("a.rar", "archive"),
        ("capture.pcap.gz", "archive"),
        ("a.tar", "archive"),
        ("evil.exe.", "pe"),  # trailing dots / spaces are dropped like Windows does
        ("evil.exe  ", "pe"),
        ("invoicefdp.exe", "pe"),  # the sanitized RLO name: the real extension wins
        ("binary", None),  # no extension (an ELF usually has none)
        (".pcap", None),  # a hidden file, not an extension
        ("archive.", None),
        ("evidence.bin", None),
        ("a.unknownext", None),
        ("a." + "x" * 40, None),
        ("", None),
        ("...", None),
    ],
)
def test_declared_family(filename: str, family: str | None) -> None:
    assert filetypes.declared_family(filename) == family


@pytest.mark.parametrize(
    ("head", "route"),
    [
        (PCAP, "pcap"),
        (PCAPNG, "pcapng"),
        (PE, "pe"),
        (ELF, "elf"),
        (b"%PDF-1.7", None),
        (b"", None),
    ],
)
def test_magic_route(head: bytes, route: str | None) -> None:
    assert filetypes.magic_route(head) == route


@pytest.mark.parametrize(
    ("mime", "route", "family"),
    [
        ("application/octet-stream", "pcapng", "pcap"),  # the routing wins over libmagic
        ("application/vnd.tcpdump.pcap", None, "pcap"),
        ("application/x-dosexec", None, "pe"),
        ("application/vnd.microsoft.portable-executable", "pe", "pe"),
        ("application/x-sharedlib", None, "elf"),
        ("application/x-pie-executable", "elf", "elf"),
        ("application/pdf", None, "pdf"),
        ("application/zip", None, "zip"),
        ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", None, "zip"),
        ("application/msword", None, "office_legacy"),
        ("application/CDFV2", None, "office_legacy"),
        ("image/png", None, "image"),
        ("text/plain; charset=us-ascii", None, "text"),
        ("application/json", None, "text"),
        ("application/gzip", None, "archive"),
        ("application/x-7z-compressed", None, "archive"),
        ("application/octet-stream", None, None),
        ("inode/x-empty", None, None),
        ("", None, None),
        (None, None, None),
        ("not a mime \x00‮", "garbage", None),
    ],
)
def test_detected_family(mime: str | None, route: str | None, family: str | None) -> None:
    assert filetypes.detected_family(mime, route) == family


@pytest.mark.parametrize(
    ("declared", "detected", "mismatch"),
    [
        ("pdf", "pe", True),  # an .exe named invoice.pdf
        ("text", "pe", True),
        ("image", "elf", True),
        ("pcap", "pcap", False),  # a pcapng named .pcap
        ("zip", "zip", False),  # OOXML is zip-based
        ("text", "text", False),  # JSON detected as text/plain
        ("archive", "zip", False),  # benign pair
        ("zip", "archive", False),
        (None, "pe", False),  # unknown never counts
        ("pdf", None, False),
        (None, None, False),
    ],
)
def test_type_mismatch(declared: str | None, detected: str | None, mismatch: bool) -> None:
    assert filetypes.type_mismatch(declared, detected) is mismatch


def test_benign_pairs_are_symmetric() -> None:
    assert all((b, a) in filetypes.BENIGN_PAIRS for a, b in filetypes.BENIGN_PAIRS)


@given(st.text(max_size=400))
def test_hostile_names_never_raise(raw: str) -> None:
    for name in (raw, sanitize_filename(raw)):
        family = filetypes.declared_family(name)
        assert family is None or isinstance(family, str)


@given(st.text(max_size=200), st.one_of(st.none(), st.text(max_size=20)))
def test_hostile_mimes_never_raise(mime: str, route: str | None) -> None:
    family = filetypes.detected_family(mime, route)
    assert family is None or isinstance(family, str)


@given(st.binary(max_size=256))
def test_magic_route_never_raises(head: bytes) -> None:
    assert filetypes.magic_route(head) in {None, "pcap", "pcapng", "pe", "elf"}
