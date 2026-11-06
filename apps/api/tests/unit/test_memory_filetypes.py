"""The `memory` declared type (M8 phase 6): image extensions or `kind=memory`, never a
mismatch on content without magic, and never a routing to the memory analyzer."""

import pytest
from starlette.requests import Request

from app.core import filetypes
from app.core.config import get_settings
from app.modules.analysis.service import auto_choice
from app.modules.evidence import uploads
from app.modules.memory_analysis.errors import MemoryImageTooLarge

LIME = b"EMiL" + (1).to_bytes(4, "little") + bytes(24)  # LiME range header magic
CRASH_DUMP = b"PAGEDU64" + bytes(56)
ELF_CORE = bytes.fromhex("7f454c46") + bytes([2, 1, 1]) + bytes(9) + (4).to_bytes(2, "little")
PE = b"MZ" + bytes(0x3A) + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(64)
GIB = 1024**3


@pytest.mark.parametrize(
    "filename",
    ["host.raw", "host.mem", "vm.vmem", "dump.lime", "MEMORY.DMP", "vmcore.core", "x.Raw."],
)
def test_image_extensions_declare_memory(filename: str) -> None:
    assert filetypes.declared_family(filename) == "memory"


@pytest.mark.parametrize("filename", ["image.bin", "evil.exe", "noext", "capture.pcap", ""])
def test_kind_memory_declares_memory_whatever_the_name(filename: str) -> None:
    assert filetypes.declared_family(filename, kind="memory") == "memory"
    assert filetypes.declared_family(filename, kind=None) != "memory"


@pytest.mark.parametrize("head", [bytes(64), LIME, CRASH_DUMP, ELF_CORE, b"\xff" * 64])
def test_image_content_has_no_routing(head: bytes) -> None:
    # No magic routes to memory, and LiME / crash-dump / ELF core heads route nowhere.
    assert filetypes.magic_route(head) is None


@pytest.mark.parametrize(
    "mime", ["application/octet-stream", "inode/x-empty", "application/x-coredump", None]
)
def test_memory_without_magic_is_not_a_mismatch(mime: str | None) -> None:
    detected = filetypes.detected_family(mime, None)
    assert detected is None
    assert filetypes.type_mismatch("memory", detected) is False


def test_an_executable_named_as_an_image_is_flagged() -> None:
    detected = filetypes.detected_family("application/x-dosexec", filetypes.magic_route(PE))
    assert detected == "pe"
    assert filetypes.type_mismatch("memory", detected) is True


@pytest.mark.parametrize("head", [LIME, CRASH_DUMP, ELF_CORE, bytes(4096)])
def test_auto_choice_never_picks_memory(head: bytes) -> None:
    choice = auto_choice(head, len(head), get_settings())
    assert choice is None or choice[0] != "memory"


def _request(length: int) -> Request:
    headers = [
        (b"content-type", b"application/octet-stream"),
        (b"content-length", str(length).encode()),
    ]
    return Request({"type": "http", "method": "POST", "headers": headers})


def test_a_memory_upload_has_its_own_declared_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT14: a 4 GiB image passes under `kind=memory` (8 GiB default) and is refused without
    it (2 GiB); declared lengths only, no bytes."""
    settings = get_settings()
    monkeypatch.setattr(settings, "memory_max_bytes", 8 * GIB)
    monkeypatch.setattr(settings, "max_evidence_bytes", 2 * GIB)
    assert uploads._check_request(_request(4 * GIB), "memory") == 4 * GIB
    with pytest.raises(uploads.PayloadTooLarge):
        uploads._check_request(_request(4 * GIB))
    with pytest.raises(MemoryImageTooLarge) as info:
        uploads._check_request(_request(8 * GIB + 1), "memory")
    assert info.value.status_code == 413 and info.value.code == "memory_image_too_large"
    assert uploads.max_upload_bytes("memory") == 8 * GIB
    assert uploads.max_upload_bytes(None) == 2 * GIB
