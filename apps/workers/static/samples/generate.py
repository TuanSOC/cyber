"""Synthetic, labeled sample set for tests and detector evaluation (never executed).

Hand-built PE32 / PE32+ / ELF64 files from the pure-Python builders, EICAR assembled at
runtime from split parts, generated archives that ClamAV cannot fully scan (zip bombs,
prefixed / SFX / nested zips with a member above ClamAV's max-filesize, zip64, tar.gz; all
small on disk, never expanded by us), near-miss negatives (one API short of each suspicious
set, a single packer indicator, a high-entropy icon), and, when mingw-w64 is installed
(dev/test image), tiny benign C programs cross-compiled at test time for capa realism.
Nothing is committed as a binary and no real malware is involved: "suspicious" samples only
*reference* API names and strings.

Ground truth goes to labels.json: per scenario the profile to run, the expected file format,
the expected findings (detector + type), signature matches, capabilities and IOCs.

    python -m samples.generate /path/to/out
"""

import gzip
import io
import json
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

from samples import elf, pe

SEED = 20261105
TEST_MARKER = "CYBERLAB-STATIC-TEST-MARKER-7f3a"
STACK_STRING = "cyberlab-stackstr.example.com"
SRC = Path(__file__).parent / "c"
# Above ClamAV's --max-filesize (64 MiB): such a zip member is silently trimmed by ClamAV.
LARGE_MEMBER_MIB = 70
ZIP_DATE = (2026, 1, 1, 0, 0, 0)
PREFIX = b"CYBERLAB-PREFIX-"  # leading data before a zip (ClamAV still finds the zip)
MINGW = {"x64": "x86_64-w64-mingw32-gcc", "x86": "i686-w64-mingw32-gcc"}

Labels = dict[str, dict[str, Any]]

# Reasonable, non-suspicious CRT-ish imports most samples share.
KERNEL32_BASE: list[str | int] = [
    "GetModuleHandleA", "GetCommandLineA", "GetLastError", "ExitProcess", "GetStartupInfoA",
    "HeapAlloc", "HeapFree", "GetProcessHeap", "CloseHandle", "Sleep",
]  # fmt: skip
MSVCRT_BASE: list[str | int] = ["printf", "malloc", "free", "strlen", "memcpy", "exit"]


def eicar() -> bytes:
    """The EICAR anti-virus test file, assembled at runtime (never stored whole)."""
    parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-", "FILE!$H+H*"]
    return "".join(parts).encode("ascii")


def code(rng: random.Random, size: int) -> bytes:
    """Inert x86-ish filler with code-like (moderate) entropy."""
    vocab = [
        b"\x55", b"\x89\xe5", b"\x83\xec\x20", b"\x31\xc0", b"\x8b\x45\xf8", b"\x89\x45\xfc",
        b"\x90", b"\xc3", b"\x5d", b"\x50", b"\x58", b"\x85\xc0", b"\x74\x08", b"\x75\x04",
    ]  # fmt: skip
    out = bytearray()
    while len(out) < size:
        if rng.random() < 0.15:
            out += bytes([0xE8]) + struct.pack("<i", rng.randrange(-4096, 4096))
        else:
            out += rng.choice(vocab)
    return bytes(out[:size])


def stack_string_code(value: str) -> bytes:
    """x86 that builds `value` byte by byte on the stack (only FLOSS's emulator sees it)."""
    out = bytearray(b"\x55\x89\xe5\x83\xec\x40")  # push ebp; mov ebp, esp; sub esp, 0x40
    for i, ch in enumerate(value.encode() + b"\0"):
        out += bytes([0xC6, 0x45, (0x100 - 0x40 + i) & 0xFF, ch])  # mov byte [ebp-0x40+i], ch
    out += b"\x8d\x45\xc0\x50\xe8\x00\x00\x00\x00\x83\xc4\x04\xc9\xc3"  # lea; push; call; leave
    return bytes(out)


def rdata(*strings: str, wide: tuple[str, ...] = ()) -> bytes:
    blob = b"".join(s.encode() + b"\0" for s in strings)
    if wide:  # 2-byte aligned and NUL-separated, as compilers emit them
        blob += b"\0" * (2 + len(blob) % 2)
    blob += b"".join(s.encode("utf-16-le") + b"\0\0" for s in wide)
    return blob


MANIFEST = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
    '  <assemblyIdentity type="win32" name="CyberLab.Benign" version="6.0.0.0"/>\n'
    "</assembly>\n"
)


def _standard(rng: random.Random, *strings: str, wide: tuple[str, ...] = ()) -> list[pe.Section]:
    return [
        pe.Section(".text", code(rng, 0x1800), pe.TEXT),
        pe.Section(".rdata", rdata(*strings, wide=wide), pe.RDATA),
        pe.Section(".data", bytes(rng.randrange(0, 16) for _ in range(0x200)), pe.DATA),
    ]


def build_scenarios(rng: random.Random) -> tuple[dict[str, bytes], Labels]:
    samples: dict[str, bytes] = {}
    labels: Labels = {}

    def add(name: str, data: bytes, **label: Any) -> None:
        samples[name] = data
        label.setdefault("profile", "full")
        label.setdefault("findings", [])
        label.setdefault("signatures", [])
        label.setdefault("iocs", [])
        label.setdefault("capabilities", [])
        label.setdefault("floss", False)  # evaluation runs FLOSS only where it is labelled
        label.setdefault("benign", not label["findings"] and not label["signatures"])
        labels[name] = label

    add(
        "benign_pe32",
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=_standard(
                    rng,
                    "Hello from the CyberLab benign sample",
                    "Usage: %s <input-file>",
                    "Documentation: https://www.example.com/help/index.html",
                    "kernel32.dll",
                    "settings.ini",
                    wide=("CyberLab Benign Sample",),
                ),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE + ["LoadLibraryA", "GetProcAddress"],
                    "msvcrt.dll": MSVCRT_BASE,
                    "USER32.dll": ["MessageBoxA"],
                },
                resources=[
                    pe.Resource(pe.RT_MANIFEST, 1, MANIFEST.encode()),
                    pe.Resource(pe.RT_RCDATA, 2, b"[settings]\nlanguage=en\n" * 8),
                ],
                rich=[(0x0104, 30148, 12), (0x0105, 30148, 3), (0x0102, 30148, 1)],
            )
        ),
        file_format="pe",
        iocs=[
            {"type": "url", "value": "https://www.example.com/help/index.html"},
            {"type": "domain", "value": "www.example.com"},
        ],
    )
    add(
        "benign_pe64",
        pe.build(
            pe.PeSpec(
                bits=64,
                dll=True,
                sections=_standard(rng, "CyberLab benign library", "config.Path"),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE,
                    "ADVAPI32.dll": ["RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey"],
                },
                exports=["CyberLabInit", "CyberLabProcess", "CyberLabShutdown"],
                dll_name="cyberlab_benign.dll",
                certificate=bytes(rng.randrange(256) for _ in range(512)),
            )
        ),
        file_format="pe",
    )
    upx1 = rng.randbytes(0x3000) + b"UPX!" + rng.randbytes(0x400)
    add(
        "packed_like",
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=[
                    pe.Section("UPX0", b"", pe.TEXT | pe.SCN_WRITE | pe.SCN_UDATA, 0x30000),
                    pe.Section("UPX1", upx1, pe.TEXT | pe.SCN_WRITE),
                ],
                imports={"KERNEL32.DLL": ["LoadLibraryA", "GetProcAddress"]},
                entry_section="UPX1",
                entry_offset=0x3200,
            )
        ),
        file_format="pe",
        findings=[
            {"detector": "packer", "type": "packer_indicators"},
            {"detector": "yara", "type": "yara_match", "name": "CyberLab_UPX_Section_Names"},
            {"detector": "yara", "type": "yara_match", "name": "CyberLab_UPX_Marker_String"},
            {"detector": "capa", "type": "capability_anti_analysis"},
        ],
        capabilities=["packed with UPX"],
        signatures=[
            {"engine": "yara", "name": "CyberLab_UPX_Section_Names"},
            {"engine": "yara", "name": "CyberLab_UPX_Marker_String"},
        ],
    )
    add(
        "injection_imports",
        pe.build(
            pe.PeSpec(
                bits=64,
                sections=_standard(rng, "target process id: %lu", "explorer.exe"),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE
                    + ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    "msvcrt.dll": MSVCRT_BASE,
                },
            )
        ),
        file_format="pe",
        findings=[
            {"detector": "suspicious_api", "type": "api_injection"},
            {
                "detector": "yara",
                "type": "yara_match",
                "name": "CyberLab_Process_Injection_API_Names",
            },
        ],
        signatures=[{"engine": "yara", "name": "CyberLab_Process_Injection_API_Names"}],
    )
    add(
        "keylogger_imports",
        pe.build(
            pe.PeSpec(
                bits=32,
                gui=True,
                sections=_standard(rng, "keys.log", "[%02x]"),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE + ["CreateFileA", "WriteFile"],
                    "USER32.dll": [
                        "SetWindowsHookExA",
                        "CallNextHookEx",
                        "GetAsyncKeyState",
                        "GetKeyState",
                        "GetMessageA",
                        "UnhookWindowsHookEx",
                    ],
                },  # fmt: skip
            )
        ),
        file_format="pe",
        findings=[
            {"detector": "suspicious_api", "type": "api_keylogging"},
            {"detector": "yara", "type": "yara_match", "name": "CyberLab_Keyboard_Hook_API_Names"},
        ],
        signatures=[{"engine": "yara", "name": "CyberLab_Keyboard_Hook_API_Names"}],
    )
    add(
        "test_marker",
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=_standard(rng, "CyberLab test marker sample", TEST_MARKER),
                imports={"KERNEL32.dll": KERNEL32_BASE, "msvcrt.dll": MSVCRT_BASE},
            )
        ),
        file_format="pe",
        findings=[
            {"detector": "yara", "type": "yara_match", "name": "CyberLab_Test_Marker"},
            {"detector": "clamav", "type": "av_signature_match", "name": "PUA.CyberLab.TestMarker"},
        ],
        signatures=[
            {"engine": "yara", "name": "CyberLab_Test_Marker"},
            {"engine": "clamav", "name": "PUA.CyberLab.TestMarker"},
        ],
    )
    add(
        "antidebug_imports",
        pe.build(
            pe.PeSpec(
                bits=64,
                sections=_standard(rng, "debugger check"),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE
                    + ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"],
                    "ntdll.dll": ["NtQueryInformationProcess"],
                },
            )
        ),
        file_format="pe",
        findings=[{"detector": "suspicious_api", "type": "api_anti_debug"}],
    )
    add(
        "credential_imports",
        pe.build(
            pe.PeSpec(
                bits=64,
                sections=_standard(rng, "credential export"),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE + ["OpenProcess"],
                    "ADVAPI32.dll": ["CredEnumerateA", "CredReadA", "CredFree"],
                    "CRYPT32.dll": ["CryptUnprotectData"],
                    "dbghelp.dll": ["MiniDumpWriteDump"],
                },
            )
        ),
        file_format="pe",
        findings=[{"detector": "suspicious_api", "type": "api_credential_access"}],
    )
    run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    add(
        "persistence_imports",
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=_standard(
                    rng, run_key, "C:\\ProgramData\\CyberLabTest\\updater.exe", "CyberLabUpdater"
                ),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE,
                    "ADVAPI32.dll": [
                        "RegCreateKeyExA",
                        "RegSetValueExA",
                        "RegCloseKey",
                        "OpenSCManagerA",
                        "CreateServiceA",
                        "StartServiceA",
                        "CloseServiceHandle",
                    ],
                },  # fmt: skip
            )
        ),
        file_format="pe",
        findings=[{"detector": "suspicious_api", "type": "api_persistence"}],
        iocs=[
            {"type": "registry_key", "value": run_key},
            {"type": "file_path", "value": "C:\\ProgramData\\CyberLabTest\\updater.exe"},
        ],
    )
    add(
        "downloader_imports",
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=_standard(
                    rng,
                    "http://downloads.example.net/update/payload.bin",
                    "198.51.100.23",
                    "support@example.org",
                    "%TEMP%\\cyberlab-update.exe",
                    wide=("https://cdn.example.org/files/setup.msi",),
                ),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE + ["WinExec"],
                    "urlmon.dll": ["URLDownloadToFileA"],
                    "WININET.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"],
                },
            )
        ),
        file_format="pe",
        findings=[{"detector": "suspicious_api", "type": "api_downloader"}],
        iocs=[
            {"type": "url", "value": "http://downloads.example.net/update/payload.bin"},
            {"type": "url", "value": "https://cdn.example.org/files/setup.msi"},
            {"type": "domain", "value": "downloads.example.net"},
            {"type": "domain", "value": "cdn.example.org"},
            {"type": "ip", "value": "198.51.100.23"},
            {"type": "email", "value": "support@example.org"},
            {"type": "file_path", "value": "%TEMP%\\cyberlab-update.exe"},
        ],
    )
    embedded = pe.build(
        pe.PeSpec(bits=32, sections=_standard(rng, "embedded"), imports={"KERNEL32.dll": ["Sleep"]})
    )
    add(
        "pe_anomalies",
        pe.build(
            pe.PeSpec(
                bits=32,
                timestamp=4_070_908_800,  # 2099-01-01: in the future
                sections=_standard(rng, "anomalies sample"),
                imports={"KERNEL32.dll": KERNEL32_BASE, "msvcrt.dll": MSVCRT_BASE},
                tls_callbacks=2,
                resources=[pe.Resource(pe.RT_RCDATA, 101, rng.randbytes(0x2000))],
                overlay=embedded + rng.randbytes(0x800),
            )
        ),
        file_format="pe",
        findings=[
            {"detector": "pe_anomaly", "type": "timestamp_anomaly"},
            {"detector": "pe_anomaly", "type": "tls_callbacks"},
            {"detector": "pe_anomaly", "type": "high_entropy_resource"},
            {"detector": "pe_anomaly", "type": "overlay"},
            {"detector": "yara", "type": "yara_match", "name": "CyberLab_Embedded_PE_In_Overlay"},
        ],
        signatures=[{"engine": "yara", "name": "CyberLab_Embedded_PE_In_Overlay"}],
    )
    add(
        "benign_elf",
        elf.build(
            elf.ElfSpec(
                imports=["puts", "printf", "malloc", "free", "__libc_start_main"],
                text=code(rng, 0x600),
                rodata=rdata("Hello from the CyberLab benign ELF sample", "usage: %s FILE"),
                data=bytes(64),
                local_symbols=["main", "parse_args", "checksum"],
            )
        ),
        file_format="elf",
    )
    add(
        "stack_string",
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=[
                    pe.Section(
                        ".text", stack_string_code(STACK_STRING) + code(rng, 0x400), pe.TEXT
                    ),
                    pe.Section(".rdata", rdata("stack string sample"), pe.RDATA),
                ],
                imports={"KERNEL32.dll": ["ExitProcess", "GetModuleHandleA", "Sleep"]},
            )
        ),
        file_format="pe",
        findings=[{"detector": "capa", "type": "capability_anti_analysis"}],
        capabilities=["contain obfuscated stackstrings"],
        iocs=[{"type": "domain", "value": STACK_STRING, "source": "floss"}],
        floss=True,
    )
    # Near misses: each must stay below every finding (labelled benign, nothing above info).
    add(
        "near_miss_apis",  # one API group short of every suspicious set
        pe.build(
            pe.PeSpec(
                bits=64,
                sections=_standard(rng, "near miss sample", "settings.dat"),
                imports={
                    "KERNEL32.dll": KERNEL32_BASE
                    + ["VirtualAllocEx", "WriteProcessMemory", "IsDebuggerPresent", "CreateFileA"],
                    "USER32.dll": ["GetAsyncKeyState", "GetKeyState", "GetMessageA"],
                    "ADVAPI32.dll": [
                        "CredReadA",
                        "CredFree",
                        "RegCreateKeyExA",
                        "RegSetValueExA",
                        "RegCloseKey",
                        "OpenSCManagerA",
                        "CloseServiceHandle",
                    ],
                    "urlmon.dll": ["URLDownloadToFileA"],
                },  # fmt: skip
            )
        ),
        file_format="pe",
        near_miss=True,
    )
    add(
        "near_miss_packer",  # a single packer indicator (tiny import table)
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=_standard(rng, "plugin loader"),
                imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress"]},
            )
        ),
        file_format="pe",
        near_miss=True,
    )
    add(
        "near_miss_icon",  # compressed image resources are expected to be high-entropy
        pe.build(
            pe.PeSpec(
                bits=32,
                sections=_standard(rng, "icon sample"),
                imports={"KERNEL32.dll": KERNEL32_BASE, "msvcrt.dll": MSVCRT_BASE},
                resources=[pe.Resource(pe.RT_ICON, 1, rng.randbytes(0x2000))],
            )
        ),
        file_format="pe",
        near_miss=True,
    )
    add(
        "eicar",
        eicar(),
        profile="av",
        file_format="other",
        signatures=[{"engine": "clamav", "name": "CyberLab.Test.EICAR"}],
        findings=[
            {"detector": "clamav", "type": "av_signature_match", "name": "CyberLab.Test.EICAR"}
        ],
    )
    return samples, labels


def nested_zip_bomb(path: Path, depth: int = 20, zeros_mib: int = 300) -> None:
    """`zeros_mib` MiB of zeros, zipped, then re-zipped `depth` times (~0.3 MB on disk).

    Bounded for the test box: ClamAV's recursion / file-size limits stop it long before the
    inner member is expanded, and nothing here ever expands it either.
    """
    chunk = bytes(1024 * 1024)

    def member(name: str) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))  # deterministic
        info.compress_type = zipfile.ZIP_DEFLATED
        return info

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compresslevel=9) as z:
        with z.open(member("zeros.bin"), "w") as f:  # streamed: never 300 MiB in memory
            for _ in range(zeros_mib):
                f.write(chunk)
    data = buffer.getvalue()
    for level in range(depth):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            z.writestr(member(f"level{depth - level}.zip"), data)
        data = buffer.getvalue()
    path.write_bytes(data)


def large_member_zip(*, zip64: bool = False) -> bytes:
    """A zip whose single member inflates to LARGE_MEMBER_MIB MiB of zeros (~70 KB on disk)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compresslevel=9) as z:
        info = zipfile.ZipInfo("zeros.bin", date_time=ZIP_DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        with z.open(info, "w", force_zip64=zip64) as f:
            chunk = bytes(1024 * 1024)
            for _ in range(LARGE_MEMBER_MIB):
                f.write(chunk)
    return buffer.getvalue()


class _Unseekable(io.RawIOBase):
    """Write-only stream: zipfile then writes data descriptors (flag bit 3)."""

    def __init__(self, target: io.BytesIO) -> None:
        self.target = target

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:  # type: ignore[override]
        return self.target.write(data)


def zip64_data_descriptor() -> bytes:
    """A small deflated zip64 member written with a data descriptor (ClamAV skips it)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(_Unseekable(buffer), "w") as z:
        info = zipfile.ZipInfo("notes.txt", date_time=ZIP_DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        with z.open(info, "w", force_zip64=True) as f:
            f.write(b"zip64 member with a data descriptor.\n" * 64)
    return buffer.getvalue()


def nested_zip(inner: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        info = zipfile.ZipInfo("inner.bin", date_time=ZIP_DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, inner)
    return buffer.getvalue()


def large_member_tar_gz() -> bytes:
    """tar.gz with one LARGE_MEMBER_MIB MiB member (ClamAV raises its own limit alert)."""
    raw = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as stream,
        tarfile.open(fileobj=stream, mode="w|") as tar,
    ):
        info = tarfile.TarInfo("zeros.bin")
        info.size = LARGE_MEMBER_MIB * 1024 * 1024
        tar.addfile(info, _Zeros(info.size))
    return raw.getvalue()


class _Zeros(io.RawIOBase):
    def __init__(self, size: int) -> None:
        self.left = size

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:  # type: ignore[override]
        n = min(len(buffer), self.left)
        buffer[:n] = bytes(n)
        self.left -= n
        return n


def lying_size_zip(data: bytes, declared: int) -> bytes:
    """`data` zipped, then its local + central headers rewritten to claim `declared` bytes.

    ClamAV inflates the real stream (and trims it at --max-filesize, silently); zipfile would
    stop at the declared size. CRCs are left alone: only sizes lie.
    """
    out = bytearray(data)
    for signature, at in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        pos = out.find(signature)
        while pos != -1:
            struct.pack_into("<I", out, pos + at, declared)
            pos = out.find(signature, pos + 4)
    return bytes(out)


def deflate_zeros(mib: int) -> bytes:
    """Raw deflate of `mib` MiB of zeros, streamed (~1 KB per MiB)."""
    encoder = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    chunk = bytes(1024 * 1024)
    return b"".join(encoder.compress(chunk) for _ in range(mib)) + encoder.flush()


def local_entry(
    body: bytes, size: int, *, name: bytes = b"m.bin", version: int = 20, method: int = 8
) -> bytes:
    """One local file header + data, no central directory (ClamAV still extracts it)."""
    header = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", version, 0, method, 0, 0x21, 0, len(body), size,
        len(name), 0,
    )  # fmt: skip
    return header + name + body


def hidden_in_extra(hidden: bytes) -> bytes:
    """A valid one-member zip whose LOCAL extra field carries `hidden` (another local entry).

    The central directory has no extra field, so only the member's header bytes contain it;
    ClamAV still extracts the hidden entry.
    """
    name, body = b"cover.txt", b"cover member\n"
    crc = zlib.crc32(body)
    extra = struct.pack("<HH", 0xCAFE, len(hidden)) + hidden  # one well-formed extra record
    local = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0x21, crc, len(body), len(body), len(name),
        len(extra),
    ) + name + extra + body  # fmt: skip
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0x21, crc, len(body), len(body),
        len(name), 0, 0, 0, 0, 0, 0,
    ) + name  # fmt: skip
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def raw_deflate(data: bytes) -> bytes:
    encoder = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return encoder.compress(data) + encoder.flush()


def zip_in_extra_field() -> bytes:
    """Hidden entry = a deflated zip whose member is LARGE_MEMBER_MIB MiB (fits in 64 KiB).

    Prefixed: ClamAV's embedded-zip scan then extracts the hidden entry (measured in the
    image: marker found when small; clean, silently trimmed, with the 70 MiB member).
    """
    inner = large_member_zip()
    hidden = local_entry(raw_deflate(inner), len(inner), name=b"inner.zip")
    return PREFIX + hidden_in_extra(hidden)


def odd_local_headers(mib: int = LARGE_MEMBER_MIB) -> dict[str, bytes]:
    """Prefixed, central-directory-less zips with unusual (but extractable) local headers."""
    body, size = deflate_zeros(mib), mib * 1024 * 1024
    return {
        "nameless": PREFIX + local_entry(body, size, name=b""),
        "version_255": PREFIX + local_entry(body, size, version=255),
        "long_name": PREFIX + local_entry(body, size, name=b"n" * 5000),
    }


def not_fully_scannable(benign_pe: bytes) -> dict[str, bytes]:
    """RT2 regressions: archives ClamAV cannot (or does not) scan completely."""
    large = large_member_zip()
    return {
        "zip_prefixed_large_member": PREFIX * 64 + large,
        "sfx_pe_zip_large_member": benign_pe + large,  # PE + appended zip ("SFX")
        "zip_nested_prefixed": nested_zip(PREFIX * 16 + large),
        "zip64_data_descriptor": zip64_data_descriptor(),
        "tar_gz_large_member": large_member_tar_gz(),
        "zip_prefixed_lying_size": PREFIX * 4 + lying_size_zip(large, 1024),
        "zip_local_header_nameless": odd_local_headers()["nameless"],
        "zip_hidden_in_extra_field": zip_in_extra_field(),
    }


def compile_c(source: Path, out: Path, arch: str) -> bool:
    compiler = shutil.which(MINGW[arch])
    if compiler is None:
        return False
    subprocess.run(  # noqa: S603 - fixed argv, test-time cross-compilation only
        [compiler, "-O1", "-s", "-o", str(out), str(source), "-Wl,--no-insert-timestamp"],
        check=True,
        capture_output=True,
    )
    return True


def generate(out: Path, *, mingw: bool = True) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    samples, labels = build_scenarios(rng)
    paths: dict[str, Path] = {}
    for name, data in samples.items():
        path = out / f"{name}.bin"
        path.write_bytes(data)
        paths[name] = path

    bomb = out / "nested_zip_bomb.bin"
    nested_zip_bomb(bomb)
    paths["nested_zip_bomb"] = bomb
    labels["nested_zip_bomb"] = {
        "profile": "av", "file_format": "other", "findings": [], "signatures": [], "iocs": [],
        "capabilities": [], "benign": True, "expect_not_fully_scanned": True, "floss": False,
    }  # fmt: skip
    large = out / "zip_large_member.bin"
    nested_zip_bomb(large, depth=1)
    paths["zip_large_member"] = large
    labels["zip_large_member"] = {**labels["nested_zip_bomb"]}
    for name, data in not_fully_scannable(samples["benign_pe32"]).items():
        path = out / f"{name}.bin"
        path.write_bytes(data)
        paths[name] = path
        labels[name] = {
            **labels["nested_zip_bomb"],
            "file_format": "pe" if data[:2] == b"MZ" else "other",
        }

    if mingw:
        builds = {
            "mingw_hello": ("hello.c", "x64"),
            "mingw_hello32": ("hello.c", "x86"),
            "mingw_injector": ("injector.c", "x64"),
        }
        for name, (source, arch) in builds.items():
            path = out / f"{name}.exe"
            if compile_c(SRC / source, path, arch):
                paths[name] = path
                labels[name] = mingw_labels(name)
    (out / "labels.json").write_text(json.dumps(labels, indent=2, sort_keys=True))
    return paths


def mingw_labels(name: str) -> dict[str, Any]:
    """Facts of the cross-compiled programs (mingw's CRT registers TLS callbacks)."""
    base: dict[str, Any] = {
        "profile": "full",
        "file_format": "pe",
        "findings": [{"detector": "pe_anomaly", "type": "tls_callbacks"}],
        "signatures": [],
        "iocs": [],
        "capabilities": [],
        "benign": True,
        "mingw": True,
        "floss": name == "mingw_injector",
    }
    if name == "mingw_injector":
        base["benign"] = False
        base["findings"] = [
            *base["findings"],
            {"detector": "suspicious_api", "type": "api_injection"},
            {"detector": "capa", "type": "capability_injection"},
            {
                "detector": "yara",
                "type": "yara_match",
                "name": "CyberLab_Process_Injection_API_Names",
            },
        ]
        base["signatures"] = [{"engine": "yara", "name": "CyberLab_Process_Injection_API_Names"}]
        base["capabilities"] = ["inject thread", "allocate or change RWX memory", "create thread"]
    return base


if __name__ == "__main__":
    generated = generate(Path(sys.argv[1]))
    print("\n".join(f"{name}: {path}" for name, path in sorted(generated.items())))
