"""Structural edge cases for the RE engines (M10 phase 4): inputs with no function truth that
only have to end cleanly (a result, or a classified error code; never a crash or a hang).

Built from the M3 pure-Python PE builder (`apps/workers/static/samples/pe.py`), imported by
path, never copied (RT7 spirit: one builder). It is looked up in `CYBERLAB_M3_SAMPLES`, then
`/opt/samples/m3` (the dev image), then the repository's static worker; `load_pe()` returns
None when none exists and the caller records the skip reason. The bytes are deterministic
(fixed seed), inert filler or random code, and never executed:

- `edge_no_sections`: a valid PE whose `NumberOfSections` is patched to 0;
- `edge_overlapping_sections`: `.data` patched to start at `.text`'s RVA;
- `edge_entry_outside`: `AddressOfEntryPoint` beyond every section;
- `edge_zero_imports`: no import directory at all;
- `edge_tiny_functions`: 10 000 exported entry points, each 16 bytes of random code ending
  in RET (function caps and per-function costs);
- `edge_random_16mib`: one 16 MiB - 64 KiB `.text` of random bytes (time / memory worst case
  for the robustness side; `bulk_gen` is the realistic latency case, RT21).
"""

import importlib.util
import os
import random
import struct
from pathlib import Path
from types import ModuleType
from typing import Any

SEED = 20261107
TINY_FUNCTIONS = 10_000
RANDOM_TEXT_BYTES = 16 * 1024**2 - 64 * 1024


def _candidates() -> list[Path]:
    paths = []
    if env := os.environ.get("CYBERLAB_M3_SAMPLES"):
        paths.append(Path(env))
    paths.append(Path("/opt/samples/m3"))
    paths.append(Path(__file__).resolve().parents[2] / "static" / "samples")
    return paths


def load_pe() -> ModuleType | None:
    """The M3 PE builder module, loaded by path under a private name."""
    for directory in _candidates():
        path = directory / "pe.py"
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location("cyberlab_m3_samples_pe", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return None


def _headers(data: bytes) -> tuple[int, int, int]:
    """(e_lfanew, number of sections, section table offset)."""
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    n_sections, = struct.unpack_from("<H", data, e_lfanew + 6)
    opt_size, = struct.unpack_from("<H", data, e_lfanew + 20)
    return e_lfanew, n_sections, e_lfanew + 24 + opt_size


def section_rvas(data: bytes) -> list[int]:
    _, count, table = _headers(data)
    return [struct.unpack_from("<I", data, table + 40 * i + 12)[0] for i in range(count)]


def entry_rva(data: bytes) -> int:
    e_lfanew, _, _ = _headers(data)
    return int(struct.unpack_from("<I", data, e_lfanew + 24 + 16)[0])


def build(pe: ModuleType, *, random_text_bytes: int = RANDOM_TEXT_BYTES) -> dict[str, bytes]:
    """Every edge case, deterministic from `SEED` (`random_text_bytes` shrinks the 16 MiB one
    for unit tests)."""
    rng = random.Random(SEED)
    text = pe.Section(".text", b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3".ljust(64, b"\xcc"), pe.TEXT)
    data_section = pe.Section(".data", b"CyberLab RE edge-case data".ljust(64, b"\0"), pe.DATA)
    imports = {"KERNEL32.dll": ["GetTickCount", "ExitProcess"]}
    out: dict[str, bytes] = {}

    image = bytearray(pe.build(pe.PeSpec(bits=64, sections=[text, data_section], imports=imports)))
    e_lfanew, _, _ = _headers(bytes(image))
    struct.pack_into("<H", image, e_lfanew + 6, 0)
    out["edge_no_sections"] = bytes(image)

    image = bytearray(pe.build(pe.PeSpec(bits=64, sections=[text, data_section], imports=imports)))
    _, _, table = _headers(bytes(image))
    text_rva = struct.unpack_from("<I", image, table + 12)[0]
    struct.pack_into("<I", image, table + 40 + 12, text_rva)
    out["edge_overlapping_sections"] = bytes(image)

    out["edge_entry_outside"] = pe.build(
        pe.PeSpec(bits=32, sections=[text, data_section], imports=imports, entry_offset=0x100000)
    )
    out["edge_zero_imports"] = pe.build(pe.PeSpec(bits=64, sections=[text, data_section]))

    chunks = bytearray()
    for _ in range(TINY_FUNCTIONS):
        chunks += rng.randbytes(15) + b"\xc3"
    out["edge_tiny_functions"] = pe.build(
        pe.PeSpec(
            bits=64,
            dll=True,
            dll_name="cyberlab_tiny.dll",
            sections=[pe.Section(".text", bytes(chunks), pe.TEXT)],
            exports=[f"tiny_{i:05d}" for i in range(TINY_FUNCTIONS)],
        )
    )
    out["edge_random_16mib"] = pe.build(
        pe.PeSpec(
            bits=64,
            sections=[pe.Section(".text", rng.randbytes(random_text_bytes), pe.TEXT)],
            imports=imports,
        )
    )
    return out


def labels(samples: dict[str, bytes]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, data in samples.items():
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        machine, = struct.unpack_from("<H", data, e_lfanew + 4)
        out[name] = {
            "kind": "edge_case",
            "format": "pe",
            "arch": "x86_64" if machine == 0x8664 else "x86",
            "stripped": True,
            "truth": None,
            "expect": "clean_end",
            "size_bytes": len(data),
            "expected_findings": [],
            "expected_iocs": [],
        }
    return out
