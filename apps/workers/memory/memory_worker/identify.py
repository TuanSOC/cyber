"""What the identify probe reports and how root turns it into an OS and a kernel identity
(M8 phase 2; pure Python, shared by the probe's early scan stop and root).

The probe stacks the image's format layers (and the Windows page-table stacker, which needs
no symbols), then scans the top physical layer once for both kernel signatures: the RSDS
record of a kernel PDB (`ntkrnlmp.pdb`, ...: name, GUID, age) and a `Linux version x.y.z`
banner. It reports the layer chain and the first hit of each; root decides here:

- a layer outside `ACCEPTED_LAYERS` (QEMU, Xen, ...) -> `unsupported_memory_format`;
- `os_hint` restricts the candidates; with `auto`, Windows wins when the Windows page-table
  layer stacked or no banner was found, otherwise Linux;
- no candidate -> `os_undetermined`; a PDB outside the kernel allow-list or a banner that is
  not a valid `LinuxBanner` -> `os_undetermined` with the reason (never a diagnostic stream
  with an invalid requirement).
"""

import re
from dataclasses import dataclass
from typing import Annotated, Literal

from cyberlab_jobs.memory import LinuxBanner, MemoryOs, OsHint, WindowsPdb
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

# Format layers Volatility may stack under the kernel layer, plus the page-table layers.
FORMAT_LAYERS = frozenset(
    {
        "FileLayer",
        "LimeLayer",
        "AVMLLayer",
        "Elf64Layer",
        "VmwareLayer",
        "WindowsCrashDump32Layer",
        "WindowsCrashDump64Layer",
    }
)
INTEL_LAYERS = {
    "WindowsIntel": "x86",
    "WindowsIntelPAE": "x86",
    "WindowsIntel32e": "x64",
    "WindowsMixedIntel32e": "x64",
    "Intel": "x86",
    "IntelPAE": "x86",
    "Intel32e": "x64",
    "LinuxIntel": "x86",
    "LinuxIntelPAE": "x86",
    "LinuxIntel32e": "x64",
}
ACCEPTED_LAYERS = FORMAT_LAYERS | frozenset(INTEL_LAYERS)
WINDOWS_PAGE_LAYERS = frozenset(n for n in INTEL_LAYERS if n.startswith("Windows"))
# Stackers the identify probe runs: the format stackers (QEMU included, so root can refuse
# it by name) and the Windows page-table stacker. The Linux stackers need symbols.
IDENTIFY_STACKERS = frozenset(
    {
        "AVMLStacker",
        "Elf64Stacker",
        "LimeStacker",
        "QemuStacker",
        "VmwareStacker",
        "WindowsCrashDumpStacker",
        "WindowsIntelStacker",
    }
)
LAYER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_LAYERS = 8
X86_BANNER = re.compile(r"\b(?:i[3-6]86|x86_32)\b")
LayerName = Annotated[StrictStr, Field(pattern=LAYER_NAME.pattern)]
RefusalCode = Literal["unsupported_memory_format", "os_undetermined"]


class _Loose(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class PdbHit(_Loose):
    name: Annotated[StrictStr, Field(max_length=64)]
    guid: Annotated[StrictStr, Field(max_length=64)]
    age: StrictInt


class IdentifyRecord(_Loose):
    """The probe's `identify` object (status.json), validated by root (values untrusted)."""

    layers: Annotated[list[LayerName], Field(min_length=1, max_length=MAX_LAYERS)]
    pdb: PdbHit | None = None
    banner: Annotated[StrictStr, Field(max_length=4096)] | None = None


class IdentifyRefused(Exception):
    def __init__(self, code: RefusalCode, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class Identified:
    os: MemoryOs
    identity: WindowsPdb | LinuxBanner
    layer: str  # the chain without FileLayer, e.g. "WindowsCrashDump64Layer>WindowsIntel32e"
    arch: Literal["x86", "x64"]


def windows_layer_stacked(layers: list[str]) -> bool:
    return any(name in WINDOWS_PAGE_LAYERS for name in layers)


def stop_scan(hint: OsHint, layers: list[str], pdb: bool, banner: bool) -> bool:
    """The probe's early stop: True once the scan can no longer change `choose()`."""
    if hint == OsHint.WINDOWS:
        return pdb
    if hint == OsHint.LINUX:
        return banner
    # auto: with the Windows page-table layer a PDB hit decides, otherwise a banner does.
    return pdb if windows_layer_stacked(layers) else banner


def layer_chain(layers: list[str]) -> str:
    """Bottom-to-top chain without the plain file layer (`raw` when nothing else stacked)."""
    chain = [name for name in layers if name != "FileLayer"]
    return ">".join(chain or ["raw"])[:64]


def arch_of(layers: list[str], os: MemoryOs, banner: str | None) -> Literal["x86", "x64"]:
    for name in reversed(layers):
        if name in INTEL_LAYERS:
            return "x86" if INTEL_LAYERS[name] == "x86" else "x64"
    if os == "linux" and banner and X86_BANNER.search(banner):
        return "x86"
    return "x64"


def choose(record: IdentifyRecord, hint: OsHint) -> Identified:
    unknown = [name for name in record.layers if name not in ACCEPTED_LAYERS]
    if unknown:
        raise IdentifyRefused("unsupported_memory_format", f"layer {unknown[0]} is not accepted")
    windows = record.pdb is not None and hint in (OsHint.AUTO, OsHint.WINDOWS)
    linux = record.banner is not None and hint in (OsHint.AUTO, OsHint.LINUX)
    if windows and linux:
        windows = windows_layer_stacked(record.layers)
        linux = not windows
    if windows:
        assert record.pdb is not None  # noqa: S101 - checked above
        try:
            identity: WindowsPdb | LinuxBanner = WindowsPdb(
                name=record.pdb.name, guid=record.pdb.guid.upper(), age=record.pdb.age
            )
        except ValidationError as exc:
            raise IdentifyRefused("os_undetermined", "invalid kernel PDB identity") from exc
        os: MemoryOs = "windows"
    elif linux:
        try:
            identity = LinuxBanner(banner=record.banner or "")
        except ValidationError as exc:
            raise IdentifyRefused("os_undetermined", "invalid Linux banner") from exc
        os = "linux"
    else:
        raise IdentifyRefused("os_undetermined", "no kernel signature for the allowed OS")
    banner = identity.banner if isinstance(identity, LinuxBanner) else None
    return Identified(
        os=os,
        identity=identity,
        layer=layer_chain(record.layers),
        arch=arch_of(record.layers, os, banner),
    )


__all__ = [
    "ACCEPTED_LAYERS",
    "IDENTIFY_STACKERS",
    "Identified",
    "IdentifyRecord",
    "IdentifyRefused",
    "PdbHit",
    "arch_of",
    "choose",
    "layer_chain",
    "stop_scan",
]
