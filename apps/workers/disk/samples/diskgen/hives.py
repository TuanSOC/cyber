"""Registry hives without third-party data: our own minimal base hive (a regf header with its
checksum, one hbin, a root `nk` cell, one `sk` cell and a free cell), then, when hivex is
installed, `hivexregedit --merge` of our own `.reg` text into it (a Run key, a service whose
ImagePath is in Temp, a UserAssist entry). hivex's own test hives are never used.

Every key timestamp hivex writes is reset afterwards (`normalize`), so a merged hive is
deterministic; if hivex is missing or fails the base hive is used as is and the registry events
stay replay-only (recorded in the ground truth as `hive_outcome`).
"""

import struct
import tempfile
from pathlib import Path

from samples.diskgen import BASE_TIME, tools

HBIN = 4096
ROOT_CELL = 0x20
CHECKSUM_AT = 0x1FC
KEY_FLAGS = 0x04 | 0x08 | 0x20  # hive entry (root), no delete, compressed (ASCII) name
EPOCH_DELTA = 11_644_473_600


def filetime(epoch: int) -> int:
    return (epoch + EPOCH_DELTA) * 10_000_000


def checksum(header: bytes | bytearray) -> int:
    value = 0
    for (dword,) in struct.iter_unpack("<I", bytes(header[:CHECKSUM_AT])):
        value ^= dword
    if value == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return value or 1


def _sid(authority: int, *subs: int) -> bytes:
    return (
        bytes([1, len(subs)])
        + authority.to_bytes(6, "big")
        + b"".join(struct.pack("<I", s) for s in subs)
    )


def security_descriptor() -> bytes:
    """Self-relative: owner Administrators, group SYSTEM, one ACE (Everyone: KEY_ALL_ACCESS)."""
    owner, group, everyone = _sid(5, 32, 544), _sid(5, 18), _sid(1, 0)
    ace = struct.pack("<BBHI", 0, 0x02, 8 + len(everyone), 0x000F003F) + everyone
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
    off_owner = 20
    off_group = off_owner + len(owner)
    off_dacl = off_group + len(group)
    head = struct.pack("<BBHIIII", 1, 0, 0x8004, off_owner, off_group, 0, off_dacl)
    return head + owner + group + acl


def _cell(body: bytes) -> bytes:
    size = (4 + len(body) + 7) // 8 * 8
    return struct.pack("<i", -size) + body.ljust(size - 4, b"\x00")


def base_hive(root_name: str, when: int = BASE_TIME) -> bytes:
    sd = security_descriptor()
    name = root_name.encode("ascii")
    nk_size = (4 + 76 + len(name) + 7) // 8 * 8
    sk_offset = ROOT_CELL + nk_size
    nk = (
        b"nk"
        + struct.pack("<HQII", KEY_FLAGS, filetime(when), 0, 0)
        + struct.pack("<IIIIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF)
        + struct.pack("<II", sk_offset, 0xFFFFFFFF)
        + struct.pack("<IIIII", 0, 0, 0, 0, 0)
        + struct.pack("<HH", len(name), 0)
        + name
    )
    sk = b"sk" + struct.pack("<HIIII", 0, sk_offset, sk_offset, 1, len(sd)) + sd
    cells = _cell(nk) + _cell(sk)
    free = HBIN - 0x20 - len(cells)
    hbin = (
        b"hbin"
        + struct.pack("<IIQQI", 0, HBIN, 0, filetime(when), 0)
        + cells
        + struct.pack("<i", free)
        + bytes(free - 4)
    )
    header = bytearray(HBIN)
    header[0:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", header, 4, 1, 1, filetime(when), 1, 3, 0, 1, ROOT_CELL, HBIN, 1)
    file_name = f"\\??\\C:\\{root_name}".encode("utf-16-le")[:64]
    header[48 : 48 + len(file_name)] = file_name
    struct.pack_into("<I", header, CHECKSUM_AT, checksum(header))
    return bytes(header) + hbin


def cells(hive: bytes) -> list[tuple[int, int]]:
    """(absolute offset, size) of every cell of every hbin; raises on a malformed bin."""
    out: list[tuple[int, int]] = []
    off = HBIN
    while off < len(hive):
        if hive[off : off + 4] != b"hbin":
            raise ValueError(f"no hbin at {off:#x}")
        size = struct.unpack_from("<I", hive, off + 8)[0]
        cell = off + 0x20
        while cell < off + size:
            (raw,) = struct.unpack_from("<i", hive, cell)
            if raw == 0:
                raise ValueError(f"zero-size cell at {cell:#x}")
            out.append((cell, raw))
            cell += abs(raw)
        if cell != off + size:
            raise ValueError(f"cells overrun the hbin at {off:#x}")
        off += size
    return out


def normalize(hive: bytes, when: int) -> bytes:
    """Reset the header, hbin and every `nk` timestamp to `when` and re-checksum."""
    out = bytearray(hive)
    ft = filetime(when)
    struct.pack_into("<Q", out, 12, ft)
    struct.pack_into("<II", out, 4, 1, 1)  # sequence numbers equal: a clean hive
    off = HBIN
    while off < len(out):
        struct.pack_into("<Q", out, off + 0x14, ft)
        off += struct.unpack_from("<I", out, off + 8)[0]
    for cell, size in cells(bytes(out)):
        if size < 0 and out[cell + 4 : cell + 6] == b"nk":
            struct.pack_into("<Q", out, cell + 8, ft)
    struct.pack_into("<I", out, CHECKSUM_AT, checksum(out))
    return bytes(out)


# --- .reg inputs (our own) -------------------------------------------------------------------

TOOL = r"C:\Users\alice\AppData\Local\Temp\tool.exe"


def _reg_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _hex(data: bytes) -> str:
    return "hex:" + ",".join(f"{b:02x}" for b in data)


def rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def userassist_data(runs: int, last: int) -> bytes:
    """Windows 7+ UserAssist value data (72 bytes): run count at 4, last run FILETIME at 60."""
    data = bytearray(72)
    struct.pack_into("<IIII", data, 0, 0, runs, runs, 0)
    struct.pack_into("<I", data, 56, 0xFFFFFFFF)
    struct.pack_into("<Q", data, 60, filetime(last))
    return bytes(data)


def reg_text(hive: str) -> tuple[str, str] | None:
    """(prefix, .reg text) of the merge for one hive name, or None for an empty hive."""
    head = "Windows Registry Editor Version 5.00\n\n"
    if hive == "SOFTWARE":
        prefix = r"HKEY_LOCAL_MACHINE\SOFTWARE"
        body = (
            f'[{prefix}\\Microsoft\\Windows\\CurrentVersion\\Run]\n"Updater"={_reg_str(TOOL)}\n\n'
        )
    elif hive == "SYSTEM":
        prefix = r"HKEY_LOCAL_MACHINE\SYSTEM"
        body = (
            f"[{prefix}\\Select]\n"
            '"Current"=dword:00000001\n"Default"=dword:00000001\n\n'
            f"[{prefix}\\ControlSet001\\Control\\ComputerName\\ComputerName]\n"
            '"ComputerName"="WS-ALICE"\n\n'
            f"[{prefix}\\ControlSet001\\Services\\CyberLabUpdater]\n"
            f'"ImagePath"={_reg_str(TOOL)}\n'
            '"Start"=dword:00000002\n"Type"=dword:00000010\n\n'
        )
    elif hive == "NTUSER.DAT":
        prefix = r"HKEY_CURRENT_USER"
        guid = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
        explorer = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
        body = (
            f"[{prefix}\\{explorer}\\UserAssist\\{guid}\\Count]\n"
            f"{_reg_str(rot13(TOOL))}={_hex(userassist_data(3, BASE_TIME + 205))}\n\n"
            f"[{prefix}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"
            f'"Sync"={_reg_str(TOOL)}\n\n'
        )
    else:
        return None
    return prefix, head + body


def build(hive: str, when: int) -> tuple[bytes, str]:
    """(hive bytes, outcome): `merged` (hivex), `base` (no merge needed), or `base_no_hivex`."""
    base = base_hive(hive.split(".")[0], when)
    spec = reg_text(hive)
    if spec is None:
        return base, "base"
    if not tools.have("hivexregedit"):
        return base, "base_no_hivex"
    prefix, text = spec
    with tempfile.TemporaryDirectory(prefix="diskgen-hive-") as tmp:
        path = Path(tmp) / "hive"
        reg = Path(tmp) / "input.reg"
        path.write_bytes(base)
        reg.write_text(text, encoding="utf-8")
        try:
            tools.run(["hivexregedit", "--merge", "--prefix", prefix, str(path), str(reg)])
        except tools.ToolFailed:
            return base, "base_hivex_failed"
        return normalize(path.read_bytes(), when), "merged"
