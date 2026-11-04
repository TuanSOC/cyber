"""Pure-Python ELF64 (x86-64, little endian) builder for synthetic, never-executed samples.

Program headers (PT_INTERP, two PT_LOADs, PT_DYNAMIC, PT_GNU_STACK), a dynamic section with
DT_NEEDED entries, dynamic symbols (undefined imports + defined exports) and an optional
static symbol table. The code bytes are inert filler.
"""

import struct
from dataclasses import dataclass, field

BASE = 0x400000
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_DYNSYM = 1, 2, 3, 6, 11
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK = 1, 2, 3, 0x6474E551
PF_X, PF_W, PF_R = 1, 2, 4
DT_NULL, DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0, 1, 5, 6, 10, 11
ET_EXEC, ET_DYN = 2, 3


@dataclass
class ElfSpec:
    elf_type: int = ET_EXEC
    interpreter: str | None = "/lib64/ld-linux-x86-64.so.2"
    needed: list[str] = field(default_factory=lambda: ["libc.so.6"])
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    text: bytes = b"\x31\xc0\xc3"
    rodata: bytes = b""
    data: bytes = b""
    local_symbols: list[str] = field(default_factory=list)  # empty = stripped


class _Strtab:
    def __init__(self) -> None:
        self.data = bytearray(b"\0")

    def add(self, name: str) -> int:
        offset = len(self.data)
        self.data += name.encode() + b"\0"
        return offset


def _align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


def build(spec: ElfSpec) -> bytes:
    dynstr = _Strtab()
    needed = [dynstr.add(lib) for lib in spec.needed]
    shstr = _Strtab()

    names = [
        ".interp", ".dynsym", ".dynstr", ".text", ".rodata", ".data", ".dynamic",
        *([".symtab", ".strtab"] if spec.local_symbols else []), ".shstrtab",
    ]  # fmt: skip
    if spec.interpreter is None:
        names.remove(".interp")
    index = {name: i + 1 for i, name in enumerate(names)}

    n_phdr = 4 + (spec.interpreter is not None)
    offset = 64 + 56 * n_phdr
    placed: dict[str, tuple[int, bytes]] = {}

    def place(name: str, data: bytes, alignment: int) -> int:
        nonlocal offset
        offset = _align(offset, alignment)
        placed[name] = (offset, data)
        start = offset
        offset += len(data)
        return start

    if spec.interpreter is not None:
        place(".interp", spec.interpreter.encode() + b"\0", 1)
    # .dynsym needs .text's address for exports: lay out sizes first.
    n_dynsym = 1 + len(spec.imports) + len(spec.exports)
    dynsym_off = _align(offset, 8)
    sym_names = [dynstr.add(n) for n in [*spec.imports, *spec.exports]]
    dynstr_off = dynsym_off + 24 * n_dynsym
    text_off = _align(dynstr_off + len(dynstr.data), 16)
    text_addr = BASE + text_off

    dynsym = bytearray(24)
    for i, name_off in enumerate(sym_names):
        is_export = i >= len(spec.imports)
        shndx = index[".text"] if is_export else 0
        value = text_addr + 0x10 * (i - len(spec.imports)) if is_export else 0
        dynsym += struct.pack("<IBBHQQ", name_off, 0x12, 0, shndx, value, 0x10 if is_export else 0)
    place(".dynsym", bytes(dynsym), 8)
    place(".dynstr", bytes(dynstr.data), 1)
    place(".text", spec.text, 16)
    place(".rodata", spec.rodata, 8)
    place(".data", spec.data, 8)
    dynsym_addr = BASE + placed[".dynsym"][0]
    dynstr_addr = BASE + placed[".dynstr"][0]
    dyn = b"".join(struct.pack("<qQ", DT_NEEDED, n) for n in needed)
    dyn += struct.pack(
        "<qQqQqQqQqQ", DT_STRTAB, dynstr_addr, DT_SYMTAB, dynsym_addr,
        DT_STRSZ, len(dynstr.data), DT_SYMENT, 24, DT_NULL, 0,
    )  # fmt: skip
    place(".dynamic", dyn, 8)
    if spec.local_symbols:
        strtab = _Strtab()
        symtab = bytearray(24)
        for i, name in enumerate(spec.local_symbols):
            symtab += struct.pack(
                "<IBBHQQ", strtab.add(name), 0x12, 0, index[".text"], text_addr + 0x10 * i, 0x10
            )
        place(".symtab", bytes(symtab), 8)
        place(".strtab", bytes(strtab.data), 1)
    sh_names = {name: shstr.add(name) for name in names}
    place(".shstrtab", bytes(shstr.data), 1)
    shoff = _align(offset, 8)
    sh_count = len(names) + 1

    def shdr(name: str) -> bytes:
        off, data = placed[name]
        kinds = {
            ".interp": (SHT_PROGBITS, SHF_ALLOC, 0, 0, 1, 0),
            ".dynsym": (SHT_DYNSYM, SHF_ALLOC, index[".dynstr"], 1, 8, 24),
            ".dynstr": (SHT_STRTAB, SHF_ALLOC, 0, 0, 1, 0),
            ".text": (SHT_PROGBITS, SHF_ALLOC | SHF_EXEC, 0, 0, 16, 0),
            ".rodata": (SHT_PROGBITS, SHF_ALLOC, 0, 0, 8, 0),
            ".data": (SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 8, 0),
            ".dynamic": (SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, index[".dynstr"], 0, 8, 16),
            ".symtab": (SHT_SYMTAB, 0, index.get(".strtab", 0), 1, 8, 24),
            ".strtab": (SHT_STRTAB, 0, 0, 0, 1, 0),
            ".shstrtab": (SHT_STRTAB, 0, 0, 0, 1, 0),
        }
        kind, flags, link, info, alignment, entsize = kinds[name]
        addr = BASE + off if flags & SHF_ALLOC else 0
        return struct.pack(
            "<IIQQQQIIQQ", sh_names[name], kind, flags, addr, off, len(data), link, info,
            alignment, entsize,
        )  # fmt: skip

    rx_end = placed[".rodata"][0] + len(placed[".rodata"][1])
    rw_start = placed[".data"][0]
    rw_end = placed[".dynamic"][0] + len(placed[".dynamic"][1])
    phdrs = bytearray()
    if spec.interpreter is not None:
        off, data = placed[".interp"]
        phdrs += struct.pack("<IIQQQQQQ", PT_INTERP, PF_R, off, BASE + off, BASE + off,
                             len(data), len(data), 1)  # fmt: skip
    phdrs += struct.pack("<IIQQQQQQ", PT_LOAD, PF_R | PF_X, 0, BASE, BASE, rx_end, rx_end, 0x1000)
    phdrs += struct.pack(
        "<IIQQQQQQ", PT_LOAD, PF_R | PF_W, rw_start, BASE + rw_start, BASE + rw_start,
        rw_end - rw_start, rw_end - rw_start, 0x1000,
    )  # fmt: skip
    off, data = placed[".dynamic"]
    phdrs += struct.pack("<IIQQQQQQ", PT_DYNAMIC, PF_R | PF_W, off, BASE + off, BASE + off,
                         len(data), len(data), 8)  # fmt: skip
    phdrs += struct.pack("<IIQQQQQQ", PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0, 16)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", spec.elf_type, 62, 1, text_addr, 64, shoff, 0, 64, 56, n_phdr, 64,
        sh_count, index[".shstrtab"],
    )  # fmt: skip
    out = bytearray(header + phdrs)
    for name in names:
        off, data = placed[name]
        out += bytes(off - len(out)) + data
    out += bytes(shoff - len(out)) + bytes(64)
    for name in names:
        out += shdr(name)
    return bytes(out)
