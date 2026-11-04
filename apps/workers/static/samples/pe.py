"""Pure-Python PE32 / PE32+ builder for synthetic, never-executed test samples.

Produces structurally valid images (headers, section table, import / export / resource /
TLS directories, optional Rich header, Authenticode-shaped certificate table, overlay) that
pefile, YARA's pe module, capa and FLOSS parse like real files. The code bytes are inert
filler: nothing here is meant to run, and nothing ever is.
"""

import struct
from dataclasses import dataclass, field

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000

SCN_CODE = 0x00000020
SCN_IDATA = 0x00000040
SCN_UDATA = 0x00000080
SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000
TEXT = SCN_CODE | SCN_EXECUTE | SCN_READ
RDATA = SCN_IDATA | SCN_READ
DATA = SCN_IDATA | SCN_READ | SCN_WRITE

RT_ICON, RT_RCDATA, RT_VERSION, RT_MANIFEST = 3, 10, 16, 24

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_SECURITY, DIR_TLS, DIR_IAT = 0, 1, 2, 4, 9, 12


def align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


@dataclass
class Section:
    name: str
    data: bytes
    characteristics: int
    virtual_size: int | None = None  # defaults to len(data)


@dataclass
class Resource:
    type_id: int
    name_id: int
    data: bytes
    lang: int = 0x0409


@dataclass
class PeSpec:
    bits: int = 32
    dll: bool = False
    gui: bool = False
    timestamp: int = 0x5F5E1000  # 2020-09-13
    sections: list[Section] = field(default_factory=list)
    imports: dict[str, list[str | int]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    dll_name: str = "sample.dll"
    resources: list[Resource] = field(default_factory=list)
    tls_callbacks: int = 0
    overlay: bytes = b""
    certificate: bytes | None = None  # WIN_CERTIFICATE body (presence test only)
    rich: list[tuple[int, int, int]] | None = None  # (product id, build, count)
    entry_section: str | None = None  # defaults to the first executable section
    entry_offset: int = 0


def _rich_header(entries: list[tuple[int, int, int]], key: int) -> bytes:
    words = [0x536E6144 ^ key, key, key, key]  # "DanS" + three padding dwords
    for product, build, count in entries:
        words += [((product << 16) | build) ^ key, count ^ key]
    return struct.pack(f"<{len(words)}I", *words) + b"Rich" + struct.pack("<I", key)


def _imports(spec: PeSpec, rva: int) -> tuple[bytes, int, int, int, int]:
    """Import directory + ILTs + IATs + hint/name table. Returns (blob, idt rva/size, iat)."""
    ptr = spec.bits // 8
    ordinal_flag = 1 << (spec.bits - 1)
    dlls = list(spec.imports.items())
    idt_size = 20 * (len(dlls) + 1)
    thunks = sum(len(funcs) + 1 for _, funcs in dlls) * ptr
    ilt_off = idt_size
    iat_off = ilt_off + thunks
    names_off = iat_off + thunks
    names = bytearray()
    name_rvas: list[list[int]] = []
    dll_name_rvas: list[int] = []
    for _dll, funcs in dlls:
        rvas = []
        for func in funcs:
            if isinstance(func, int):
                rvas.append(ordinal_flag | func)
                continue
            if len(names) % 2:
                names += b"\0"
            rvas.append(rva + names_off + len(names))
            names += struct.pack("<H", 0) + func.encode() + b"\0"
        name_rvas.append(rvas)
    for dll, _ in dlls:
        dll_name_rvas.append(rva + names_off + len(names))
        names += dll.encode() + b"\0"
    idt = bytearray()
    table = bytearray()
    cursor = 0
    for i, rvas in enumerate(name_rvas):
        idt += struct.pack(
            "<IIIII", rva + ilt_off + cursor, 0, 0, dll_name_rvas[i], rva + iat_off + cursor
        )
        fmt = "<Q" if ptr == 8 else "<I"
        for value in [*rvas, 0]:
            table += struct.pack(fmt, value)
        cursor += (len(rvas) + 1) * ptr
    idt += bytes(20)
    blob = bytes(idt) + bytes(table) + bytes(table) + bytes(names)
    return blob, rva, idt_size, rva + iat_off, thunks


def _exports(spec: PeSpec, rva: int, code_rva: int) -> bytes:
    names = sorted(spec.exports)
    n = len(names)
    eat_off = 40
    npt_off = eat_off + 4 * n
    ot_off = npt_off + 4 * n
    str_off = ot_off + 2 * n
    strings = bytearray(spec.dll_name.encode() + b"\0")
    name_rvas = []
    for name in names:
        name_rvas.append(rva + str_off + len(strings))
        strings += name.encode() + b"\0"
    header = struct.pack(
        "<IIHHIIIIIII",
        0, spec.timestamp, 0, 0, rva + str_off, 1, n, n,
        rva + eat_off, rva + npt_off, rva + ot_off,
    )  # fmt: skip
    eat = b"".join(struct.pack("<I", code_rva + 0x10 * i) for i in range(n))
    npt = b"".join(struct.pack("<I", r) for r in name_rvas)
    ot = b"".join(struct.pack("<H", i) for i in range(n))
    return header + eat + npt + ot + bytes(strings)


def _resources(spec: PeSpec, rva: int) -> bytes:
    """Three-level ID-only resource tree: type -> name -> language -> data entry."""
    by_type: dict[int, dict[int, list[Resource]]] = {}
    for res in spec.resources:
        by_type.setdefault(res.type_id, {}).setdefault(res.name_id, []).append(res)

    def directory(count: int) -> bytes:
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, count)

    # Sizes first: every directory is 16 bytes + 8 per entry, data entries 16 bytes.
    root_size = 16 + 8 * len(by_type)
    type_sizes = {t: 16 + 8 * len(names) for t, names in by_type.items()}
    name_dirs = [(t, n) for t, names in by_type.items() for n in names]
    name_sizes = {(t, n): 16 + 8 * len(by_type[t][n]) for t, n in name_dirs}
    leaves = [r for t, names in by_type.items() for n in names for r in names[n]]

    offset = root_size
    type_offsets = {}
    for t in by_type:
        type_offsets[t] = offset
        offset += type_sizes[t]
    name_offsets = {}
    for key in name_dirs:
        name_offsets[key] = offset
        offset += name_sizes[key]
    entry_offsets = {}
    for i, _ in enumerate(leaves):
        entry_offsets[i] = offset
        offset += 16
    data_offsets = {}
    for i, leaf in enumerate(leaves):
        offset = align(offset, 8)
        data_offsets[i] = offset
        offset += len(leaf.data)

    out = bytearray(directory(len(by_type)))
    for t in by_type:
        out += struct.pack("<II", t, 0x80000000 | type_offsets[t])
    leaf_index = 0
    leaf_ids: dict[tuple[int, int], list[int]] = {}
    for t, names in by_type.items():
        for n in names:
            for _ in names[n]:
                leaf_ids.setdefault((t, n), []).append(leaf_index)
                leaf_index += 1
    for t, names in by_type.items():
        out += directory(len(names))
        for n in names:
            out += struct.pack("<II", n, 0x80000000 | name_offsets[(t, n)])
    for t, n in name_dirs:
        out += directory(len(by_type[t][n]))
        for leaf_id, res in zip(leaf_ids[(t, n)], by_type[t][n], strict=True):
            out += struct.pack("<II", res.lang, entry_offsets[leaf_id])
    for i, leaf in enumerate(leaves):
        out += struct.pack("<IIII", rva + data_offsets[i], len(leaf.data), 0, 0)
    for i, leaf in enumerate(leaves):
        out += bytes(data_offsets[i] - len(out)) + leaf.data
    return bytes(out)


def build(spec: PeSpec) -> bytes:
    pe64 = spec.bits == 64
    ptr = 8 if pe64 else 4
    image_base = 0x140000000 if pe64 else 0x400000
    if spec.dll:
        image_base = 0x180000000 if pe64 else 0x10000000

    sections = list(spec.sections)
    code = next((s for s in sections if s.characteristics & SCN_EXECUTE), None)
    if code is None:
        raise ValueError("a PE needs one executable section")
    extra: list[tuple[str, int]] = []  # (generated section name, data directory index)
    if spec.imports:
        extra.append((".idata", DIR_IMPORT))
    if spec.exports:
        extra.append((".edata", DIR_EXPORT))
    if spec.tls_callbacks:
        extra.append((".tls", DIR_TLS))
    if spec.resources:
        extra.append((".rsrc", DIR_RESOURCE))

    opt_size = 240 if pe64 else 224
    rich = _rich_header(spec.rich, 0x1F2E3D4C) if spec.rich else b""
    stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    stub += b"This program cannot be run in DOS mode.\r\r\n$"
    stub = stub.ljust(align(len(stub), 8), b"\0")
    e_lfanew = 0x40 + len(stub) + len(rich)
    e_lfanew = align(e_lfanew, 8)
    n_sections = len(sections) + len(extra)
    headers_size = align(e_lfanew + 4 + 20 + opt_size + 40 * n_sections, FILE_ALIGN)

    # Place user sections, then the generated ones (sizes do not depend on their RVA).
    layout: list[tuple[str, int, int, bytes, int]] = []  # name, rva, vsize, data, flags
    rva = SECTION_ALIGN
    rvas: dict[str, int] = {}
    for s in sections:
        rvas[s.name] = rva
        vsize = s.virtual_size if s.virtual_size is not None else len(s.data)
        layout.append((s.name, rva, vsize, s.data, s.characteristics))
        rva += align(max(vsize, 1), SECTION_ALIGN)
    code_rva = rvas[code.name]

    directories = [(0, 0)] * 16
    for name, index in extra:
        if index == DIR_IMPORT:
            blob, idt, idt_size, iat, iat_size = _imports(spec, rva)
            directories[DIR_IMPORT] = (idt, idt_size)
            directories[DIR_IAT] = (iat, iat_size)
            flags = RDATA | SCN_WRITE
        elif index == DIR_EXPORT:
            blob = _exports(spec, rva, code_rva)
            directories[DIR_EXPORT] = (rva, len(blob))
            flags = RDATA
        elif index == DIR_TLS:
            n = spec.tls_callbacks
            dir_size = 40 if pe64 else 24
            callbacks_rva = rva + dir_size
            index_rva = callbacks_rva + ptr * (n + 1)
            va = image_base
            fmt = "<QQQQII" if pe64 else "<IIIIII"
            tls_dir = struct.pack(
                fmt, va + index_rva + 8, va + index_rva + 16, va + index_rva,
                va + callbacks_rva, 0, 0,
            )  # fmt: skip
            pfmt = "<Q" if pe64 else "<I"
            cbs = b"".join(struct.pack(pfmt, va + code_rva + 0x20 * (i + 1)) for i in range(n))
            blob = tls_dir + cbs + bytes(ptr) + bytes(24)
            directories[DIR_TLS] = (rva, dir_size)
            flags = DATA
        else:
            blob = _resources(spec, rva)
            directories[DIR_RESOURCE] = (rva, len(blob))
            flags = RDATA
        rvas[name] = rva
        layout.append((name, rva, len(blob), blob, flags))
        rva += align(max(len(blob), 1), SECTION_ALIGN)
    size_of_image = rva

    entry_name = spec.entry_section or code.name
    entry = rvas[entry_name] + spec.entry_offset

    body = bytearray()
    table = bytearray()
    raw_ptr = headers_size
    size_code = size_idata = size_udata = 0
    for name, srva, vsize, data, flags in layout:
        raw_size = align(len(data), FILE_ALIGN) if data else 0
        table += struct.pack(
            "<8sIIIIIIHHI",
            name.encode()[:8], vsize, srva, raw_size, raw_ptr if raw_size else 0,
            0, 0, 0, 0, flags,
        )  # fmt: skip
        body += data.ljust(raw_size, b"\0")
        raw_ptr += raw_size
        if flags & SCN_CODE:
            size_code += raw_size
        elif flags & SCN_UDATA:
            size_udata += vsize
        else:
            size_idata += raw_size

    tail = bytearray(spec.overlay)
    if spec.certificate is not None:
        cert = struct.pack("<IHH", 8 + len(spec.certificate), 0x0200, 0x0002) + spec.certificate
        cert = cert.ljust(align(len(cert), 8), b"\0")
        cert_offset = raw_ptr + len(tail)
        cert_offset_aligned = align(cert_offset, 8)
        tail += bytes(cert_offset_aligned - cert_offset) + cert
        directories[DIR_SECURITY] = (cert_offset_aligned, len(cert))

    characteristics = 0x0002  # executable image
    characteristics |= 0x0020 if pe64 else 0x0100  # large address aware / 32-bit machine
    if spec.dll:
        characteristics |= 0x2000
    coff = struct.pack(
        "<HHIIIHH", 0x8664 if pe64 else 0x014C, n_sections, spec.timestamp, 0, 0, opt_size,
        characteristics,
    )  # fmt: skip
    subsystem = 2 if spec.gui else 3
    dll_chars = 0x8160 if pe64 else 0x8140
    base_of_code = code_rva
    if pe64:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 14, 30, size_code, size_idata, size_udata, entry, base_of_code, image_base,
            SECTION_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, size_of_image, headers_size, 0,
            subsystem, dll_chars, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )  # fmt: skip
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 14, 30, size_code, size_idata, size_udata, entry, base_of_code, 0,
            image_base, SECTION_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, size_of_image,
            headers_size, 0, subsystem, dll_chars, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )  # fmt: skip
    opt += b"".join(struct.pack("<II", *d) for d in directories)
    assert len(opt) == opt_size, len(opt)

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<HHHHHHHHH", dos, 2, 0x90, 3, 0, 4, 0, 0xFFFF, 0, 0xB8, 0)
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    head = bytes(dos) + stub + rich
    head = head.ljust(e_lfanew, b"\0") + b"PE\0\0" + coff + opt + bytes(table)
    return head.ljust(headers_size, b"\0") + bytes(body) + bytes(tail)
