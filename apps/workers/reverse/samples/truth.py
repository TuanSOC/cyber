"""Ground truth of one unstripped build (M10 phase 4): what the stripped twin really contains.

Inputs, all produced in the dev image by `generate.py` from the same build:
- the C source's `re:` annotation blocks (`fn=`, `calls=`, `indirect=`, `string=`, `import=`,
  `finding=`), parsed by `parse_annotations`;
- `nm --defined-only --numeric-sort [--print-size]` of the unstripped binary: the text symbols
  with their addresses (and sizes on ELF; PE / COFF symbols have none, so a PE function's size
  is the distance to the next text symbol);
- the linker map (`-Wl,-Map`): the `.text*` input sections with their address ranges and the
  object or archive member they come from. A function is *library* code (CRT, libgcc, ...)
  when its address lies in an input section that is not the sample's own object;
- `objdump -d --no-show-raw-insn -w`: direct `call` / `jmp` targets per function.

Call edges come from the annotations and are kept only when objdump shows the call (or the
tail-call `jmp`) from the caller to the callee's first byte in this build: at -O2 an inlined
helper's edges disappear, and the truth follows the build, not the source. Observed calls
between two annotated functions that the source does not annotate are reported separately
(an annotation error at -O0). String and import references come from the annotations; each
is marked `verified` when the build shows it (the literal's bytes are in the file; the
import's `__imp_` / `@plt` symbol appears in the function's disassembly; i386 PE
`call *abs` lines carry no symbol, so those stay unverified, never dropped). A function that
-O2 inlined away hands its strings, imports and expected findings to the functions it was
inlined into (`inlined_from`).

Addresses: `rva = address - preferred_base` (PE `ImageBase`; ELF lowest `PT_LOAD` vaddr,
page-aligned), the same convention as `ReFunctionRecord.rva` (RT8).
"""

import bisect
import re
import struct
from dataclasses import asdict, dataclass, field
from typing import Any

ANNOTATION_KEYS = frozenset({"fn", "calls", "indirect", "string", "import", "finding"})
TEXT_TYPES = frozenset("TtWw")
COMMENT_RE = re.compile(r"/\*(.*?)\*/", re.S)
LINE_RE = re.compile(r"^\s*\*?\s*re:\s*([a-z]+)=(.*?)\s*$")
NM_RE = re.compile(r"^([0-9a-fA-F]+)\s+(?:([0-9a-fA-F]+)\s+)?([A-Za-z])\s+(\S+)$")
MAP_SECTION_RE = re.compile(r"^ (\.\S+)(?:\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S.*))?$")
MAP_CONTINUATION_RE = re.compile(r"^\s{10,}0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S.*)$")
OBJDUMP_HEADER_RE = re.compile(r"^([0-9a-fA-F]+) <([^>]+)>:\s*$")
OBJDUMP_BRANCH_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:bnd\s+|notrack\s+)?(call|jmp)[lqw]?\s+([0-9a-fA-F]+) <([^>]+)>"
)
OBJDUMP_SYMBOL_RE = re.compile(r"<([^>]+)>")
# Compiler-made parts of one source function (`foo.cold`, `foo.part.0`, ...).
SUFFIX_RE = re.compile(r"\.(?:cold|part|isra|constprop|lto_priv)(?:\.\d+)*$")
DECORATION_RE = re.compile(r"@\d+$")


class TruthError(ValueError):
    """An annotation or tool output that cannot be turned into truth."""


# --- annotations ------------------------------------------------------------------------------


@dataclass
class Annotation:
    name: str
    calls: list[str] = field(default_factory=list)
    indirect: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    # `method|type|severity` of a phase-5 finding expected in this function.
    findings: list[dict[str, str]] = field(default_factory=list)


def _names(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def parse_annotations(source: str) -> dict[str, Annotation]:
    """Every `re:` block of a C source, by function name (a block starts with `fn=`)."""
    out: dict[str, Annotation] = {}
    for comment in COMMENT_RE.finditer(source):
        current: Annotation | None = None
        for raw in comment.group(1).splitlines():
            match = LINE_RE.match(raw)
            if match is None:
                continue
            key, value = match.groups()
            if key not in ANNOTATION_KEYS:
                raise TruthError(f"unknown annotation key {key!r}")
            if key == "fn":
                name = value.split()[0] if value.split() else ""
                if not name or name in out:
                    raise TruthError(f"bad or duplicate fn annotation {value!r}")
                current = out[name] = Annotation(name)
                continue
            if current is None:
                raise TruthError(f"annotation {key!r} before fn=")
            if key == "calls":
                current.calls += _names(value)
            elif key == "indirect":
                current.indirect += _names(value)
            elif key == "string":
                if not value:
                    raise TruthError("empty string annotation")
                current.strings.append(value)
            elif key == "import":
                current.imports += _names(value)
            else:
                method, kind, severity = (part.strip() for part in value.split("|"))
                current.findings.append({"method": method, "type": kind, "severity": severity})
    for ann in out.values():
        for callee in [*ann.calls, *ann.indirect]:
            if callee not in out:
                raise TruthError(f"{ann.name} calls unannotated {callee}")
    return out


# --- tool outputs -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int | None


def parse_nm(text: str) -> list[Symbol]:
    """Text symbols of `nm --defined-only --numeric-sort [--print-size]`, by address."""
    symbols = []
    for line in text.splitlines():
        match = NM_RE.match(line.strip())
        if match is None:
            continue
        address, size, kind, name = match.groups()
        if kind not in TEXT_TYPES or name.startswith("."):
            continue
        symbols.append(Symbol(name, int(address, 16), int(size, 16) if size else None))
    return sorted(symbols, key=lambda s: (s.address, s.name))


@dataclass(frozen=True)
class InputSection:
    start: int
    end: int
    origin: str  # the object file or `archive.a(member.o)`


def parse_map(text: str) -> list[InputSection]:
    """The `.text*` input sections of a GNU ld map (after "Linker script and memory map")."""
    marker = text.find("Linker script and memory map")
    lines = text[marker:].splitlines() if marker >= 0 else []
    sections: list[InputSection] = []
    pending: str | None = None  # a section name whose numbers wrapped to the next line
    for line in lines:
        head = MAP_SECTION_RE.match(line)
        if head is not None:
            name, start, size, origin = head.groups()
            if start is None:
                pending = name
                continue
            pending = None
            if name.startswith(".text") and int(size, 16) > 0:
                sections.append(InputSection(int(start, 16), int(start, 16) + int(size, 16),
                                             origin.strip()))  # fmt: skip
            continue
        tail = MAP_CONTINUATION_RE.match(line)
        if tail is not None and pending is not None:
            start, size, origin = tail.groups()
            if pending.startswith(".text") and int(size, 16) > 0:
                sections.append(InputSection(int(start, 16), int(start, 16) + int(size, 16),
                                             origin.strip()))  # fmt: skip
        pending = None
    return sorted(sections, key=lambda s: s.start)


@dataclass
class Disassembly:
    start: int
    branches: list[tuple[str, int, str]] = field(default_factory=list)  # (call|jmp, target, sym)
    symbols: set[str] = field(default_factory=set)  # every <symbol> the function mentions


def parse_objdump(text: str) -> dict[str, Disassembly]:
    """Per symbol block: direct branch targets (`<name>` without an offset) and symbols."""
    blocks: dict[str, Disassembly] = {}
    current: Disassembly | None = None
    for line in text.splitlines():
        header = OBJDUMP_HEADER_RE.match(line)
        if header is not None:
            current = blocks.setdefault(header.group(2), Disassembly(int(header.group(1), 16)))
            continue
        if current is None:
            continue
        branch = OBJDUMP_BRANCH_RE.match(line)
        if branch is not None and "+" not in branch.group(4):
            current.branches.append((branch.group(2), int(branch.group(3), 16), branch.group(4)))
        current.symbols.update(OBJDUMP_SYMBOL_RE.findall(line))
    return blocks


def preferred_base(data: bytes) -> int:
    """PE `ImageBase`; ELF lowest `PT_LOAD` p_vaddr, page-aligned (RT8)."""
    if data[:2] == b"MZ":
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        if magic == 0x20B:
            return int(struct.unpack_from("<Q", data, e_lfanew + 24 + 24)[0])
        return int(struct.unpack_from("<I", data, e_lfanew + 24 + 28)[0])
    if data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1:
        phoff, = struct.unpack_from("<Q", data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
        loads = []
        for i in range(phnum):
            p_type, = struct.unpack_from("<I", data, phoff + i * phentsize)
            if p_type == 1:
                loads.append(struct.unpack_from("<Q", data, phoff + i * phentsize + 16)[0])
        if loads:
            return int(min(loads)) & ~0xFFF
        return 0
    raise TruthError("neither a PE nor a little-endian ELF64")


# --- truth ------------------------------------------------------------------------------------


@dataclass
class Function:
    name: str
    rva: int
    size: int
    library: bool
    origin: str


@dataclass
class Truth:
    preferred_base: int
    functions: list[Function]
    edges: list[dict[str, str]]  # {"caller", "callee", "via": "call" | "jmp"}
    edges_unconfirmed: list[dict[str, str]]  # annotated, not in this build (inlined, ...)
    edges_unannotated: list[dict[str, str]]  # observed between annotated functions only
    string_refs: list[dict[str, Any]]  # {"value", "function", "verified"}
    import_refs: list[dict[str, Any]]  # {"name", "function", "verified"}
    findings: list[dict[str, str]]  # {"method", "type", "severity", "function"}
    missing: list[str]  # annotated functions absent from this build (inlined away)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def by_name(self) -> dict[str, Function]:
        return {f.name: f for f in self.functions}


def canonical(symbol: str, known: frozenset[str] | set[str]) -> str:
    """A symbol as its source name: `foo.cold` -> `foo`; i386 `_foo` / `_foo@8` -> `foo`."""
    name = SUFFIX_RE.sub("", symbol)
    name = DECORATION_RE.sub("", name)
    if name not in known and name.startswith("_") and name[1:] in known:
        name = name[1:]
    return name


def import_symbol(symbol: str) -> str:
    """`__imp_CreateFileW`, `__imp__CreateFileW@28`, `socket@plt` -> the import name."""
    name = symbol.split("@plt")[0]
    for prefix in ("__imp__", "__imp_", "_imp__"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return DECORATION_RE.sub("", name)


def _origin(sections: list[InputSection], starts: list[int], address: int) -> str | None:
    i = bisect.bisect_right(starts, address) - 1
    if i >= 0 and sections[i].start <= address < sections[i].end:
        return sections[i].origin
    return None


def _contains(data: bytes, value: str) -> bool:
    return value.encode("utf-8") in data or value.encode("utf-16-le") in data


def build_truth(
    *,
    source: str,
    own_object: str,
    nm_text: str,
    map_text: str,
    objdump_text: str,
    binary: bytes,
) -> Truth:
    annotations = parse_annotations(source)
    known = set(annotations)
    base = preferred_base(binary)
    symbols = parse_nm(nm_text)
    sections = parse_map(map_text)
    starts = [s.start for s in sections]
    blocks = parse_objdump(objdump_text)

    functions: dict[str, Function] = {}
    start_of: dict[int, str] = {}
    for i, sym in enumerate(symbols):
        name = canonical(sym.name, known)
        if name in functions:  # a `.cold` part or an alias: the first symbol is the entry
            continue
        size = sym.size
        if size is None:
            following = next((s.address for s in symbols[i + 1 :] if s.address > sym.address), None)
            size = following - sym.address if following is not None else 0
        origin = _origin(sections, starts, sym.address)
        library = origin is None or origin.rsplit("/", 1)[-1] != own_object
        functions[name] = Function(name, sym.address - base, size, library, origin or "unknown")
        start_of.setdefault(sym.address, name)

    observed: set[tuple[str, str, str]] = set()
    mentioned: dict[str, set[str]] = {}
    for symbol, block in blocks.items():
        caller = canonical(symbol, known)
        mentioned.setdefault(caller, set()).update(import_symbol(s) for s in block.symbols)
        for kind, target, _ in block.branches:
            callee = start_of.get(target)
            if callee is None or (kind == "jmp" and callee == caller):
                continue  # not a function entry, or a loop back to the own entry
            observed.add((caller, callee, kind))

    edges, unconfirmed, unannotated = [], [], []
    observed_pairs: dict[tuple[str, str], str] = {}
    for caller, callee, kind in sorted(observed):
        if observed_pairs.get((caller, callee)) != "call":  # a real call wins over a tail jmp
            observed_pairs[(caller, callee)] = kind
    for ann in annotations.values():
        for callee in ann.calls:
            via = observed_pairs.get((ann.name, callee))
            if via is not None and ann.name in functions and callee in functions:
                edges.append({"caller": ann.name, "callee": callee, "via": via})
            else:
                unconfirmed.append({"caller": ann.name, "callee": callee})
    for (caller, callee), via in sorted(observed_pairs.items()):
        if caller in known and callee in known and callee not in annotations[caller].calls:
            unannotated.append({"caller": caller, "callee": callee, "via": via})

    def owners(name: str, seen: frozenset[str] = frozenset()) -> list[str]:
        """The function itself, or (inlined away) the present functions it was inlined into."""
        if name in functions:
            return [name]
        found: list[str] = []
        for ann in annotations.values():
            if name in ann.calls and ann.name not in seen:
                found += [o for o in owners(ann.name, seen | {name}) if o not in found]
        return sorted(found)

    string_refs, import_refs, findings = [], [], []
    for ann in annotations.values():
        for owner in owners(ann.name):
            moved = {} if owner == ann.name else {"inlined_from": ann.name}
            string_refs += [
                {"value": v, "function": owner, "verified": _contains(binary, v), **moved}
                for v in ann.strings
            ]
            seen = mentioned.get(owner, set())
            import_refs += [
                {"name": i, "function": owner, "verified": i in seen, **moved} for i in ann.imports
            ]
            findings += [{**f, "function": owner, **moved} for f in ann.findings]
    return Truth(
        preferred_base=base,
        functions=sorted(functions.values(), key=lambda f: (f.rva, f.name)),
        edges=sorted(edges, key=lambda e: (e["caller"], e["callee"])),
        edges_unconfirmed=sorted(unconfirmed, key=lambda e: (e["caller"], e["callee"])),
        edges_unannotated=unannotated,
        string_refs=string_refs,
        import_refs=import_refs,
        findings=findings,
        missing=sorted(known - set(functions)),
    )
