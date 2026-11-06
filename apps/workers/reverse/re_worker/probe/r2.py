"""The radare2 reducer (tool uid; M10 phase 3, RT9): `r2.out` -> stage rows.

    python -I -s -B -m re_worker.probe r2 --input <out>/r2.out --out <out> --max-functions N ...

radare2 ran once, non-interactively, with the fixed script `/opt/re/r2/quick.r2` (no r2pipe,
no command built from binary-derived data); its stdout is `r2.out` (bounded by RLIMIT_FSIZE).
Root never parses it: this probe does, as the tool uid, with the audit hook installed first
(it starts no JVM), and writes the same row shapes as the Ghidra `analyze` stage
(`normalize/records.py`), so root's validation, caps and `ReView` are shared.

Splitting: the script echoes `===CYBERLAB:<section>===` before each JSON command (`ij`, `aflj`,
`iij`, `izj`) and `===CYBERLAB:end===` last. A marker counts only on a line of its own, in the
expected order, once (radare2 escapes newlines inside JSON strings, so binary-derived text
cannot forge a marker line; a repeated or out-of-order marker is ignored and recorded). Each
section is held up to `MAX_SECTION_BYTES` (`RE_R2_MAX_JSON_BYTES`, 64 MiB); a larger one is
refused before parsing. A missing, oversize or unparsable section is an empty result plus an
engine error `radare_<section>_failed`; no `end` marker means the output was cut
(`truncated.r2_output`).

Mapping (radare2 6.2.6 JSON [I: field names confirmed by `tests/engine/test_r2_smoke.py`;
both the 6.x `addr` and the 5.x `offset` spellings are read]):
- `ij` -> `program_facts` (`bin.baddr` is the image base; the entry is `entry0`'s address);
- `aflj` -> functions (body = `[minaddr, maxaddr)` when sane, else `[addr, addr + size)`);
  `callrefs` of type CALL -> call edges and import refs; `datarefs` -> string refs (and import
  refs when they hit an import slot); `sym.imp.*` functions are import thunks;
- `iij` -> imports (`plt` is the thunk / IAT address; `Ordinal_<n>` names are ordinals);
- `izj` -> strings (`vaddr`, `string`, `type`, `length`).
"""

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Any, BinaryIO

from cyberlab_jobs.reverse import MAX_STRING_CHARS, MIN_STRING_CHARS, NameSource, StringEncoding

from re_worker.normalize.reader import loads
from re_worker.probe.guard import GUARD
from re_worker.probe.mapping import ordinal_of
from re_worker.probe.out import RowWriter, StageFailure, optional_text, text

SECTIONS = ("info", "functions", "imports", "strings")
MARKER = re.compile(rb"^===CYBERLAB:([a-z]{1,16})===\r?\n?$")
MAX_SECTION_BYTES = 64 * 1024**2  # RE_R2_MAX_JSON_BYTES
MAX_INPUT_BYTES = 256 * 1024**2  # = radare2's RLIMIT_FSIZE
MAX_BODY_BYTES = 16 * 1024**2  # a [minaddr, maxaddr) span above this is not believed
U64 = 2**64
CAP_KINDS = {
    "functions": "function",
    "call_edges": "call_edge",
    "imports": "import",
    "import_refs": "import_ref",
    "strings": "string",
    "string_refs": "string_ref",
}
ENCODINGS: dict[str, StringEncoding] = {
    "ascii": "ascii",
    "utf8": "utf8",
    "utf16le": "utf16le",
    "wide": "utf16le",
    "utf16be": "utf16be",
    "wide_be": "utf16be",
    "utf32le": "utf32",
    "utf32be": "utf32",
}
GENERATED_PREFIXES = ("fcn.", "sub.", "loc.", "case.", "int.", "unk.")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    for flag in CAP_KINDS:
        parser.add_argument(f"--max-{flag.replace('_', '-')}", type=int, required=True)


def caps(args: argparse.Namespace) -> dict[str, int]:
    return {kind: int(getattr(args, f"max_{flag}")) for flag, kind in CAP_KINDS.items()}


# --- splitting ---------------------------------------------------------------------------


class Sections:
    def __init__(self) -> None:
        self.raw: dict[str, bytes] = {}
        self.errors: list[str] = []
        self.ended = False
        self.input_cut = False

    def error(self, code: str) -> None:
        if code not in self.errors:
            self.errors.append(code)


def split(f: BinaryIO, max_section: int = MAX_SECTION_BYTES) -> Sections:
    """Bounded split of `r2.out` at the marker lines (never more than one section held)."""
    found = Sections()
    order = [*SECTIONS, "end"]
    expected = 0
    current: str | None = None
    buf = bytearray()
    over = False
    total = 0

    def close() -> None:
        if current is None:
            return
        if over:
            found.error(f"radare_{current}_too_large")
        else:
            found.raw[current] = bytes(buf)

    while True:
        line = f.readline(max_section + 2)
        if not line:
            break
        total += len(line)
        if total > MAX_INPUT_BYTES:
            found.input_cut = True
            break
        match = MARKER.match(line)
        if match is not None:
            name = match.group(1).decode()
            if expected < len(order) and name == order[expected]:
                close()
                expected += 1
                if name == "end":
                    found.ended = True
                    current = None
                    break
                current, buf, over = name, bytearray(), False
                continue
            found.error("radare_marker_unexpected")
            continue
        if current is None or over:
            continue
        if len(buf) + len(line) > max_section:
            over = True
            buf = bytearray()
            continue
        buf += line
    if not found.ended:
        close()
    return found


def parse(raw: bytes | None) -> Any:
    """The section's JSON value: the first line that starts like JSON and parses strictly
    (radare2 may print a warning line before it)."""
    if raw is None:
        return None
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped.startswith((b"{", b"[")):
            continue
        try:
            return loads(stripped)
        except (ValueError, RecursionError):
            return None
    return None


# --- values ------------------------------------------------------------------------------


def _int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value < U64 else None


def _addr(item: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        if key in item:
            return _int(item[key])
    return None


def name_source(name: str, kind: object) -> NameSource:
    if name.startswith("sym.imp.") or kind == "imp":
        return NameSource.IMPORT
    if name == "entry0" or name.startswith("entry."):
        return NameSource.EXPORT
    if name.startswith("dbg."):
        return NameSource.DEBUG
    if name.startswith(GENERATED_PREFIXES):
        return NameSource.GENERATED
    return NameSource.SYMBOL


def import_key(name: str, library: str = "") -> str:
    """`sym.imp.KERNEL32.dll_VirtualAlloc` / `imp.puts` / `VirtualAlloc` -> a lookup key."""
    for prefix in ("sym.imp.", "imp."):
        if name.startswith(prefix):
            name = name[len(prefix) :]
    if library and name.lower().startswith(library.lower() + "_"):
        name = name[len(library) + 1 :]
    return name.lower()


def _refs(value: object) -> list[tuple[int, str]]:
    """(target, type) pairs of a `callrefs` / `datarefs` list (ints or objects)."""
    out: list[tuple[int, str]] = []
    if not isinstance(value, list):
        return out
    for ref in value[:100_000]:
        if isinstance(ref, dict):
            target = _addr(ref, "addr", "offset")
            kind = str(ref.get("type", ""))[:16].upper()
        else:
            target, kind = _int(ref), "DATA"
        if target is not None:
            out.append((target, kind))
    return out


# --- reduction ---------------------------------------------------------------------------


class Reducer:
    def __init__(self, writer: RowWriter, status: dict[str, Any]) -> None:
        self.writer = writer
        self.status = status
        self.errors: list[str] = []
        self.base = 0
        self.import_by_slot: dict[int, int] = {}
        self.import_by_key: dict[str, int] = {}
        self.libraries: set[str] = set()
        self.string_by_addr: dict[int, int] = {}

    def error(self, code: str) -> None:
        if code not in self.errors:
            self.errors.append(code)

    def info(self, value: Any, functions: Any) -> None:
        core = value.get("bin") if isinstance(value, dict) else None
        if not isinstance(core, dict):
            self.error("radare_info_failed")
            core = {}
        self.base = _int(core.get("baddr")) or 0
        entry = None
        if isinstance(functions, list):
            for fn in functions:
                if isinstance(fn, dict) and fn.get("name") == "entry0":
                    entry = _addr(fn, "addr", "offset")
                    break
        self.writer.emit(
            "program_facts",
            {
                "language_id": None,
                "compiler_spec": None,
                "image_base": self.base,
                "entry": entry,
                "analysis_status": "complete",
            },
        )

    def imports(self, value: Any) -> None:
        if not isinstance(value, list):
            self.error("radare_imports_failed")
            return
        index = 0
        for item in value:
            if not isinstance(item, dict):
                continue
            if self.writer.full("import"):
                self.writer.truncated["import"] = True
                return
            name = text(item.get("name") or "", 255)
            library = text(item.get("libname") or item.get("lib") or "", 128)
            ordinal = ordinal_of(name)
            if not name and ordinal is None:
                continue
            slot = _int(item.get("plt")) or None
            self.writer.emit(
                "import",
                {
                    "index": index,
                    "library": library,
                    "name": None if ordinal is not None else name,
                    "ordinal": ordinal,
                    "address": slot,
                },
            )
            if slot is not None:
                self.import_by_slot[slot] = index
            self.import_by_key.setdefault(import_key(name, library), index)
            if library:
                self.libraries.add(library)
            index += 1

    def _thunk_import(self, name: str) -> int | None:
        if not name.startswith("sym.imp."):
            return None
        key = import_key(name)
        if key in self.import_by_key:
            return self.import_by_key[key]
        for library in self.libraries:
            found = self.import_by_key.get(import_key(name, library))
            if found is not None:
                return found
        return None

    def strings(self, value: Any) -> None:
        if not isinstance(value, list):
            self.error("radare_strings_failed")
            return
        index = 0
        for item in value:
            if not isinstance(item, dict):
                continue
            if self.writer.full("string"):
                self.writer.truncated["string"] = True
                return
            address = _addr(item, "vaddr", "addr")
            raw = item.get("string")
            if address is None or not isinstance(raw, str):
                continue
            value_text = text(raw, 1 << 20)
            if len(value_text) < MIN_STRING_CHARS:
                continue
            length = _int(item.get("length"))
            self.writer.emit(
                "string",
                {
                    "index": index,
                    "address": address,
                    "encoding": ENCODINGS.get(str(item.get("type", "")).lower(), "ascii"),
                    "value": value_text[:MAX_STRING_CHARS],
                    "length": length if length is not None else len(value_text),
                },
            )
            self.string_by_addr.setdefault(address, index)
            index += 1

    def _body(self, fn: dict[str, Any], entry: int, size: int) -> list[dict[str, int]]:
        low = _addr(fn, "minaddr", "minbound")
        high = _addr(fn, "maxaddr", "maxbound")
        if low is not None and high is not None and low <= entry < high:
            if high - low <= MAX_BODY_BYTES and low >= self.base:
                return [{"start": low - self.base, "end": high - self.base}]
        if size > 0 and entry >= self.base:
            return [{"start": entry - self.base, "end": entry - self.base + size}]
        return []

    def functions(self, value: Any) -> None:
        if not isinstance(value, list):
            self.error("radare_functions_failed")
            return
        entries: set[int] = set()
        thunks: dict[int, int] = {}
        pending: list[tuple[int, dict[str, Any]]] = []
        for fn in value:
            if not isinstance(fn, dict):
                continue
            if self.writer.full("function"):
                self.writer.truncated["function"] = True
                break
            entry = _addr(fn, "addr", "offset")
            if entry is None or entry in entries or entry < self.base:
                continue
            name = text(fn.get("name") or f"fcn.{entry:08x}", 255)
            size = _int(fn.get("size")) or 0
            source = name_source(name, fn.get("type"))
            thunk = self._thunk_import(name)
            is_import = source == NameSource.IMPORT
            if thunk is not None:
                thunks[entry] = thunk
            self.writer.emit(
                "function",
                {
                    "entry": entry,
                    "rva": entry - self.base,
                    "name": name,
                    "name_source": str(source),
                    "size": size,
                    "body": self._body(fn, entry, size),
                    "body_truncated": False,
                    "is_thunk": is_import,
                    "is_external": is_import,
                    "is_library": False,
                    "signature": optional_text(fn.get("signature"), 512),
                    "calling_convention": optional_text(fn.get("calltype"), 32),
                    "instructions": _int(fn.get("ninstrs")) or 0,
                },
            )
            entries.add(entry)
            pending.append((entry, fn))
        self._references(pending, entries, thunks)

    def _references(
        self, pending: list[tuple[int, dict[str, Any]]], entries: set[int], thunks: dict[int, int]
    ) -> None:
        edges: Counter[tuple[int, int]] = Counter()
        import_refs: Counter[tuple[int, int]] = Counter()
        string_refs: Counter[tuple[int, int]] = Counter()
        for entry, fn in pending:
            for target, kind in _refs(fn.get("callrefs")):
                if target in self.import_by_slot:
                    import_refs[(self.import_by_slot[target], entry)] += 1
                elif kind in ("CALL", "C") and target in entries:
                    edges[(entry, target)] += 1
                    if target in thunks:
                        import_refs[(thunks[target], entry)] += 1
            for target, _kind in _refs(fn.get("datarefs")):
                if target in self.string_by_addr:
                    string_refs[(self.string_by_addr[target], entry)] += 1
                elif target in self.import_by_slot:
                    import_refs[(self.import_by_slot[target], entry)] += 1
        for (caller, callee), sites in sorted(edges.items()):
            row = {"caller": caller, "callee": callee, "sites": sites}
            if not self.writer.emit("call_edge", row):
                break
        for (index, entry), count in sorted(import_refs.items()):
            if not self.writer.emit(
                "import_ref", {"import_index": index, "function_entry": entry, "count": count}
            ):
                break
        for (index, entry), count in sorted(string_refs.items()):
            if not self.writer.emit(
                "string_ref", {"string_index": index, "function_entry": entry, "count": count}
            ):
                break


def reduce(sections: Sections, writer: RowWriter, status: dict[str, Any]) -> None:
    reducer = Reducer(writer, status)
    values = {name: parse(sections.raw.get(name)) for name in SECTIONS}
    for name in SECTIONS:
        if values[name] is None and f"radare_{name}_too_large" not in sections.errors:
            reducer.error(f"radare_{name}_failed")
    reducer.info(values["info"], values["functions"])
    reducer.imports(values["imports"])  # before functions: thunks and slots resolve to them
    reducer.strings(values["strings"])  # before functions: data refs resolve to them
    reducer.functions(values["functions"])
    truncated = dict(writer.truncated)
    if not sections.ended or sections.input_cut:
        truncated["r2_output"] = True
    status["truncated"] = truncated
    status["engine_errors"] = (sections.errors + reducer.errors)[:32]


def run(args: argparse.Namespace, writer: RowWriter, status: dict[str, Any]) -> None:
    GUARD.install()  # no JVM here: the hook goes in before the output is opened
    try:
        f = open(args.input, "rb")  # noqa: SIM115 - closed below
    except OSError as exc:
        raise StageFailure("re_parse_failed", "no_r2_output") from exc
    with f:
        sections = split(f)
    reduce(sections, writer, status)


__all__ = [
    "MARKER",
    "MAX_SECTION_BYTES",
    "SECTIONS",
    "Sections",
    "add_arguments",
    "caps",
    "import_key",
    "name_source",
    "parse",
    "reduce",
    "run",
    "split",
]
