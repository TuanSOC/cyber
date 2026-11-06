"""Stage `analyze` (tool uid, one JVM): import, bounded auto-analysis, export (M10 phase 2).

    python -I -s -B -m re_worker.probe analyze --sample S --loader pe|elf --project P \\
        --out O --heap N --analysis-timeout T --max-functions N ... --max-string-refs N

Order (RT1): the JVM starts through `launcher.start` (our arguments only), the effective JVM
arguments go to the status, **then** the audit hook is installed, **then** the sample is
opened. The project is created in the root-prepared, tool-owned `--project` dir; the sample
is imported with the root-chosen loader class only (`loader_choice`, options fail closed,
RT20); the frozen analysis options are set and checked by name (`analysis_options`); the
analysis runs under a timeout monitor (a cancelled analysis still exports what exists:
`analysis_status = timeout`); the project is saved (the decompile stage re-opens it); then
the exporters write bounded rows (`probe/out.py`, per-kind caps) in the shapes of
`normalize/records.py`.

Every Ghidra call here is the 12.2 / PyGhidra 3.2 API as documented [I: confirmed by the
engine smoke, `tests/engine/test_ghidra_smoke.py`]. Strings coming out of the program
(names, signatures, string values) are attacker-controlled: NUL-free, surrogate-safe and
length-cut by `out.text`; root re-validates every row.
"""

import argparse
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from cyberlab_jobs.reverse import MAX_BODY_RANGES, MAX_STRING_CHARS, MIN_STRING_CHARS

from re_worker import jvm_args
from re_worker.probe import analysis_options, loader_choice, mapping
from re_worker.probe.guard import GUARD
from re_worker.probe.launcher import start
from re_worker.probe.out import RowWriter, StageFailure, optional_text, text

PROJECT = "cyberlab"
PROGRAM = "sample"
FID_BOOKMARK = ("Analysis", "Function ID Analyzer")
CAP_KINDS = {
    "functions": "function",
    "call_edges": "call_edge",
    "imports": "import",
    "import_refs": "import_ref",
    "strings": "string",
    "string_refs": "string_ref",
}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--loader", choices=sorted(loader_choice.LOADER_CLASSES), required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--heap", type=int, required=True)
    parser.add_argument("--analysis-timeout", type=int, required=True)
    for flag in CAP_KINDS:
        parser.add_argument(f"--max-{flag.replace('_', '-')}", type=int, required=True)


def caps(args: argparse.Namespace) -> dict[str, int]:
    return {kind: int(getattr(args, f"max_{flag}")) for flag, kind in CAP_KINDS.items()}


# --- Ghidra helpers (12.2 API) -------------------------------------------------------------


def _offset(address: Any) -> int:
    return int(address.getUnsignedOffset())


def _loader_class(fmt: str) -> Any:
    from ghidra.app.util.opinion import ElfLoader, PeLoader

    return PeLoader if fmt == "pe" else ElfLoader


def _default_options(loader: Any, sample: Path) -> list[tuple[str, object]]:
    """The chosen loader's default options for this file (RT20)."""
    from ghidra.app.util.bin import FileByteProvider
    from java.io import File
    from java.nio.file import AccessMode

    provider = FileByteProvider(File(str(sample)), None, AccessMode.READ)
    try:
        specs = list(loader.findSupportedLoadSpecs(provider))
        if not specs:
            raise StageFailure("re_parse_failed", "loader_refused")
        spec = next((s for s in specs if s.isPreferred()), specs[0])
        try:  # 11.4+ adds `mirrorFsLayout`
            options = loader.getDefaultOptions(provider, spec, None, False, False)
        except TypeError:
            options = loader.getDefaultOptions(provider, spec, None, False)
        return [(str(o.getName()), _option_value(o.getValue())) for o in options]
    finally:
        provider.close()


def _option_value(value: Any) -> object:
    if value is None:
        return ""
    text_value = str(value)
    if text_value in ("true", "false"):
        return text_value == "true"
    return text_value


def _pairs(args: list[tuple[str, str]]) -> Any:
    from java.util import ArrayList

    try:
        from generic.stl import Pair
    except ImportError:  # pragma: no cover - moved in a newer Ghidra
        from ghidra.util.datastruct import Pair  # type: ignore[no-redef]
    pairs = ArrayList()
    for name, value in args:
        pairs.add(Pair(name, value))
    return pairs


def import_sample(project: Any, sample: Path, fmt: str, status: dict[str, Any]) -> None:
    """Load the sample with the root-chosen loader only, after the option check; save it."""
    import pyghidra
    from ghidra.util.task import TaskMonitor

    loader_cls = _loader_class(fmt)
    options = _default_options(loader_cls(), sample)
    status["loader_options"] = [name[:512] for name, _ in options][:64]
    problems = loader_choice.check_options(fmt, options)
    if problems:
        status["unknown_options"] = [p[:512] for p in problems][:32]
        raise StageFailure("re_parse_failed", "loader_option")
    builder = (
        pyghidra.program_loader()
        .project(project)
        .source(str(sample))
        .name(PROGRAM)
        .loaders(loader_cls.class_)
        .loaderArgs(_pairs(loader_choice.loader_args(options)))
    )
    with builder.load() as results:
        results.save(TaskMonitor.DUMMY)


def set_analysis_options(program: Any, fmt: str, status: dict[str, Any]) -> None:
    import pyghidra

    options = pyghidra.analysis_properties(program)
    names = [str(n) for n in options.getOptionNames()]
    values, missing = analysis_options.plan(fmt, names)
    if missing:
        status["unknown_options"] = [f"missing:{m}"[:512] for m in missing][:32]
        raise StageFailure("re_parse_failed", "unknown_analysis_option")
    with pyghidra.transaction(program):
        for name, value in values.items():
            options.setBoolean(name, value)


def run_analysis(program: Any, timeout_s: int) -> str:
    """`complete`, or `timeout` when the monitor cancelled it (export proceeds either way)."""
    import pyghidra

    monitor = pyghidra.task_monitor(timeout_s)
    try:
        pyghidra.analyze(program, monitor)
    except Exception:
        if monitor.isCancelled():
            return "timeout"
        raise
    return "timeout" if monitor.isCancelled() else "complete"


# --- exporters -----------------------------------------------------------------------------


class Exporter:
    """One pass over the program; every list stops at its cap (the writer's flag)."""

    def __init__(self, program: Any, writer: RowWriter) -> None:
        self.program = program
        self.writer = writer
        self.base = _offset(program.getImageBase())
        self.functions = program.getFunctionManager()
        self.listing = program.getListing()
        self.refs = program.getReferenceManager()
        self.big_endian = bool(program.getLanguage().isBigEndian())
        self.exports: set[int] = set()
        self.external_index: dict[str, int] = {}  # str(external address) -> import index
        self.slot_index: dict[int, int] = {}  # IAT / GOT slot -> import index
        self.thunk_index: dict[int, int] = {}  # thunk entry -> import index
        # Pairs held in memory before writing: a few times the caps, then the kind is cut.
        self.edge_bound = 4 * writer.caps.get("call_edge", 0)
        self.import_ref_bound = 4 * writer.caps.get("import_ref", 0)

    def _count(self, counter: Counter[tuple[int, int]], key: tuple[int, int], kind: str) -> None:
        bound = self.edge_bound if kind == "call_edge" else self.import_ref_bound
        if key not in counter and len(counter) >= bound:
            self.writer.truncated[kind] = True
            return
        counter[key] += 1

    def program_facts(self, analysis_status: str) -> None:
        entry = None
        symbols = self.program.getSymbolTable()
        for address in symbols.getExternalEntryPointIterator():
            offset = _offset(address)
            self.exports.add(offset)
            primary = symbols.getPrimarySymbol(address)
            if entry is None or (primary is not None and str(primary.getName()) == "entry"):
                entry = offset
        language = self.program.getLanguageID().getIdAsString()
        compiler = self.program.getCompilerSpec().getCompilerSpecID().getIdAsString()
        self.writer.emit(
            "program_facts",
            {
                "language_id": optional_text(language, 64),
                "compiler_spec": optional_text(compiler, 32),
                "image_base": self.base,
                "entry": entry,
                "analysis_status": analysis_status,
            },
        )

    def imports(self) -> None:
        manager = self.program.getExternalManager()
        index = 0
        for library in manager.getExternalLibraryNames():
            for location in manager.getExternalLocations(library):
                if self.writer.full("import"):
                    self.writer.truncated["import"] = True
                    return
                label = text(location.getLabel(), 255)
                ordinal = mapping.ordinal_of(label)
                external = location.getExternalSpaceAddress()
                slot = None
                for ref in self.refs.getReferencesTo(external):
                    source = ref.getFromAddress()
                    if not source.isExternalAddress():
                        slot = _offset(source)
                        break
                self.writer.emit(
                    "import",
                    {
                        "index": index,
                        "library": text(library, 128),
                        "name": None if ordinal is not None else (label or None),
                        "ordinal": ordinal,
                        "address": slot,
                    },
                )
                self.external_index[str(external)] = index
                if slot is not None:
                    self.slot_index[slot] = index
                index += 1

    def _thunk_import(self, function: Any) -> int | None:
        if not function.isThunk():
            return None
        target = function.getThunkedFunction(True)
        if target is None or not target.isExternal():
            return None
        return self.external_index.get(str(target.getEntryPoint()))

    def _is_fid(self, entry: Any) -> bool:
        try:
            marks = self.program.getBookmarkManager()
            return marks.getBookmark(entry, *FID_BOOKMARK) is not None
        except Exception:  # noqa: BLE001 - an optional fact
            return False

    def _body(self, function: Any) -> tuple[list[dict[str, int]], bool]:
        ranges: list[dict[str, int]] = []
        for rng in function.getBody().getAddressRanges():
            start = _offset(rng.getMinAddress())
            end = _offset(rng.getMaxAddress()) + 1
            if start < self.base:
                continue
            if len(ranges) == MAX_BODY_RANGES:
                return ranges, True
            ranges.append({"start": start - self.base, "end": end - self.base})
        return ranges, False

    def functions_and_refs(self) -> None:
        edges: Counter[tuple[int, int]] = Counter()
        import_refs: Counter[tuple[int, int]] = Counter()
        for function in self.functions.getFunctions(True):
            if self.writer.full("function"):
                self.writer.truncated["function"] = True
                break
            entry_address = function.getEntryPoint()
            entry = _offset(entry_address)
            if entry < self.base:
                continue
            thunk_import = self._thunk_import(function)
            if thunk_import is not None:
                self.thunk_index[entry] = thunk_import
            body, cut = self._body(function)
            instructions = 0
            for instruction in self.listing.getInstructions(function.getBody(), True):
                instructions += 1
                for ref in instruction.getReferencesFrom():
                    self._reference(entry, ref, edges, import_refs)
            source = str(function.getSymbol().getSource())
            name_source = mapping.name_source(
                source,
                is_export=entry in self.exports,
                imports_external=thunk_import is not None,
                is_fid=self._is_fid(entry_address),
            )
            self.writer.emit(
                "function",
                {
                    "entry": entry,
                    "rva": entry - self.base,
                    "name": text(function.getName(), 255) or f"FUN_{entry:x}",
                    "name_source": str(name_source),
                    "size": int(function.getBody().getNumAddresses()),
                    "body": body,
                    "body_truncated": cut,
                    "is_thunk": bool(function.isThunk()),
                    "is_external": thunk_import is not None,
                    "is_library": name_source == "fid_library",
                    "signature": optional_text(function.getSignature().getPrototypeString(), 512),
                    "calling_convention": optional_text(function.getCallingConventionName(), 32),
                    "instructions": instructions,
                },
            )
        # A call to a thunk of an import is a use of that import by the caller.
        for (caller, callee), sites in edges.items():
            index = self.thunk_index.get(callee)
            if index is not None:
                import_refs[(index, caller)] += sites
        for (caller, callee), sites in sorted(edges.items()):
            row = {"caller": caller, "callee": callee, "sites": sites}
            if not self.writer.emit("call_edge", row):
                break
        for (index, caller), count in sorted(import_refs.items()):
            row = {"import_index": index, "function_entry": caller, "count": count}
            if not self.writer.emit("import_ref", row):
                break

    def _reference(
        self,
        entry: int,
        ref: Any,
        edges: Counter[tuple[int, int]],
        import_refs: Counter[tuple[int, int]],
    ) -> None:
        target = ref.getToAddress()
        if target.isExternalAddress():
            index = self.external_index.get(str(target))
            if index is not None:
                self._count(import_refs, (index, entry), "import_ref")
            return
        offset = _offset(target)
        if offset in self.slot_index:  # a read of / call through an IAT or GOT slot
            self._count(import_refs, (self.slot_index[offset], entry), "import_ref")
            return
        if ref.getReferenceType().isCall():
            callee = self.functions.getFunctionAt(target)
            if callee is not None and not callee.isExternal():
                self._count(edges, (entry, _offset(callee.getEntryPoint())), "call_edge")

    def strings(self) -> None:
        index = 0
        for data in self.listing.getDefinedData(True):
            if self.writer.full("string"):
                self.writer.truncated["string"] = True
                return
            if not data.hasStringValue():
                continue
            raw = data.getValue()
            if raw is None:
                continue
            value = text(raw, 1 << 20)
            if len(value) < MIN_STRING_CHARS:
                continue
            address = _offset(data.getAddress())
            encoding = mapping.string_encoding(
                str(data.getDataType().getName()), value, big_endian=self.big_endian
            )
            self.writer.emit(
                "string",
                {
                    "index": index,
                    "address": address,
                    "encoding": encoding,
                    "value": value[:MAX_STRING_CHARS],
                    "length": len(value),
                },
            )
            referrers: Counter[int] = Counter()
            for ref in self.refs.getReferencesTo(data.getAddress()):
                function = self.functions.getFunctionContaining(ref.getFromAddress())
                if function is not None:
                    referrers[_offset(function.getEntryPoint())] += 1
            for function_entry, count in sorted(referrers.items()):
                row = {"string_index": index, "function_entry": function_entry, "count": count}
                self.writer.emit("string_ref", row)
            index += 1


# --- the stage -----------------------------------------------------------------------------


def run(args: argparse.Namespace, writer: RowWriter, status: dict[str, Any]) -> None:
    out = PurePosixPath(str(args.out))
    status["jvm_args"] = start(jvm_args.stage_args(args.heap, out))
    status["jvm_started"] = True
    GUARD.install()  # RT1: after the JVM is up, before the sample is opened

    import pyghidra

    with pyghidra.open_project(str(args.project), PROJECT, create=True) as project:
        import_sample(project, args.sample, args.loader, status)
        program, consumer = pyghidra.consume_program(project, f"/{PROGRAM}")
        try:
            set_analysis_options(program, args.loader, status)
            status["analysis_status"] = run_analysis(program, args.analysis_timeout)
            from ghidra.util.task import TaskMonitor

            program.save("cyberlab analysis", TaskMonitor.DUMMY)
            exporter = Exporter(program, writer)
            exporter.program_facts(status["analysis_status"])
            exporter.imports()
            exporter.functions_and_refs()
            exporter.strings()
        finally:
            program.release(consumer)


__all__ = ["PROGRAM", "PROJECT", "Exporter", "add_arguments", "caps", "run"]
