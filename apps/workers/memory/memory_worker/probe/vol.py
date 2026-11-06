"""Library-mode adapter over volatility3 2.28.2 (tool uid only; the one module that imports
Volatility, so API drift is contained here; risk "Library-mode API drift").

Verified against the 2.28.2 sources (phase-2 notes in the phase file):
- `cli/__init__.py` only sets `constants.OFFLINE` for `--offline`; `layers/resources.py`'s
  `OfflineHandler` refuses http(s) when it is set (and the TLS failure path would otherwise
  retry WITHOUT verification). `configure()` sets `OFFLINE = True`, `REMOTE_ISF_URL = None`
  and `PARALLELISM = Off` before any automagic runs.
- `volatility3.symbols.__path__` IS `constants.SYMBOL_BASEPATHS` (the same list): the store
  first, then the two read-only built-in dirs (bundled netscan / PE / bash / generic tables);
  the writable `<CACHE_PATH>/symbols` fallback is dropped, so `pdbutil.download_pdb_isf`
  finds no writable path (RT2). Plugin paths are the two built-in dirs only.
- `plugins.construct_plugin(ctx, automagics, plugin, "plugins", None, open_method)` sets the
  open method; ours raises on construction (RT20).
- `TreeGrid.populate(visitor, None, fail_on_errors=True)` re-raises the visitor's exception,
  which is how the row cap stops the grid.
- Identify: `pdbutil.PdbSignatureScanner(kernel names)` yields `(GUID, age, name, offset)`;
  the banner regex is the one of `plugins/banners.py`; `LayerStacker.stack_layer(ctx, name,
  stackers)` returns the stacked layer names, highest first.
"""

import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import volatility3
import volatility3.plugins
import volatility3.symbols
from cyberlab_jobs.memory import KERNEL_PDB_NAMES, OsHint
from volatility3 import framework
from volatility3.framework import automagic, constants, contexts, exceptions, interfaces, renderers
from volatility3.framework import plugins as vol_plugins
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, physical
from volatility3.framework.symbols.windows import pdbutil

from memory_worker.identify import IDENTIFY_STACKERS, stop_scan
from memory_worker.probe.encode import CapReached, RowWriter, VolTypes
from memory_worker.probe.guard import GUARD
from memory_worker.probe.plugins import PluginSpec
from memory_worker.symbols.store import normalize_banner

BANNER = re.compile(rb"Linux version [0-9]+\.[0-9]+\.[0-9]+")
MAX_ISF = 8
BASE_CONFIG = "plugins"


class ProbeSetupError(Exception):
    """The offline / path setup could not be asserted: the probe refuses to run."""


def builtin_symbol_dirs() -> list[str]:
    """The two read-only built-in symbol dirs (`volatility3/symbols`, `.../framework/symbols`)."""
    base = Path(volatility3.__file__).resolve().parent
    return [str(base / "symbols"), str(base / "framework" / "symbols")]


def configure(symbols_dir: Path) -> dict[str, Any]:
    """Offline, symbol and plugin paths; asserted, then reported in status.json."""
    constants.OFFLINE = True
    constants.REMOTE_ISF_URL = None
    constants.PARALLELISM = constants.Parallelism.Off
    builtin = builtin_symbol_dirs()
    defaults = [str(Path(p).resolve()) for p in constants.SYMBOL_BASEPATHS[:2]]
    if defaults != builtin:
        raise ProbeSetupError("unexpected built-in symbol dirs")
    paths = [str(symbols_dir), *builtin]
    # One list object for both names, as Volatility itself has it.
    constants.SYMBOL_BASEPATHS = paths
    volatility3.symbols.__path__ = paths
    volatility3.plugins.__path__ = list(constants.PLUGINS_PATH)
    facts = facts_now()
    if (
        facts["symbol_paths"] != paths
        or facts["offline"] is not True
        or facts["remote_isf_url"] is not None
        or len(facts["plugin_paths"]) != 2
    ):
        raise ProbeSetupError("offline / path assertion failed")
    return facts


def facts_now() -> dict[str, Any]:
    return {
        "offline": constants.OFFLINE,
        "remote_isf_url": constants.REMOTE_ISF_URL,
        "symbol_paths": list(volatility3.symbols.__path__),
        "plugin_paths": list(volatility3.plugins.__path__),
    }


def location(image: Path) -> str:
    return str(requirements.URIRequirement.location_from_file(str(image)))


# --- value types for the encoder -----------------------------------------------------------


def _read_layer(value: Any, n: int) -> bytes:
    layer = value.context.layers[value.layer_name]
    return bytes(layer.read(value.offset, min(int(value.length), n), True))


def _disassemble(value: Any, n: int) -> str:
    import capstone  # imported (and loaded) before the audit hook by `prepare_imports`

    modes = {
        "intel": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "intel64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    }
    if value.architecture not in modes:
        return ""
    engine = capstone.Cs(*modes[value.architecture])
    data = bytes(value.data[:n])
    lines = [
        f"{i.address:#x}: {i.mnemonic} {i.op_str}".rstrip()
        for i in engine.disasm(data, value.offset)
    ]
    return "\n".join(lines)


def vol_types() -> VolTypes:
    return VolTypes(
        absent=interfaces.renderers.BaseAbsentValue,
        layer_data=renderers.LayerData,
        disassembly=renderers.Disassembly,
        read_layer=_read_layer,
        disassemble=_disassemble,
    )


def refusing_file_handler() -> type:
    """`open_method` for every plugin: constructing a file handler is refused (RT20)."""

    class RefusingFileHandler(interfaces.plugins.FileHandlerInterface):  # type: ignore[misc]
        def __init__(self, filename: str) -> None:
            del filename
            GUARD.refuse_file_output()

        def close(self) -> None:  # pragma: no cover - never constructed
            return None

    return RefusingFileHandler


# --- imports before the audit hook ---------------------------------------------------------


def prepare_imports(ctx: Any) -> list[Any]:
    """Import every module the run needs (plugins, layers, automagic, capstone) before the
    audit hook goes in: an import-time helper (ctypes.util.find_library spawns a process)
    must not count as a refused event of the run."""
    import capstone  # noqa: F401 - loaded now, used by `_disassemble`

    framework.import_files(volatility3.plugins, True)
    framework.import_files(sys.modules["volatility3.framework.layers"], True)
    return list(automagic.available(ctx))


# --- identify ------------------------------------------------------------------------------


class _IdentityScanner(interfaces.layers.ScannerInterface):  # type: ignore[misc]
    """Both kernel signatures in one pass over the physical layer."""

    thread_safe = False
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, pdb: bool, banner: bool) -> None:
        super().__init__()
        names = [name.encode() for name in sorted(KERNEL_PDB_NAMES)]
        self._pdb = pdbutil.PdbSignatureScanner(names) if pdb else None
        self._banner = banner
        self.overlap = 0x4000

    def __call__(self, data: bytes, data_offset: int) -> Iterator[tuple[str, Any, int]]:
        if self._pdb is not None:
            self._pdb.chunk_size = self.chunk_size
            for guid, age, name, offset in self._pdb(data, data_offset):
                yield "pdb", (guid, age, name), offset
        if self._banner:
            for match in BANNER.finditer(data):
                if match.start() < self.chunk_size:
                    yield "banner", None, data_offset + match.start()


def _banner_at(layer: Any, offset: int) -> str | None:
    """The banner in the store's form (phase 5's `normalize_banner`: cut at the first NUL,
    whitespace stripped, printable ASCII, <= 512), so a Linux lookup matches the import."""
    return normalize_banner(bytes(layer.read(offset, 0xFFF, True)))


def identify(image: Path, hint: OsHint) -> dict[str, Any]:
    ctx = contexts.Context()
    prepare_imports(ctx)
    import volatility3.framework.automagic.windows  # noqa: F401 - WindowsIntelStacker

    GUARD.install()
    config_path = "identify.FileLayer"
    ctx.config[interfaces.configuration.path_join(config_path, "location")] = location(image)
    base = physical.FileLayer(ctx, config_path, "FileLayer")
    ctx.add_layer(base)
    stackers = sorted(
        (
            s
            for s in framework.class_subclasses(interfaces.automagic.StackerLayerInterface)
            if s.__name__ in IDENTIFY_STACKERS
        ),
        key=lambda s: s.stack_order,
    )
    stacked = stacker.LayerStacker.stack_layer(ctx, base.name, stackers)
    names = list(reversed(stacked))  # bottom -> top
    layers = [type(ctx.layers[n]).__name__ for n in names]
    physical_name = next(n for n in stacked if not isinstance(ctx.layers[n], intel.Intel))
    scan_layer = ctx.layers[physical_name]
    pdb: dict[str, Any] | None = None
    banner: str | None = None
    scanner = _IdentityScanner(
        pdb=hint in (OsHint.AUTO, OsHint.WINDOWS), banner=hint in (OsHint.AUTO, OsHint.LINUX)
    )
    for kind, value, offset in scan_layer.scan(ctx, scanner):
        if kind == "pdb" and pdb is None:
            guid, age, name = value
            pdb = {"name": bytes(name).decode("latin-1")[:64], "guid": str(guid)[:64], "age": age}
        elif kind == "banner" and banner is None:
            banner = _banner_at(scan_layer, offset)
        if stop_scan(hint, layers, pdb is not None, banner is not None):
            break
    return {"layers": layers[:8], "pdb": pdb, "banner": banner}


# --- one plugin ----------------------------------------------------------------------------


def _isf_urls(ctx: Any, store_uri: str) -> list[str]:
    urls: list[str] = []
    for key in ctx.config:
        if not str(key).endswith(".isf_url"):
            continue
        value = ctx.config.get(key)
        if isinstance(value, str) and value.startswith(store_uri + "/") and value not in urls:
            urls.append(value[:1024])
            if len(urls) >= MAX_ISF:
                break
    return urls


def _layer_names(ctx: Any) -> list[str]:
    names: list[str] = []
    for name in ctx.layers:
        cls = type(ctx.layers[name]).__name__
        if cls not in names:
            names.append(cls[:64])
    return names[:8]


def run_plugin(
    spec: PluginSpec, image: Path, symbols_dir: Path, writer: RowWriter, facts: dict[str, Any]
) -> None:
    """Construct and run one allow-listed plugin, streaming its rows through `writer` (which
    stops the grid at its cap). Volatility's exceptions propagate (the probe maps them to a
    status); `facts` collects what status.json reports, also on failure."""
    ctx = contexts.Context()
    automagics = prepare_imports(ctx)
    plugin_cls = framework.list_plugins().get(spec.class_path)
    if plugin_cls is None:
        raise exceptions.VolatilityException(f"plugin {spec.class_path} is not available")
    chosen = automagic.choose_automagic(automagics, plugin_cls)
    ctx.config["automagic.LayerStacker.single_location"] = location(image)
    ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
    plugin_path = interfaces.configuration.path_join(BASE_CONFIG, plugin_cls.__name__)
    for name, value in spec.options.items():
        ctx.config[interfaces.configuration.path_join(plugin_path, name)] = value
    GUARD.install()
    constructed = vol_plugins.construct_plugin(
        ctx, chosen, plugin_cls, BASE_CONFIG, None, refusing_file_handler()
    )
    facts["isf"] = _isf_urls(ctx, symbols_dir.resolve().as_uri())
    facts["layers"] = _layer_names(ctx)
    grid = constructed.run()
    writer.columns = [str(column.name) for column in grid.columns]
    facts["columns"] = writer.columns[:64]
    try:
        grid.populate(writer, None, fail_on_errors=True)
    except CapReached:
        writer.cap()


def unsatisfied(exc: BaseException) -> bool:
    return isinstance(exc, exceptions.UnsatisfiedException)


__all__ = [
    "ProbeSetupError",
    "builtin_symbol_dirs",
    "configure",
    "facts_now",
    "identify",
    "location",
    "run_plugin",
    "unsatisfied",
]
