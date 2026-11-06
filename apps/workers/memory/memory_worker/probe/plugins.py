"""The plugin allow-list of the probe: one fixed configuration per `MemoryPlugin` (M8 phase 2).

Pure data (no Volatility import), shared by the probe (tool uid) and root (row caps, tests).
Nothing here comes from the job message except which allow-listed plugin runs: the class,
every option and the row cap are fixed by this table, and a name outside it is refused
before Volatility is imported (`spec_for`).

Every `dump` / `dump-regions` option is false and no output directory exists; the probe also
constructs each plugin with a refusing file handler as `open_method` (RT20), so even an option
missed here could not write a file. Process scans keep their default virtual / physical
choice (`physical` false: offsets are virtual, `Offset(V)`).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from cyberlab_jobs.memory import MemoryLimits, MemoryPlugin

OptionValue = bool | int | str | None
# Which `MemoryLimits` cap bounds the rows of a plugin (the probe stops its grid there).
RowCap = Literal["processes", "connections", "injections", "artifacts"]


@dataclass(frozen=True)
class PluginSpec:
    plugin: MemoryPlugin
    class_path: str  # key of `framework.list_plugins()` (volatility3.plugins.<...>.<Class>)
    cap: RowCap
    options: Mapping[str, OptionValue] = field(default_factory=dict)


_P = MemoryPlugin


def _spec(
    plugin: MemoryPlugin,
    class_path: str,
    cap: RowCap,
    options: dict[str, OptionValue] | None = None,
) -> PluginSpec:
    # Keys are Volatility's requirement names verbatim (`dump-regions`, `decorate_comm`).
    return PluginSpec(plugin, class_path, cap, MappingProxyType(dict(options or {})))


NO_DUMP: dict[str, OptionValue] = {"dump": False}
PLUGINS: Mapping[MemoryPlugin, PluginSpec] = MappingProxyType(
    {
        s.plugin: s
        for s in (
            _spec(_P.WINDOWS_INFO, "windows.info.Info", "artifacts"),
            _spec(_P.WINDOWS_PSLIST, "windows.pslist.PsList", "processes",
                  {"physical": False, "dump": False}),
            _spec(_P.WINDOWS_PSSCAN, "windows.psscan.PsScan", "processes",
                  {"physical": False, "dump": False}),
            _spec(_P.WINDOWS_CMDLINE, "windows.cmdline.CmdLine", "processes"),
            _spec(_P.WINDOWS_DLLLIST, "windows.dlllist.DllList", "artifacts", NO_DUMP),
            _spec(_P.WINDOWS_NETSCAN, "windows.netscan.NetScan", "connections",
                  {"include-corrupt": False}),
            _spec(_P.WINDOWS_MALFIND, "windows.malware.malfind.Malfind", "injections", NO_DUMP),
            _spec(_P.WINDOWS_SVCSCAN, "windows.svcscan.SvcScan", "artifacts"),
            _spec(_P.WINDOWS_HIVELIST, "windows.registry.hivelist.HiveList", "artifacts",
                  NO_DUMP),
            _spec(_P.WINDOWS_USERASSIST, "windows.registry.userassist.UserAssist", "artifacts"),
            _spec(_P.WINDOWS_LDRMODULES, "windows.malware.ldrmodules.LdrModules", "artifacts"),
            _spec(_P.LINUX_PSLIST, "linux.pslist.PsList", "processes",
                  {"threads": False, "decorate_comm": False, "dump": False}),
            _spec(_P.LINUX_PSAUX, "linux.psaux.PsAux", "processes"),
            _spec(_P.LINUX_BASH, "linux.bash.Bash", "artifacts"),
            _spec(_P.LINUX_SOCKSTAT, "linux.sockstat.Sockstat", "connections"),
            _spec(_P.LINUX_LSOF, "linux.lsof.Lsof", "artifacts", {"files_only": False}),
            _spec(_P.LINUX_MALFIND, "linux.malware.malfind.Malfind", "injections",
                  {"dump-regions": False, "show-all-dirty-pages": False, "hexdump-size": 64}),
            _spec(_P.LINUX_CHECK_SYSCALL, "linux.malware.check_syscall.Check_syscall",
                  "artifacts"),
            _spec(_P.LINUX_HIDDEN_MODULES, "linux.malware.hidden_modules.Hidden_modules",
                  "artifacts", NO_DUMP),
        )
    }
)  # fmt: skip

# Option names a plugin must never get true (tested over the whole table).
WRITE_OPTIONS = frozenset({"dump", "dump-regions", "output", "output-dir"})


class UnknownPlugin(ValueError):
    """A name outside the allow-list (never reaches Volatility)."""


def spec_for(name: str) -> PluginSpec:
    try:
        return PLUGINS[MemoryPlugin(name)]
    except ValueError as exc:
        raise UnknownPlugin(name) from exc


def max_rows(spec: PluginSpec, limits: MemoryLimits) -> int:
    """Rows the probe may emit for one plugin: its kind's cap (root enforces it again)."""
    caps = {
        "processes": limits.max_processes,
        "connections": limits.max_connections,
        "injections": limits.max_injections,
        "artifacts": limits.max_artifacts,
    }
    return caps[spec.cap]


__all__ = ["PLUGINS", "WRITE_OPTIONS", "PluginSpec", "UnknownPlugin", "max_rows", "spec_for"]
