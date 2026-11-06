"""One row model per allow-listed plugin, in the volatility3 2.28.2 column names (aliases).

Strict types (a string where an int belongs, a nested object in a scalar column, a bool for
an int: the row is skipped and counted); unknown columns are ignored and counted
(`unknown_columns`); a null value (the probe's encoding of an absent / unreadable value) is
always accepted. `COLUMNS[plugin]` is the exact column list of the plugin's `TreeGrid`, which
`test_plugin_columns.py` compares with the installed Volatility source (RT4, the only guard
for the Windows plugins, which no test executes) and with `tests/fixtures/vol_rows/`.

Datetimes arrive as ISO strings, hex columns as ints, hex dumps as lowercase hex strings.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Any

from cyberlab_jobs.memory import MemoryPlugin
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

I = StrictInt | None  # noqa: E741
S = Annotated[StrictStr, Field(max_length=8192)] | None
B = StrictBool | None
RESERVED = frozenset({"_parent", "_unreadable"})


class Row(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=False)
    parent: StrictInt | None = Field(default=None, alias="_parent")


def _f(alias: str) -> Any:
    return Field(default=None, alias=alias)


# --- Windows -------------------------------------------------------------------------------


class WinInfo(Row):
    variable: S = _f("Variable")
    value: S = _f("Value")


class WinProcess(Row):  # windows.pslist and windows.psscan (identical columns)
    pid: I = _f("PID")
    ppid: I = _f("PPID")
    name: S = _f("ImageFileName")
    offset: I = _f("Offset(V)")
    threads: I = _f("Threads")
    handles: I = _f("Handles")
    session_id: I = _f("SessionId")
    wow64: B = _f("Wow64")
    create_time: S = _f("CreateTime")
    exit_time: S = _f("ExitTime")
    file_output: S = _f("File output")


class WinCmdline(Row):
    pid: I = _f("PID")
    process: S = _f("Process")
    args: S = _f("Args")


class WinDll(Row):
    pid: I = _f("PID")
    process: S = _f("Process")
    base: I = _f("Base")
    size: I = _f("Size")
    name: S = _f("Name")
    path: S = _f("Path")
    load_count: I = _f("LoadCount")
    load_time: S = _f("LoadTime")
    file_output: S = _f("File output")


class WinNetscan(Row):
    offset: I = _f("Offset")
    proto: S = _f("Proto")
    local_addr: S = _f("LocalAddr")
    local_port: I = _f("LocalPort")
    foreign_addr: S = _f("ForeignAddr")
    foreign_port: I = _f("ForeignPort")
    state: S = _f("State")
    pid: I = _f("PID")
    owner: S = _f("Owner")
    created: S = _f("Created")


class WinMalfind(Row):
    pid: I = _f("PID")
    process: S = _f("Process")
    start: I = _f("Start VPN")
    end: I = _f("End VPN")
    tag: S = _f("Tag")
    protection: S = _f("Protection")
    commit_charge: I = _f("CommitCharge")
    private_memory: I = _f("PrivateMemory")
    file_output: S = _f("File output")
    notes: S = _f("Notes")
    hexdump: S = _f("Hexdump")
    disasm: S = _f("Disasm")


class WinService(Row):
    offset: I = _f("Offset")
    order: I = _f("Order")
    pid: I = _f("PID")
    start: S = _f("Start")
    state: S = _f("State")
    type: S = _f("Type")
    name: S = _f("Name")
    display: S = _f("Display")
    binary: S = _f("Binary")
    binary_registry: S = _f("Binary (Registry)")
    dll: S = _f("Dll")


class WinHive(Row):
    offset: I = _f("Offset")
    path: S = _f("FileFullPath")
    file_output: S = _f("File output")


class WinUserAssist(Row):
    hive_offset: I = _f("Hive Offset")
    hive_name: S = _f("Hive Name")
    path: S = _f("Path")
    last_write_time: S = _f("Last Write Time")
    type: S = _f("Type")
    name: S = _f("Name")
    id: I = _f("ID")
    count: I = _f("Count")
    focus_count: I = _f("Focus Count")
    time_focused: S = _f("Time Focused")
    last_updated: S = _f("Last Updated")
    raw_data: S = _f("Raw Data")


class WinLdrModule(Row):
    pid: I = _f("Pid")
    process: S = _f("Process")
    base: I = _f("Base")
    in_load: B = _f("InLoad")
    in_init: B = _f("InInit")
    in_mem: B = _f("InMem")
    path: S = _f("MappedPath")


# --- Linux ---------------------------------------------------------------------------------


class LinuxTask(Row):
    offset: I = _f("OFFSET (V)")
    pid: I = _f("PID")
    tid: I = _f("TID")
    ppid: I = _f("PPID")
    comm: S = _f("COMM")
    uid: I = _f("UID")
    gid: I = _f("GID")
    euid: I = _f("EUID")
    egid: I = _f("EGID")
    creation_time: S = _f("CREATION TIME")
    file_output: S = _f("File output")


class LinuxPsaux(Row):
    pid: I = _f("PID")
    ppid: I = _f("PPID")
    comm: S = _f("COMM")
    args: S = _f("ARGS")


class LinuxBash(Row):
    pid: I = _f("PID")
    process: S = _f("Process")
    command_time: S = _f("CommandTime")
    command: S = _f("Command")


class LinuxSocket(Row):
    netns: I = _f("NetNS")
    process: S = _f("Process Name")
    pid: I = _f("PID")
    tid: I = _f("TID")
    fd: I = _f("FD")
    sock_offset: I = _f("Sock Offset")
    family: S = _f("Family")
    type: S = _f("Type")
    proto: S = _f("Proto")
    source_addr: S = _f("Source Addr")
    source_port: S = _f("Source Port")
    destination_addr: S = _f("Destination Addr")
    destination_port: S = _f("Destination Port")
    state: S = _f("State")
    filter: S = _f("Filter")


class LinuxOpenFile(Row):
    pid: I = _f("PID")
    tid: I = _f("TID")
    process: S = _f("Process")
    fd: I = _f("FD")
    path: S = _f("Path")
    device: S = _f("Device")
    inode: I = _f("Inode")
    type: S = _f("Type")
    mode: S = _f("Mode")
    changed: S = _f("Changed")
    modified: S = _f("Modified")
    accessed: S = _f("Accessed")
    size: I = _f("Size")


class LinuxMalfind(Row):
    pid: I = _f("PID")
    process: S = _f("Process")
    start: I = _f("Start")
    end: I = _f("End")
    path: S = _f("Path")
    protection: S = _f("Protection")
    hexdump: S = _f("Hexdump")
    disasm: S = _f("Disasm")
    file_output: S = _f("File output")


class LinuxSyscall(Row):
    table_address: I = _f("Table Address")
    table_name: S = _f("Table Name")
    index: I = _f("Index")
    handler_address: I = _f("Handler Address")
    handler_symbol: S = _f("Handler Symbol")


class LinuxHiddenModule(Row):
    offset: I = _f("Offset")
    module_name: S = _f("Module Name")
    code_size: I = _f("Code Size")
    taints: S = _f("Taints")
    load_arguments: S = _f("Load Arguments")
    file_output: S = _f("File Output")


_P = MemoryPlugin
MODELS: Mapping[MemoryPlugin, type[Row]] = MappingProxyType(
    {
        _P.WINDOWS_INFO: WinInfo,
        _P.WINDOWS_PSLIST: WinProcess,
        _P.WINDOWS_PSSCAN: WinProcess,
        _P.WINDOWS_CMDLINE: WinCmdline,
        _P.WINDOWS_DLLLIST: WinDll,
        _P.WINDOWS_NETSCAN: WinNetscan,
        _P.WINDOWS_MALFIND: WinMalfind,
        _P.WINDOWS_SVCSCAN: WinService,
        _P.WINDOWS_HIVELIST: WinHive,
        _P.WINDOWS_USERASSIST: WinUserAssist,
        _P.WINDOWS_LDRMODULES: WinLdrModule,
        _P.LINUX_PSLIST: LinuxTask,
        _P.LINUX_PSAUX: LinuxPsaux,
        _P.LINUX_BASH: LinuxBash,
        _P.LINUX_SOCKSTAT: LinuxSocket,
        _P.LINUX_LSOF: LinuxOpenFile,
        _P.LINUX_MALFIND: LinuxMalfind,
        _P.LINUX_CHECK_SYSCALL: LinuxSyscall,
        _P.LINUX_HIDDEN_MODULES: LinuxHiddenModule,
    }
)


def columns(model: type[Row]) -> tuple[str, ...]:
    return tuple(
        str(f.alias)
        for name, f in model.model_fields.items()
        if name != "parent" and f.alias is not None
    )


COLUMNS: Mapping[MemoryPlugin, tuple[str, ...]] = MappingProxyType(
    {plugin: columns(model) for plugin, model in MODELS.items()}
)

__all__ = ["COLUMNS", "MODELS", "RESERVED", "Row", "columns"]
