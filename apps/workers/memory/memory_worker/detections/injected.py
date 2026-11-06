"""`heuristic:mem_injected_code@1`: private, writable and executable regions (`malfind`).

`medium` when the region starts with an `MZ` header or holds a `PE\\0\\0` signature at an
in-bounds `e_lfanew`; `low` otherwise. Regions without a PE header in known JIT hosts
(browsers, .NET and script runtimes, Electron apps) are skipped: JIT compilers allocate RWX
memory all the time. Titles describe the region, never "injected code" (RT21).
"""

from cyberlab_jobs.memory import MemoryInjectionRecord

from memory_worker.detections.base import Context, Finding, hex_addr, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

# Lower-case process names whose RWX regions without a PE header are expected.
JIT_HOSTS = frozenset(
    {
        "chrome.exe",
        "msedge.exe",
        "msedgewebview2.exe",
        "firefox.exe",
        "iexplore.exe",
        "brave.exe",
        "opera.exe",
        "teams.exe",
        "ms-teams.exe",
        "slack.exe",
        "discord.exe",
        "code.exe",
        "powershell.exe",
        "powershell_ise.exe",
        "pwsh.exe",
        "dotnet.exe",
        "devenv.exe",
        "w3wp.exe",
        "java.exe",
        "javaw.exe",
        "node.exe",
        "electron.exe",
    }
)
WINDOWS_EXEC_WRITE = ("PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY")
PE_SIGNATURE = "50450000"  # "PE\0\0"
MZ = "4d5a"
E_LFANEW_OFFSET = 0x3C
CONFIDENCE_PE = 0.7
CONFIDENCE_REGION = 0.4
HEAD_SHOWN = 16  # bytes of the head quoted in a description


def writable_executable(protection: str | None) -> bool:
    if not protection:
        return False
    value = protection.upper()
    if value.startswith("PAGE_"):
        return any(p in value for p in WINDOWS_EXEC_WRITE)
    # Linux VMA flags ("rwx", "rwxp").
    flags = value.lower()
    return "w" in flags and "x" in flags


def is_private(region: MemoryInjectionRecord) -> bool:
    if region.private is not None:
        return region.private
    return (region.tag or "") == "VadS"  # private VAD tag when the flag is not reported


def pe_header(region: MemoryInjectionRecord) -> str | None:
    """`"an MZ header"` / `"a PE header"` when visible, else None."""
    head = region.head_hex
    size = region.end - region.start + 1
    if head.startswith(MZ) and len(head) >= (E_LFANEW_OFFSET + 4) * 2:
        field = head[E_LFANEW_OFFSET * 2 : (E_LFANEW_OFFSET + 4) * 2]
        lfanew = int.from_bytes(bytes.fromhex(field), "little")
        in_head = len(head) >= (lfanew + 4) * 2
        if lfanew + 4 <= size and in_head and head[lfanew * 2 : (lfanew + 4) * 2] == PE_SIGNATURE:
            return "a PE header"
    if head.startswith(MZ):
        return "an MZ header"
    if region.has_pe:
        return "a PE header"
    return None


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for region in view.injections:
        if not is_private(region) or not writable_executable(region.protection):
            continue
        name = region.process or ctx.name_of(region.pid) or "unknown"
        header = pe_header(region)
        if header is None and name.lower() in JIT_HOSTS:
            continue
        start, end = hex_addr(region.start), hex_addr(region.end)
        values: dict[str, object] = {
            "pid": region.pid,
            "name": excerpt(name, 64),
            "protection": excerpt(region.protection, 64),
            "start": start,
            "end": end,
            "size": region.end - region.start + 1,
            "header": header or "",
            "head": region.head_hex[: HEAD_SHOWN * 2] or "not captured",
        }
        out.append(
            Finding(
                type="mem_private_exec_pe" if header else "mem_private_exec_region",
                severity="medium" if header else "low",
                confidence=CONFIDENCE_PE if header else CONFIDENCE_REGION,
                values=values,
                key=f"{region.pid}|{start}",
                pid=region.pid,
                refs=refs([f"pid:{region.pid}", f"region:{start}-{end}"]),
                attributes={
                    "pid": region.pid,
                    "start": start,
                    "end": end,
                    "pe_header": header is not None,
                    "protection": (region.protection or "")[:64],
                },
            )
        )
    return out
