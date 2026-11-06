"""`heuristic:mem_unexpected_network@1`: an established TCP connection to an external address
owned by a Windows program that normally makes none.

"External" is a globally routable address (`ipaddress.is_global`) or a documentation range
(below): private, loopback, link-local and CGNAT addresses never fire, so a domain
controller's `lsass.exe` talking to its clients stays silent.
"""

import ipaddress

from memory_worker.detections.base import Context, Finding, joined, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

# Lower-case process names that normally hold no network connection.
NO_NETWORK = frozenset(
    {
        "lsass.exe",
        "notepad.exe",
        "calc.exe",
        "mspaint.exe",
        "wordpad.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "conhost.exe",
        "dllhost.exe",
        "taskhostw.exe",
        "werfault.exe",
        "cmd.exe",
    }
)
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
ESTABLISHED = "ESTABLISHED"
CONFIDENCE = 0.6
MAX_REMOTES_SHOWN = 10
# RFC 5737 / 3849 documentation ranges: synthetic test data uses them as "external" addresses,
# and no real host ever has one (treated as external so the scenario set can exercise the
# rule; `is_global` alone calls them non-global).
DOCUMENTATION = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def external(address: Address) -> bool:
    if any(address in net for net in DOCUMENTATION if net.version == address.version):
        return True
    return address.is_global and not address.is_multicast


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    if view.os != "windows":
        return []
    by_pid: dict[int, list[tuple[Address, int | None, str]]] = {}
    owners: dict[int, str] = {}
    for conn in view.connections:
        if conn.proto != "tcp" or conn.pid is None or conn.remote_addr is None:
            continue
        if (conn.state or "").upper() != ESTABLISHED or not external(conn.remote_addr):
            continue
        owner = conn.owner or ctx.name_of(conn.pid) or ""
        if owner.lower() not in NO_NETWORK:
            continue
        if conn.pid not in by_pid and not ctx.budget.take():
            break
        offset = f"0x{conn.offset:x}" if conn.offset is not None else ""
        by_pid.setdefault(conn.pid, []).append((conn.remote_addr, conn.remote_port, offset))
        owners.setdefault(conn.pid, owner)
    out: list[Finding] = []
    for pid, remotes in by_pid.items():
        shown = [f"{ip}:{port}" if port is not None else str(ip) for ip, port, _ in remotes]
        first_ip, first_port, _ = remotes[0]
        out.append(
            Finding(
                type="mem_unexpected_network",
                severity="medium",
                confidence=CONFIDENCE,
                values={
                    "pid": pid,
                    "name": excerpt(owners[pid], 64),
                    "count": len(remotes),
                    "remotes": joined(shown[:MAX_REMOTES_SHOWN], 300),
                },
                key=str(pid),
                pid=pid,
                refs=refs(
                    [f"pid:{pid}", *(f"connection:{off}" for _, _, off in remotes if off)]
                ),
                attributes={"pid": pid, "connections": len(remotes), "first_remote": str(first_ip)},
                dst_ip=first_ip,
                dst_port=first_port,
            )
        )
    return out
