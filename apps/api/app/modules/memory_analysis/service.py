"""Memory read API logic (M8 phase 7): job readiness, the summary, row mapping and the
server-side process tree.

- Every read runs under `SET LOCAL statement_timeout = '5s'` (the request's tenant
  transaction) and answers `409 analysis_not_ready` while the job is queued or running.
- Text is returned exactly as stored (bounded and NUL-free at ingest); command lines and
  bash history are raw here (job pages, evidence.read) and masked only on the shared
  surfaces (findings, IOC context, timeline titles; RT13). Addresses (and address
  attributes) are `0x...` hex strings, as are hex heads; disassembly is text.
- No audit per read (recorded decision, same as the static result pages).
"""

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any, Literal

from cyberlab_jobs.memory import MemoryProfile
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, Conflict, NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import ACTIVE, AnalysisJob
from app.modules.memory_analysis import repository as repo
from app.modules.memory_analysis.models import (
    SOURCE_BITS,
    MemoryArtifact,
    MemoryConnection,
    MemoryImage,
    MemoryInjection,
    MemoryProcess,
)
from app.modules.memory_analysis.schemas import (
    ArtifactOut,
    ConnectionOut,
    InjectionOut,
    LinuxBannerOut,
    MemorySummaryOut,
    PluginStatusOut,
    ProcessDetailOut,
    ProcessOut,
    SymbolsOut,
    WindowsPdbOut,
)

STATEMENT_TIMEOUT = "SET LOCAL statement_timeout = '5s'"
ProcessView = Literal["list", "tree"]


class AnalysisNotReady(Conflict):
    code = "analysis_not_ready"
    message = "This analysis is still queued or running"


class ResultsNotAvailable(NotFound):
    """Same code as the static `/sample` route: a terminal job without a stored result."""

    code = "results_not_available"
    message = "This analysis has no stored results"


class TreeViewFiltered(AppError):
    status_code = 422
    code = "memory_tree_unfiltered"
    message = "The process tree covers the whole job: use the list view to filter"


async def ready_job(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> AnalysisJob:
    """The org's memory job (404 otherwise) once it is terminal (409 before), with the read
    statement timeout set for the rest of the request's transaction."""
    await session.execute(text(STATEMENT_TIMEOUT))
    job = await repo.ensure_memory_job(session, org_id, job_id)
    if job.status in ACTIVE:
        raise AnalysisNotReady()
    return job


# --- Row mapping ---------------------------------------------------------------------------


def source_names(bits: int) -> list[str]:
    return [name for name, bit in SOURCE_BITS.items() if bits & bit]


def process_out(row: MemoryProcess, children: int = 0) -> ProcessOut:
    return ProcessOut.model_validate(
        {
            "id": row.id,
            "pid": row.pid,
            "ppid": row.ppid,
            "name": row.name,
            "offset": row.offset,
            "create_time": row.create_time,
            "exit_time": row.exit_time,
            "threads": row.threads,
            "handles": row.handles,
            "session_id": row.session_id,
            "wow64": row.wow64,
            "sources": source_names(row.sources),
            "cmdline": row.cmdline,
            "image_path": row.image_path,
            "children": children,
        }
    )


def _ip(value: object) -> str | None:
    """asyncpg returns inet values as ipaddress objects (an interface when a mask is set);
    the API speaks plain host strings, as the `q` filter matches them (`host()`)."""
    if value is None:
        return None
    if isinstance(value, IPv4Interface | IPv6Interface):
        return str(value.ip)
    return str(value)


def connection_out(row: MemoryConnection) -> ConnectionOut:
    return ConnectionOut.model_validate(
        {
            "id": row.id,
            "proto": row.proto,
            "local_addr": _ip(row.local_addr),
            "local_port": row.local_port,
            "remote_addr": _ip(row.remote_addr),
            "remote_port": row.remote_port,
            "state": row.state,
            "pid": row.pid,
            "owner": row.owner,
            "created": row.created,
            "offset": row.offset,
        }
    )


def injection_out(row: MemoryInjection) -> InjectionOut:
    return InjectionOut.model_validate(row)


def artifact_out(row: MemoryArtifact) -> ArtifactOut:
    return ArtifactOut.model_validate(row)


# --- Summary -------------------------------------------------------------------------------


def _str_map(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def _bool_map(value: object) -> dict[str, bool]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, bool)}


def _int_map(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, int) and not isinstance(v, bool)}


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def symbols_out(image: MemoryImage) -> SymbolsOut:
    """The symbols outcome; the Windows PDB triple only when complete (the UI builds the
    operator command from it alone, RT12), the Linux banner as inert text."""
    pdb = None
    if image.pdb_name and image.pdb_guid and image.pdb_age is not None:
        pdb = WindowsPdbOut(name=image.pdb_name, guid=image.pdb_guid, age=image.pdb_age)
    banner = LinuxBannerOut(banner=image.kernel_banner) if image.kernel_banner else None
    return SymbolsOut(
        status=image.symbols_status,  # DB check constraint
        isf_sha256=image.isf_sha256,
        windows_pdb=pdb,
        linux_banner=banner,
    )


async def summary(session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob) -> MemorySummaryOut:
    """The image facts, the symbols outcome and every plugin's status. The header fields the
    ingest keeps in the job summary (`tool_versions`, `truncated`, `engine_errors`, as for
    pcap / static) are read tolerantly; the row counts are live (the stored counts, e.g. the
    ingest's `orphan_ref`, are kept under the live ones)."""
    image = await repo.image(session, org_id, job.id)
    if image is None:
        raise ResultsNotAvailable()
    size_bytes, sha256 = await repo.evidence_facts(session, org_id, job.evidence_id)
    stored: Mapping[str, Any] = job.summary if isinstance(job.summary, Mapping) else {}
    tool_versions = _str_map(stored.get("tool_versions"))
    if not tool_versions and image.volatility_version:
        tool_versions = {"volatility3": image.volatility_version}
    counts = {**_int_map(image.counts), **await repo.live_counts(session, org_id, job.id)}
    assert job.profile is not None  # noqa: S101 - 0016 check: memory jobs have a profile
    return MemorySummaryOut(
        job_id=job.id,
        evidence_id=job.evidence_id,
        profile=MemoryProfile(job.profile.value),
        os=image.os,  # DB check constraint
        arch=image.arch,
        layer=image.layer,
        engine=image.engine,  # DB check constraint
        nt_build=image.nt_build,
        system_time=image.system_time,
        size_bytes=size_bytes,
        sha256=sha256 or "",
        symbols=symbols_out(image),
        tool_versions=tool_versions,
        plugins=[PluginStatusOut.model_validate(p) for p in image.plugins or []],
        counts=counts,
        truncated=_bool_map(stored.get("truncated")),
        engine_errors=_str_list(stored.get("engine_errors")),
    )


# --- Process tree --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TreeInput:
    pid: int
    ppid: int | None
    create_time: datetime | None


@dataclass(frozen=True, slots=True)
class TreeNode:
    """One process in tree (pre-)order: `index` into the input, its tree parent's index."""

    index: int
    depth: int
    parent: int | None
    parent_missing: bool
    children: int


def _key(item: TreeInput, index: int) -> tuple[bool, float, int, int]:
    ct = item.create_time
    return (ct is None, ct.timestamp() if ct is not None else 0.0, item.pid, index)


def _pick_parent(items: Sequence[TreeInput], i: int, candidates: list[int]) -> int | None:
    """The instance of the parent pid that existed when the child started: the newest one
    created at or before it; one of unknown age otherwise; none when every instance is
    younger than the child (the pid was reused after the real parent exited)."""
    ct = items[i].create_time
    if ct is None:
        return candidates[0]
    before = [j for j in candidates if (t := items[j].create_time) is not None and t <= ct]
    if before:
        return max(before, key=lambda j: _key(items[j], j))
    unknown = [j for j in candidates if items[j].create_time is None]
    return unknown[0] if unknown else None


def build_tree(items: Sequence[TreeInput]) -> list[TreeNode]:
    """Processes in depth-first pre-order (siblings oldest first). Pure and iterative, so a
    hostile image cannot cause a recursion error:
    - a process whose ppid matches no process of the job is a root with `parent_missing`;
    - a ppid equal to its own pid is a root;
    - a cycle (A -> B -> A) is broken at its oldest member, which becomes a root;
    - every input appears exactly once."""
    n = len(items)
    by_pid: dict[int, list[int]] = {}
    for i, item in enumerate(items):
        by_pid.setdefault(item.pid, []).append(i)
    parent: list[int | None] = [None] * n
    missing = [False] * n
    for i, item in enumerate(items):
        if item.ppid is None or item.ppid == item.pid:
            continue
        candidates = [j for j in by_pid.get(item.ppid, []) if j != i]
        chosen = _pick_parent(items, i, candidates) if candidates else None
        parent[i] = chosen
        missing[i] = chosen is None
    # Break cycles: walk each parent chain once (0 = new, 1 = on the current path, 2 = done).
    state = [0] * n
    for start in range(n):
        path: list[int] = []
        node: int | None = start
        while node is not None and state[node] == 0:
            state[node] = 1
            path.append(node)
            node = parent[node]
        if node is not None and state[node] == 1:
            cycle = path[path.index(node) :]
            breaker = min(cycle, key=lambda j: _key(items[j], j))
            parent[breaker] = None
        for j in path:
            state[j] = 2
    children: list[list[int]] = [[] for _ in range(n)]
    roots: list[int] = []
    for i in range(n):
        p = parent[i]
        (roots if p is None else children[p]).append(i)
    for siblings in (roots, *children):
        siblings.sort(key=lambda j: _key(items[j], j))
    out: list[TreeNode] = []
    stack: list[tuple[int, int]] = [(i, 0) for i in reversed(roots)]
    while stack:
        i, depth = stack.pop()
        out.append(TreeNode(i, depth, parent[i], missing[i], len(children[i])))
        stack.extend((c, depth + 1) for c in reversed(children[i]))
    return out


async def process_page(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    view: ProcessView,
    q: str | None,
    ppid: int | None,
    hidden: bool | None,
    ref: uuid.UUID | None,
) -> tuple[list[ProcessOut], int]:
    """The list view (filters, `ref`) or the tree view: the whole job in tree pre-order,
    built here from at most `MEMORY_TREE_MAX_NODES` processes. A larger job answers the
    list order instead (its `total` then exceeds the cap: the client's cue to show the
    list)."""
    if view == "tree":
        if q or ppid is not None or hidden is not None or ref is not None:
            raise TreeViewFiltered()
        cap = get_settings().memory_tree_max_nodes
        rows = await repo.tree_rows(session, org_id, job_id, cap)
        if len(rows) <= cap:
            nodes = build_tree([TreeInput(r.pid, r.ppid, r.create_time) for r in rows])
            window = nodes[page.offset : page.offset + page.limit]
            return [process_out(rows[node.index], node.children) for node in window], len(nodes)
    found, total = await repo.processes(
        session, org_id, job_id, page, q=q, ppid=ppid, hidden=hidden, ref=ref
    )
    counts = await repo.children_counts(session, org_id, job_id, (r.pid for r in found))
    return [process_out(r, counts.get(r.pid, 0)) for r in found], total


async def process_detail(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, pid: int
) -> ProcessDetailOut:
    """One process (its best instance: in the active list, running, newest) with its parent,
    children, connections, private executable regions and artifacts (each at most
    `DETAIL_CAP`); 404 for a pid the job does not have."""
    found = await repo.instances(session, org_id, job_id, pid)
    if not found:
        raise NotFound()
    row = found[0]
    parent = None
    if row.ppid is not None and row.ppid != row.pid:
        candidates = await repo.instances(session, org_id, job_id, row.ppid)
        parent = _parent_instance(row, candidates)
    kids = await repo.children_of(session, org_id, job_id, pid)
    related = [row.pid, *([parent.pid] if parent else []), *(k.pid for k in kids)]
    counts = await repo.children_counts(session, org_id, job_id, related)
    conns = await repo.rows_of_pid(
        session, MemoryConnection, org_id, job_id, pid, repo.CONNECTION_ORDER
    )
    regions = await repo.rows_of_pid(
        session, MemoryInjection, org_id, job_id, pid, repo.INJECTION_ORDER
    )
    arts = await repo.rows_of_pid(session, MemoryArtifact, org_id, job_id, pid, repo.ARTIFACT_ORDER)
    return ProcessDetailOut(
        process=process_out(row, counts.get(row.pid, 0)),
        parent=process_out(parent, counts.get(parent.pid, 0)) if parent else None,
        children=[process_out(k, counts.get(k.pid, 0)) for k in kids],
        connections=[connection_out(c) for c in conns],
        injections=[injection_out(r) for r in regions],
        artifacts=[artifact_out(a) for a in arts],
        instances=await repo.instance_count(session, org_id, job_id, pid),
    )


def _parent_instance(
    child: MemoryProcess, candidates: Sequence[MemoryProcess]
) -> MemoryProcess | None:
    """The same rule as the tree (`_pick_parent`) over the parent pid's instances."""
    if not candidates:
        return None
    items = [TreeInput(c.pid, c.ppid, c.create_time) for c in candidates]
    items.append(TreeInput(child.pid, child.ppid, child.create_time))
    chosen = _pick_parent(items, len(candidates), list(range(len(candidates))))
    return None if chosen is None else candidates[chosen]
