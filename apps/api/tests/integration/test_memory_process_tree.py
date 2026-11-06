"""The server-side process tree of a memory job (M8 phase 7): the pure builder (orphans,
cycles, pid reuse, depth without recursion) and the `view=tree` route over seeded jobs
(pre-order, the `MEMORY_TREE_MAX_NODES` fallback to the list order, no filters)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.memory_analysis.models import MemoryProcess
from app.modules.memory_analysis.service import TreeInput, TreeNode, build_tree
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant
from tests.memory_helpers import seed_memory_job

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)


def _at(minutes: int | None) -> datetime | None:
    return None if minutes is None else T0 + timedelta(minutes=minutes)


def _tree(*procs: tuple[int, int | None, int | None]) -> list[TreeNode]:
    return build_tree([TreeInput(pid, ppid, _at(m)) for pid, ppid, m in procs])


def _shape(nodes: list[TreeNode], pids: list[int]) -> list[tuple[int, int]]:
    """(pid, depth) in output order, against the input pids."""
    return [(pids[n.index], n.depth) for n in nodes]


def test_parents_children_and_sibling_order() -> None:
    procs = [(4, 0, 0), (300, 4, 2), (200, 4, 1), (301, 300, 3), (201, 200, 4)]
    nodes = _tree(*procs)
    pids = [p[0] for p in procs]
    # Siblings oldest first; depth-first pre-order.
    assert _shape(nodes, pids) == [(4, 0), (200, 1), (201, 2), (300, 1), (301, 2)]
    root = nodes[0]
    assert root.parent is None and root.parent_missing  # pid 0 is not in the job
    assert root.children == 2
    assert [n.children for n in nodes] == [2, 1, 0, 1, 0]


def test_orphans_are_roots_marked_parent_missing() -> None:
    procs = [(4, 0, 0), (468, 460, 1), (544, 460, 2), (676, 544, 3)]
    nodes = _tree(*procs)
    pids = [p[0] for p in procs]
    assert _shape(nodes, pids) == [(4, 0), (468, 0), (544, 0), (676, 1)]
    missing = {pids[n.index]: n.parent_missing for n in nodes}
    assert missing == {4: True, 468: True, 544: True, 676: False}


def test_a_two_cycle_is_broken_at_its_oldest_member() -> None:
    # Unknown ages: the cycle stays and is broken at the lowest pid.
    nodes = _tree((20, 10, None), (10, 20, None))
    assert _shape(nodes, [20, 10]) == [(10, 0), (20, 1)]
    assert not any(n.parent_missing for n in nodes)
    # Known ages: a "parent" younger than its child is a reused pid, so no cycle forms.
    nodes = _tree((10, 20, 5), (20, 10, 1))
    assert _shape(nodes, [10, 20]) == [(20, 0), (10, 1)]
    assert nodes[0].parent_missing and not nodes[1].parent_missing


def test_a_long_cycle_and_a_self_parent_never_loop() -> None:
    ring = [(pid, pid - 1 if pid > 1 else 50, None) for pid in range(1, 51)]
    nodes = _tree(*ring, (77, 77, None))
    assert len(nodes) == 51
    assert sorted(n.index for n in nodes) == list(range(51))
    roots = [n for n in nodes if n.depth == 0]
    assert len(roots) == 2  # the broken ring and the self-parented process
    assert max(n.depth for n in nodes) == 49


def test_a_deep_chain_has_no_recursion_limit() -> None:
    depth = 20_000
    chain = [(pid, pid - 1 if pid else None, None) for pid in range(depth)]
    nodes = _tree(*chain)
    assert len(nodes) == depth
    assert nodes[-1].depth == depth - 1


def test_a_reused_parent_pid_links_to_the_instance_alive_at_the_child_start() -> None:
    # pid 100 twice: an old instance (minute 0) and a new one (minute 30).
    procs = [(100, None, 0), (100, None, 30), (200, 100, 10), (300, 100, 40), (400, 100, None)]
    nodes = _tree(*procs)
    by_index = {n.index: n for n in nodes}
    assert by_index[2].parent == 0  # started at 10: the minute-0 instance
    assert by_index[3].parent == 1  # started at 40: the minute-30 instance
    assert by_index[4].parent == 0  # unknown start: the first instance
    # Every parent instance is younger than the child: the real parent exited.
    child = next(n for n in _tree((100, None, 30), (200, 100, 10)) if n.index == 1)
    assert child.parent is None and child.parent_missing and child.depth == 0


def test_every_process_appears_once_in_a_messy_input() -> None:
    procs = [
        (1, 2, None),
        (2, 3, None),
        (3, 1, None),  # a three-cycle
        (4, 4, 0),  # self-parent
        (5, 999, 1),  # orphan
        (6, 5, 2),
        (6, 5, 3),  # pid reuse under the same parent
        (7, None, None),
    ]
    nodes = _tree(*procs)
    assert sorted(n.index for n in nodes) == list(range(len(procs)))
    assert sum(n.children for n in nodes) == sum(1 for n in nodes if n.parent is not None)


# --- The route -----------------------------------------------------------------------------


def _url(reg: Registered, job_id: uuid.UUID, path: str = "/processes") -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}/memory{path}"


async def _tenant(reg: Registered) -> Tenant:
    created = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Memory tree case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(created.json()["id"]))


async def _get(client: AsyncClient, url: str, **params: Any) -> dict[str, Any]:
    response = await client.get(url, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def _all(client: AsyncClient, url: str, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    while True:
        page = await _get(client, url, offset=len(items), limit=100, **params)
        items.extend(page["items"])
        if len(items) >= page["total"] or not page["items"]:
            return items


async def test_tree_view_is_the_whole_job_in_pre_order() -> None:
    reg = await register(org_name="Memory Tree Org")
    job = await seed_memory_job(await _tenant(reg))
    c = reg.client
    tree = await _all(c, _url(reg, job), view="tree")
    listed = await _all(c, _url(reg, job))
    assert len(tree) == len(listed) == 40
    assert sorted(p["id"] for p in tree) == sorted(p["id"] for p in listed)
    # Roots first in creation order: System (ppid 0 missing), then the session orphans.
    assert tree[0]["name"] == "System"
    # Pre-order: every non-root's parent appears before it.
    seen: set[int] = set()
    for proc in tree:
        assert proc["ppid"] in seen or proc["ppid"] not in {p["pid"] for p in tree}, proc
        seen.add(proc["pid"])
    explorer = next(p for p in tree if p["name"] == "explorer.exe")
    hidden = next(p for p in tree if p["pid"] == 6112)
    assert hidden["sources"] == ["psscan"]
    assert tree.index(hidden) > tree.index(explorer)  # under explorer.exe
    assert explorer["children"] == 7
    services = next(p for p in tree if p["name"] == "services.exe")
    assert services["children"] == 14


async def test_tree_view_refuses_filters() -> None:
    reg = await register(org_name="Memory Tree Filter Org")
    job = await seed_memory_job(await _tenant(reg))
    for params in ({"q": "svchost"}, {"ppid": 4}, {"hidden": "true"}, {"ref": str(uuid.uuid4())}):
        response = await reg.client.get(_url(reg, job), params={"view": "tree", **params})
        assert response.status_code == 422, params
        assert response.json()["error"]["code"] == "memory_tree_unfiltered"
    bad = await reg.client.get(_url(reg, job), params={"view": "graph"})
    assert bad.status_code == 422


async def test_a_job_beyond_the_node_cap_answers_the_list_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reg = await register(org_name="Memory Tree Cap Org")
    job = await seed_memory_job(await _tenant(reg))
    monkeypatch.setattr(get_settings(), "memory_tree_max_nodes", 10)
    page = await _get(reg.client, _url(reg, job), view="tree", limit=100)
    listed = await _get(reg.client, _url(reg, job), limit=100)
    assert page["total"] == 40 > 10
    assert [p["id"] for p in page["items"]] == [p["id"] for p in listed["items"]]


async def test_a_cyclic_job_renders_without_error() -> None:
    reg = await register(org_name="Memory Tree Cycle Org")
    t = await _tenant(reg)
    job = await seed_memory_job(t, fixture=None)
    async with tenant_session(t.org_id, t.owner_id) as s:
        # Unknown start times, so the parent links really form a cycle (10 -> 30 -> 20 -> 10).
        for pid, ppid in ((10, 30), (20, 10), (30, 20), (40, 40), (50, 999)):
            s.add(
                MemoryProcess(
                    organization_id=t.org_id,
                    job_id=job,
                    pid=pid,
                    ppid=ppid,
                    name=f"p{pid}",
                    sources=1,
                )
            )
    tree = await _get(reg.client, _url(reg, job), view="tree")
    assert tree["total"] == 5
    assert [p["pid"] for p in tree["items"]] == [10, 20, 30, 40, 50]  # broken at pid 10
    assert [p["children"] for p in tree["items"]] == [1, 1, 0, 0, 0]
