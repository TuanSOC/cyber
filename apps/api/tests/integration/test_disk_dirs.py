"""Directory browsing of a disk job (M9 phase 8, RT13): the children of one directory are the
rows whose `parent_addr` is its `meta_addr` in that partition (no path hash, no collision
check); the root is the parent of the top-level entries; directories first, then names,
within a page; addresses are decimal text."""

from tests.factories import register
from tests.integration.test_disk_reads import U64_MAX, add_file, get, windows

SYSTEM32 = 66  # Windows/System32 in windows_triage.ndjson (142 entries)


async def test_root_of_the_first_partition_with_files() -> None:
    reg = await register(org_name="Disk Dirs Root Org")
    _, _, url = await windows(reg)
    body = await get(reg.client, f"{url}/dirs")
    assert (body["partition_index"], body["parent_addr"]) == (1, "5")
    # Exactly what TSK recorded under the root, the orphan directory's entry included.
    assert [(f["name"], f["type"]) for f in body["items"]] == [
        ("Users", "dir"),
        ("Windows", "dir"),
        ("OrphanFile-9999", "reg"),
    ]
    assert body["total"] == 3
    explicit = await get(reg.client, f"{url}/dirs", partition=1, parent=5)
    assert explicit["items"] == body["items"]


async def test_one_directory_pages_without_gaps() -> None:
    reg = await register(org_name="Disk Dirs Page Org")
    _, _, url = await windows(reg)
    c = reg.client
    first = await get(c, f"{url}/dirs", partition=1, parent=SYSTEM32, limit=100)
    second = await get(c, f"{url}/dirs", partition=1, parent=SYSTEM32, limit=100, offset=100)
    assert first["total"] == second["total"] == 142
    rows = first["items"] + second["items"]
    assert len({f["id"] for f in rows}) == 142
    assert {f["parent_addr"] for f in rows} == {str(SYSTEM32)}
    for page in (first, second):
        kinds = [f["type"] == "dir" for f in page["items"]]
        assert kinds == sorted(kinds, reverse=True)  # directories first within the page
        files = [f["name"].casefold() for f in page["items"] if f["type"] != "dir"]
        assert files == sorted(files)


async def test_empty_unknown_and_unallocated_directories() -> None:
    reg = await register(org_name="Disk Dirs Empty Org")
    t, job, url = await windows(reg)
    c = reg.client
    assert (await get(c, f"{url}/dirs", partition=1, parent=424242))["items"] == []
    unalloc = await get(c, f"{url}/dirs", partition=0)  # no file system, no rows
    assert (unalloc["items"], unalloc["partition_index"], unalloc["parent_addr"]) == (
        [],
        0,
        None,
    )
    for bad in ({"parent": -1}, {"parent": 2**64}, {"partition": 128}):
        assert (await c.get(f"{url}/dirs", params=bad)).status_code == 422, bad

    # A 64-bit directory address round-trips as text.
    await add_file(t, job, meta_addr=7, parent_addr=U64_MAX, path="deep/x", name="x")
    deep = await get(c, f"{url}/dirs", partition=1, parent=U64_MAX)
    assert deep["parent_addr"] == str(U64_MAX)
    assert [f["name"] for f in deep["items"]] == ["x"]
