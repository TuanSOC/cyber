"""The merged disk timeline (M9 phase 8, RT14): one row per set file-system time column plus
the events, totally ordered by (ts, stream, id) and stable across pages (no duplicates, no
gaps); filters by source, time column, artifact and range; FAT times of unknown zone are
labelled."""

from datetime import UTC, datetime
from typing import Any

from tests.factories import register
from tests.integration.test_disk_reads import EVENTS, FILES, add_file, get, windows

ALL = FILES * 4 + EVENTS  # every fixture entry has its four times


def _key(item: dict[str, Any]) -> tuple[str, str, str]:
    stream = item["kind"] if item["source"] == "file" else "event"
    row_id = item["file_id"] if item["source"] == "file" else item["event_id"]
    return (item["ts"], stream, row_id)


async def _all(client: Any, url: str, **params: Any) -> tuple[list[dict[str, Any]], int]:
    items: list[dict[str, Any]] = []
    total = 0
    offset = 0
    while True:
        page = await get(client, f"{url}/timeline", limit=100, offset=offset, **params)
        total = page["total"]
        items += page["items"]
        if len(page["items"]) < 100:
            return items, total
        offset += 100


async def test_pages_are_totally_ordered_without_duplicates_or_gaps() -> None:
    reg = await register(org_name="Disk Timeline Order Org")
    _, _, url = await windows(reg)
    items, total = await _all(reg.client, url)
    assert total == len(items) == ALL
    keys = [_key(i) for i in items]
    assert keys == sorted(keys)  # (ts, stream, id): ISO text of one zone sorts by time
    assert len(set(keys)) == ALL
    # A different page size slices the same order.
    odd = await get(reg.client, f"{url}/timeline", limit=37, offset=111)
    assert [_key(i) for i in odd["items"]] == keys[111:148]
    first = items[0]
    assert (first["source"], first["kind"]) == ("file", "crtime")  # 08:00, crtime < ctime
    event = next(i for i in items if i["source"] == "event")
    assert event["event_id"] and event["description"]


async def test_filters_by_source_column_artifact_and_range() -> None:
    reg = await register(org_name="Disk Timeline Filter Org")
    _, _, url = await windows(reg)
    c = reg.client
    events = await get(c, f"{url}/timeline", source="event")
    assert events["total"] == EVENTS and {i["source"] for i in events["items"]} == {"event"}
    mtimes = await get(c, f"{url}/timeline", time="mtime", source="file")
    assert mtimes["total"] == FILES and {i["kind"] for i in mtimes["items"]} == {"mtime"}
    mixed = await get(c, f"{url}/timeline", time="atime")
    assert mixed["total"] == FILES + EVENTS
    evtx = await get(c, f"{url}/timeline", artifact="evtx")
    assert evtx["total"] == 3 and {i["kind"] for i in evtx["items"]} == {"evtx"}
    window = await get(
        c, f"{url}/timeline", **{"from": "2026-10-01T08:55:00Z", "to": "2026-10-01T08:56:00Z"}
    )
    assert window["total"] > 0
    assert all("2026-10-01T08:55" <= i["ts"][:16] <= "2026-10-01T08:56" for i in window["items"])
    bad = {"from": "2026-10-02T00:00:00Z", "to": "2026-10-01T00:00:00Z"}
    assert (await c.get(f"{url}/timeline", params=bad)).status_code == 422
    assert (await c.get(f"{url}/timeline", params={"time": "btime"})).status_code == 422


async def test_fat_local_times_are_labelled() -> None:
    reg = await register(org_name="Disk Timeline FAT Org")
    t, job, url = await windows(reg)
    when = datetime(2001, 1, 1, 12, 0, tzinfo=UTC)  # before every fixture time
    await add_file(
        t, job, partition_index=1, path="FAT/OLD.TXT", mtime=when, time_basis="local_unknown"
    )
    c = reg.client
    first = (await get(c, f"{url}/timeline", limit=1))["items"][0]
    assert first["path"] == "FAT/OLD.TXT" and first["kind"] == "mtime"
    assert first["description"] == "Content Modification Time (local time, zone unknown)"
    assert (await get(c, f"{url}/timeline"))["total"] == ALL + 1
