"""`reindex` (M8 phase 5, RT5): only at `/symbols`, every cached location starts with
`file:///symbols/`, the cache is swapped in atomically; with Volatility installed (the
image), the real indexer runs offline over a temp store."""

import importlib.util
import sqlite3
from pathlib import Path

import pytest

from memory_worker.symbols import reindex as rx
from memory_worker.symbols.manifest import CACHE_FILE, StoreWriter
from tests.symbols_helpers import dumps, linux_isf, new_store, put, windows_isf, xz


def _cache(path: Path, locations: list[str]) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cache (location TEXT UNIQUE NOT NULL, identifier TEXT)")
    conn.execute("CREATE TABLE database_info (db_version INT)")
    conn.executemany("INSERT INTO cache (location) VALUES (?)", [(x,) for x in locations])
    conn.commit()
    conn.close()


def test_the_prefix_of_the_real_store() -> None:
    assert rx.location_prefix(Path("/symbols")) == "file:///symbols/"


def test_reindex_refuses_any_root_but_symbols(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    with pytest.raises(rx.ReindexRefused, match="/symbols"):
        rx.reindex(root, indexer=lambda *_: pytest.fail("must not index"))


def test_check_cache_counts_locations(tmp_path: Path) -> None:
    cache = tmp_path / "c"
    _cache(cache, ["file:///symbols/linux/a.json.xz", "file:///symbols/windows/x/y.json.xz"])
    assert rx.check_cache(cache, Path("/symbols")) == 2


@pytest.mark.parametrize(
    "bad",
    [
        "file:///symbols-test/linux/a.json.xz",
        "file:///usr/lib/python3/volatility3/framework/symbols/windows/x.json",
        "https://example.invalid/isf/banners.json",
        "file:///symbolsx/a.json",
        "file:/symbols/a.json",
    ],
)
def test_check_cache_refuses_a_location_outside_the_store(tmp_path: Path, bad: str) -> None:
    cache = tmp_path / "c"
    _cache(cache, ["file:///symbols/linux/a.json.xz", bad])
    with pytest.raises(rx.ReindexRefused, match="outside file:///symbols/"):
        rx.check_cache(cache, Path("/symbols"))


def test_reindex_installs_the_checked_cache(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    prefix = rx.location_prefix(root.absolute())
    calls: list[Path] = []

    def indexer(store: Path, cache: Path, work: Path) -> None:
        calls.append(store)
        assert root.absolute() not in cache.parents  # built outside the store it walks
        _cache(cache, [prefix + "linux/a.json.xz", prefix + "manifest.json"])

    count = rx.reindex(root, required_root=root.absolute(), indexer=indexer)
    assert count == 2 and calls == [root.absolute()]
    assert rx.cache_locations(root / CACHE_FILE) == [
        prefix + "linux/a.json.xz",
        prefix + "manifest.json",
    ]
    assert not (root / ".staging").exists()


def test_a_bad_cache_is_never_installed(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    _cache(root / CACHE_FILE, [rx.location_prefix(root.absolute()) + "old.json"])
    before = (root / CACHE_FILE).read_bytes()

    def indexer(store: Path, cache: Path, work: Path) -> None:
        _cache(cache, ["file:///elsewhere/x.json"])

    with pytest.raises(rx.ReindexRefused):
        rx.reindex(root, required_root=root.absolute(), indexer=indexer)
    assert (root / CACHE_FILE).read_bytes() == before
    with pytest.raises(rx.ReindexRefused, match="no cache"):
        rx.reindex(root, required_root=root.absolute(), indexer=lambda *_: None)


def test_reindex_holds_the_store_lock(tmp_path: Path) -> None:
    pytest.importorskip("fcntl")
    root = new_store(tmp_path)
    with StoreWriter(root), pytest.raises(Exception, match="lock"):
        rx.reindex(root, required_root=root.absolute(), indexer=lambda *_: None)


@pytest.mark.skipif(
    importlib.util.find_spec("volatility3") is None,
    reason="volatility3 is not installed on this interpreter (runs in the image)",
)
def test_the_real_indexer_records_only_store_locations(tmp_path: Path) -> None:
    """Volatility 2.28.2's own indexer in the isolated child, offline, over a temp store:
    every recorded location is under the store root (RT5; at /symbols in production)."""
    from cyberlab_jobs.memory import LinuxBanner, WindowsPdb

    root = new_store(tmp_path)
    banner = "Linux version 6.1.0-test"
    put(root, LinuxBanner(banner=banner), xz(dumps(linux_isf(banner))))
    pdb = WindowsPdb(name="ntkrnlmp.pdb", guid="A" * 32, age=1)
    put(root, pdb, xz(dumps(windows_isf(guid="A" * 32))))
    count = rx.reindex(root, required_root=root.absolute())
    locations = rx.cache_locations(root / CACHE_FILE)
    assert count == len(locations) >= 2
    assert all(loc.startswith(rx.location_prefix(root.absolute())) for loc in locations)
