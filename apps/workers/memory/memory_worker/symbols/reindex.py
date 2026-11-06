"""`memory-symbols reindex`: rebuild Volatility's identifier cache for the store (RT5).

Volatility's `identifier.cache` (a SQLite file) records absolute `file://` locations, so it is
only valid where it was built. The worker mounts every store at `/symbols`, hence `reindex`
refuses to run unless its store root is exactly `/symbols` (`--store test` runs a compose
variant that mounts the test store there too) and refuses to install a cache holding any
location outside `file:///symbols/`.

The indexer runs offline in a child process (`isolate.task_reindex`: Volatility with
`OFFLINE = True`, no remote ISF URL, the store as its only symbol path) and writes into a
temp dir under /tmp; the checked file is copied to the store's staging dir and swapped in
atomically at
`.cache/volatility3/identifier.cache`. The worker copies it per plugin into a fresh
`XDG_CACHE_HOME` (phase 2).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote
from urllib.request import pathname2url

from memory_worker.symbols import isolate
from memory_worker.symbols.manifest import Logger, StoreWriter, no_log

REQUIRED_ROOT = Path("/symbols")
REINDEX_TIMEOUT_S = 3600.0
MAX_LOCATIONS = 1_000_000

# (store root, cache file to create) -> None; the default runs Volatility in a child.
Indexer = Callable[[Path, Path, Path], None]


class ReindexRefused(RuntimeError):
    pass


def location_prefix(root: Path) -> str:
    """`file:///symbols/` for the real store (as Volatility writes `file://` + path)."""
    if os.name != "posix":  # host test runs only: a consistent form for a drive path
        return "file://" + quote(root.as_posix()).rstrip("/") + "/"
    return "file://" + pathname2url(str(root)).rstrip("/") + "/"


def cache_locations(cache: Path) -> list[str]:
    """Every location recorded in an identifier cache: each table with a `location` column
    (2.28.2 keeps them in `cache`), read through a read-only SQLite URI."""
    uri = "file:" + pathname2url(str(cache)) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        tables = [
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        ]
        locations: list[str] = []
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in conn.execute(f"PRAGMA table_info({quoted})")]
            if "location" not in columns:
                continue
            for (location,) in conn.execute(f"SELECT location FROM {quoted}"):  # noqa: S608
                locations.append(str(location))
                if len(locations) > MAX_LOCATIONS:
                    raise ReindexRefused("the identifier cache holds too many locations")
        return locations
    finally:
        conn.close()


def check_cache(cache: Path, root: Path) -> int:
    """Refuse a cache with any location outside the store (RT5); returns the count."""
    prefix = location_prefix(root)
    locations = cache_locations(cache)
    outside = [loc for loc in locations if not loc.startswith(prefix)]
    if outside:
        sample = isolate.safe_text(outside[0], 160)
        raise ReindexRefused(
            f"{len(outside)} cached location(s) outside {prefix} (e.g. {sample}): refusing"
        )
    return len(locations)


def volatility_indexer(root: Path, cache: Path, work: Path) -> None:
    try:
        isolate.run_child(
            "reindex",
            {"root": str(root), "cache": str(cache)},
            work,
            timeout_s=REINDEX_TIMEOUT_S,
        )
    except isolate.ChildFailed as exc:
        raise ReindexRefused(str(exc)) from exc


def reindex(
    root: Path,
    *,
    required_root: Path = REQUIRED_ROOT,
    indexer: Indexer = volatility_indexer,
    log: Logger = no_log,
) -> int:
    """Rebuild and atomically install the identifier cache; returns the location count."""
    absolute = Path(os.path.abspath(root))
    if absolute != required_root:
        raise ReindexRefused(
            f"reindex runs only with the store mounted at {required_root.as_posix()} (the "
            "cache records absolute locations; RT5)"
        )
    with StoreWriter(absolute, log=log) as writer, tempfile.TemporaryDirectory() as tmp:
        # The indexer works in /tmp, never inside the store it walks (its params file and
        # the half-built cache must not become store locations).
        work = Path(tmp)
        built = work / "identifier.cache"
        indexer(absolute, built, work)
        if not built.is_file() or built.is_symlink():
            raise ReindexRefused("the indexer produced no cache")
        count = check_cache(built, absolute)
        staged = writer.work_dir("reindex") / "identifier.cache"
        shutil.copyfile(built, staged)
        if check_cache(staged, absolute) != count:
            raise ReindexRefused("the cache changed while it was copied")
        writer.install_cache(staged)
    log("reindexed", locations=count, cache=".cache/volatility3/identifier.cache")
    return count
