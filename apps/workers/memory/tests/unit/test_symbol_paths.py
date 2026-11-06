"""Symbol paths (RT2): exactly the store, then Volatility's two read-only built-in dirs; the
writable cache fallback is gone (no PDB conversion can be written anywhere), and the bundled
tables plugins need (PE, netscan, bash) still resolve through the list. Real volatility3 in
a child interpreter; skipped where it is not installed."""

import os
from pathlib import Path

import pytest

pytest.importorskip("volatility3")

from tests.unit.test_offline import run_child  # noqa: E402

CHILD = r"""
import json, sys
from pathlib import Path
from memory_worker.probe import vol
vol.configure(Path(sys.argv[1]))
import volatility3.symbols
from volatility3.framework import constants
from volatility3.framework.symbols.intermed import IntermediateSymbolTable as T
print(json.dumps({
    "paths": list(volatility3.symbols.__path__),
    "base": list(constants.SYMBOL_BASEPATHS),
    "builtin": vol.builtin_symbol_dirs(),
    "cache": constants.CACHE_PATH,
    "pe": list(T.file_symbol_url("windows", "pe")),
    "netscan": list(T.file_symbol_url("windows/netscan", "netscan-win81-x64")),
    "bash": list(T.file_symbol_url("linux", "bash64")),
}))
"""


def test_paths_are_the_store_then_the_builtin_dirs(tmp_path: Path) -> None:
    store = tmp_path / "symbols"
    (store / "windows").mkdir(parents=True)
    out = run_child(CHILD, store, tmp_path / "cache")
    builtin = out["builtin"]
    assert isinstance(builtin, list)
    assert out["paths"] == [str(store), *builtin] == out["base"]
    assert builtin[0].endswith("/volatility3/symbols")
    assert builtin[1].endswith("/volatility3/framework/symbols")
    cache = str(out["cache"])
    assert not any(str(p).startswith(cache) for p in out["paths"])  # type: ignore[union-attr]
    for table in ("pe", "netscan", "bash"):
        urls = out[table]
        assert isinstance(urls, list) and urls, table
        assert all("/volatility3/framework/symbols/" in u for u in urls), table


def test_site_packages_is_not_writable_by_the_tool_uid() -> None:
    import volatility3

    site = Path(volatility3.__file__).resolve().parents[1]
    info = os.stat(site)
    assert info.st_uid == 0 and not info.st_mode & 0o022
