"""Offline is set in code (RT7): `OFFLINE` and `REMOTE_ISF_URL`, an http(s) location raises
`OfflineException`, and with the audit hook installed the attempt is refused and counted.
Runs the real volatility3 in a child interpreter (its constants are process-global and its
import creates the cache dir under `XDG_CACHE_HOME`); skipped where it is not installed."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("volatility3")

APP = Path(__file__).resolve().parents[2]
CHILD = r"""
import json, sys
from pathlib import Path
from memory_worker.probe import vol
facts = vol.configure(Path(sys.argv[1]))
from volatility3.framework import constants, exceptions
from volatility3.framework.layers.resources import ResourceAccessor
out = {"facts": facts, "OFFLINE": constants.OFFLINE, "REMOTE": constants.REMOTE_ISF_URL}
for url in ("http://msdl.microsoft.com/download/symbols/x.pdb", "https://example.com/b.json"):
    try:
        ResourceAccessor().open(url)
        out[url] = "opened"
    except exceptions.OfflineException:
        out[url] = "offline"
    except Exception as exc:
        out[url] = type(exc).__name__
from memory_worker.probe.guard import GUARD
GUARD.install()
try:
    ResourceAccessor().open("http://msdl.microsoft.com/download/symbols/y.pdb")
    out["guarded"] = "opened"
except Exception as exc:
    out["guarded"] = type(exc).__name__
out["counts"] = GUARD.snapshot()
print(json.dumps(out))
"""


def run_child(script: str, store: Path, cache: Path) -> dict[str, object]:
    env = {
        **os.environ,
        "XDG_CACHE_HOME": str(cache),
        "PYTHONPATH": os.pathsep.join([str(APP), *sys.path]),
    }
    done = subprocess.run(
        [sys.executable, "-c", script, str(store)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    result: dict[str, object] = json.loads(done.stdout.strip().splitlines()[-1])
    return result


def test_offline_constants_and_http_refusal(tmp_path: Path) -> None:
    store = tmp_path / "symbols"
    store.mkdir()
    out = run_child(CHILD, store, tmp_path / "cache")
    assert out["OFFLINE"] is True and out["REMOTE"] is None
    assert out["http://msdl.microsoft.com/download/symbols/x.pdb"] == "offline"
    assert out["https://example.com/b.json"] == "offline"
    # With the hook in place the request never reaches urllib's handlers.
    assert out["guarded"] == "Refused"
    counts = out["counts"]
    assert isinstance(counts, dict) and counts["urllib"] == 1
    facts = out["facts"]
    assert isinstance(facts, dict) and facts["offline"] is True
