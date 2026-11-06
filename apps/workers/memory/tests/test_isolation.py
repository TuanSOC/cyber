"""Container isolation of the memory analyzer (M8 phase 1), on top of the worker kit's
analyzer checks (`/packages/py-worker-kit/tests`, run in this image too). Run inside
`memory-worker-test`:

  scripts/lane-test.sh <lane> --service memory-worker-test pytest -q tests/test_isolation.py

The env holds only BROKER_URL (as the `memory` broker user) plus the image's non-secret
switches; the symbol store is mounted read-only; the tool uid is 10006 (RT18); the VSL licence
text and our notice are in the image; no forbidden dependency is importable.
"""

import importlib.util
import os
import socket
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    "BROKER_URL" not in os.environ, reason="runs inside the memory-worker container"
)
SECRET_HINTS = ("DATABASE", "MINIO", "JWT", "POSTGRES", "SECRET", "PASSWORD", "ACCESS_KEY")


def test_environment_holds_only_the_memory_broker_url() -> None:
    leaked = [name for name in os.environ if any(h in name.upper() for h in SECRET_HINTS)]
    assert leaked == []
    assert os.environ["BROKER_URL"].startswith("redis://memory:")
    assert os.environ["HOME"] == "/nonexistent"
    assert os.environ["XDG_CONFIG_HOME"] == "/nonexistent"


def test_the_tool_uid_is_its_own() -> None:
    from cyberlab_worker import sandbox

    assert (sandbox.TOOL_UID, sandbox.TOOL_GID) == (10006, 10006)


def test_the_symbol_store_is_read_only() -> None:
    store = Path("/symbols")
    assert store.is_dir()
    with pytest.raises(OSError):
        (store / "planted.json").write_text("{}")


@pytest.mark.parametrize("host", ["memory-symbols", "memory-symbols-test", "postgres", "api"])
def test_trusted_hosts_are_not_reachable(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


def test_the_vsl_license_text_and_notice_are_in_the_image() -> None:
    assert Path("/usr/share/doc/volatility3/LICENSE.txt").is_file()
    assert "Addition" in Path("/usr/share/doc/cyberlab-memory/NOTICE").read_text()


def test_no_forbidden_dependency_is_importable() -> None:
    for module in ("leechcorepyc", "Crypto", "PIL", "smb", "yara", "yara_x"):
        assert importlib.util.find_spec(module) is None, module
    # Read from the installed metadata: importing `volatility3.framework` would create its
    # cache dir under the unwritable HOME (the worker process never imports it).
    from importlib.metadata import version

    assert version("volatility3") == "2.28.2"
