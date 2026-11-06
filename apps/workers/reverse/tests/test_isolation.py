"""Container isolation of the RE analyzer (M10 phase 1), on top of the worker kit's analyzer
checks (`/packages/py-worker-kit/tests`, run in this image too). Run inside `re-worker-test`:

  scripts/lane-test.sh <lane> --service re-worker-test pytest -q tests/test_isolation.py

The env holds only BROKER_URL (as the `reverse` broker user) plus the image's non-secret
switches; the tool uid is 10010; the JVM option variables are absent (RT19); Ghidra, the JDK
and radare2 are the pinned versions; the license texts and our notice are in the image; r2pipe
and Jython are not importable.
"""

import importlib.util
import json
import os
import socket
from pathlib import Path

import pytest

from re_worker import jvm_args

pytestmark = pytest.mark.skipif(
    "BROKER_URL" not in os.environ, reason="runs inside the re-worker container"
)
SECRET_HINTS = ("DATABASE", "MINIO", "JWT", "POSTGRES", "SECRET", "PASSWORD", "ACCESS_KEY")
VERSIONS = Path("/etc/cyberlab/versions.json")


def test_environment_holds_only_the_reverse_broker_url() -> None:
    leaked = [name for name in os.environ if any(h in name.upper() for h in SECRET_HINTS)]
    assert leaked == []
    assert os.environ["BROKER_URL"].startswith("redis://reverse:")
    assert os.environ["HOME"] == "/nonexistent"
    assert os.environ["XDG_CONFIG_HOME"] == "/nonexistent"
    assert os.environ["JAVA_HOME"] == "/opt/java/openjdk"
    assert os.environ["GHIDRA_INSTALL_DIR"] == "/opt/ghidra"


def test_no_jvm_option_variable_is_set() -> None:
    """RT19: nothing outside our argument list can reach the JVM."""
    assert [name for name in jvm_args.FORBIDDEN_ENV if name in os.environ] == []


def test_the_tool_uid_is_its_own() -> None:
    from cyberlab_worker import sandbox

    assert (sandbox.TOOL_UID, sandbox.TOOL_GID) == (10010, 10010)


@pytest.mark.parametrize("host", ["postgres", "api", "minio", "ingest-worker"])
def test_trusted_hosts_are_not_reachable(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


def test_pinned_versions_are_recorded() -> None:
    versions = json.loads(VERSIONS.read_text())
    assert versions["ghidra"] == "12.2"
    assert versions["jdk"].split(".")[0] == "25"
    assert versions["pyghidra"].startswith("3.2")
    assert versions["radare2"].startswith("6.2.6")
    for key in ("ghidra_zip_sha256", "radare2_deb_sha256", "launch_properties_sha256"):
        assert len(versions[key]) == 64, key


def test_launch_properties_are_ours() -> None:
    text = Path("/opt/ghidra/support/launch.properties").read_text()
    assert jvm_args.parse_launch_properties(text) == list(jvm_args.LAUNCH_PROPERTIES_VMARGS)


def test_install_trees_are_not_writable() -> None:
    for root in ("/opt/ghidra", "/opt/java/openjdk", "/opt/re/r2"):
        info = Path(root).stat()
        assert info.st_uid == 0 and not info.st_mode & 0o022, root
    assert oct(Path("/opt/re/r2/quick.r2").stat().st_mode & 0o777) == "0o444"


def test_trimmed_parts_are_absent() -> None:
    ghidra = Path("/opt/ghidra")
    for part in ("server", "Ghidra/Features/Jython", "Ghidra/Debug"):
        assert not (ghidra / part).exists(), part
    assert {p.name for p in (ghidra / "Ghidra/Processors").iterdir()} == {"x86", "DATA"}


def test_licenses_and_notice_are_in_the_image() -> None:
    doc = Path("/usr/share/doc/cyberlab-re")
    assert (doc / "licenses").is_dir()
    assert "Modification notice" in (doc / "NOTICE").read_text()


def test_no_forbidden_module_is_importable() -> None:
    for module in ("r2pipe", "jython"):
        assert importlib.util.find_spec(module) is None, module
