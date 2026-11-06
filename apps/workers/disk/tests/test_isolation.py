"""Container isolation of the disk analyzer (M9 phase 1), on top of the worker kit's analyzer
checks (`/packages/py-worker-kit/tests`, run in this image too). Run inside `disk-worker-test`:

  scripts/lane-test.sh <lane> --service disk-worker-test pytest -q tests/test_isolation.py

The env holds only BROKER_URL (as the `disk` broker user) plus the image's non-secret switches;
the hash-set store is mounted read-only; the tool uid is 10007 (RT27); the license texts, the
NOTICE and the pins are in the image; no Debian TSK package or binary is present.
"""

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    "BROKER_URL" not in os.environ, reason="runs inside the disk-worker container"
)
SECRET_HINTS = ("DATABASE", "MINIO", "JWT", "POSTGRES", "SECRET", "PASSWORD", "ACCESS_KEY")


def test_environment_holds_only_the_disk_broker_url() -> None:
    leaked = [name for name in os.environ if any(h in name.upper() for h in SECRET_HINTS)]
    assert leaked == []
    assert os.environ["BROKER_URL"].startswith("redis://disk:")
    assert os.environ["HOME"] == "/nonexistent"
    assert os.environ["XDG_CONFIG_HOME"] == "/nonexistent"


def test_the_tool_uid_is_its_own() -> None:
    from cyberlab_worker import sandbox

    assert (sandbox.TOOL_UID, sandbox.TOOL_GID) == (10007, 10007)


def test_the_hashset_store_is_read_only() -> None:
    store = Path("/hashsets")
    assert store.is_dir()
    with pytest.raises(OSError):
        (store / "planted.json").write_text("{}")


@pytest.mark.parametrize("host", ["disk-hashsets", "postgres", "api", "minio-console"])
def test_trusted_hosts_are_not_reachable(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


def test_notice_licenses_and_versions_are_in_the_image() -> None:
    assert "IBM Public License" in Path("/usr/share/doc/cyberlab-disk/NOTICE").read_text()
    assert any(Path("/usr/share/doc/cyberlab-disk/licenses").iterdir())
    versions = json.loads(Path("/etc/cyberlab/versions.json").read_text())
    assert versions["pytsk3"] == "20260715"
    assert versions["libewf-python"] == "20260924"
    assert versions["plaso"] == "20261027"
    assert versions["tsk"].startswith("4.15")


def test_no_debian_tsk_is_present() -> None:
    for binary in ("fls", "icat", "mmls", "srch_strings"):
        assert shutil.which(binary) is None, binary


def test_plaso_lives_in_its_own_venv_and_the_launcher_imports_under_isolation() -> None:
    out = subprocess.run(
        ["/opt/plaso/bin/python", "-I", "-c", "import cyberlab_plaso_launch, plaso; print(1)"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    worker = subprocess.run(
        ["python", "-I", "-c", "import plaso"], capture_output=True, check=False
    )
    assert worker.returncode != 0  # Plaso never mixes with the worker venv


def test_the_baked_rules_match_the_allow_list() -> None:
    import hashlib

    from cyberlab_worker.yara_rules import BASELINE_SHA256

    rules = Path("/opt/rules/image/cyberlab_baseline.yar")
    assert hashlib.sha256(rules.read_bytes()).hexdigest() == BASELINE_SHA256
    with pytest.raises(OSError):
        rules.write_text("planted")
