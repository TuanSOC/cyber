"""The userspace tools of the dev / test target (`docker/diskgen-packages.txt`), run without a
shell, a mount or any privilege. A missing tool raises `ToolMissing` (the caller lists the
image as skipped, never as built)."""

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence

from samples.diskgen import BASE_TIME


class ToolMissing(RuntimeError):
    def __init__(self, tool: str) -> None:
        super().__init__(f"{tool} not found (dev / test target only: docker/diskgen-packages.txt)")
        self.tool = tool


class ToolFailed(RuntimeError):
    pass


def have(*tools: str) -> bool:
    return all(shutil.which(t) is not None for t in tools)


def require(*tools: str) -> None:
    for tool in tools:
        if shutil.which(tool) is None:
            raise ToolMissing(tool)


def env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """A fixed environment: C.UTF-8, UTC and e2fsprogs' fake clock (mkfs / debugfs times)."""
    out = {
        "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        "LC_ALL": "C.UTF-8",  # ntfs-3g converts names with the locale
        "TZ": "UTC",
        "E2FSPROGS_FAKE_TIME": str(BASE_TIME),
        "SOURCE_DATE_EPOCH": str(BASE_TIME),
    }
    out.update(extra or {})
    return out


def run(
    argv: Sequence[str],
    *,
    stdin: bytes | None = None,
    extra_env: Mapping[str, str] | None = None,
    timeout: float = 300,
) -> str:
    return run_full(argv, stdin=stdin, extra_env=extra_env, timeout=timeout)[0]


def run_full(
    argv: Sequence[str],
    *,
    stdin: bytes | None = None,
    extra_env: Mapping[str, str] | None = None,
    timeout: float = 300,
) -> tuple[str, str]:
    """(stdout, stderr) of a tool that exited 0; `ToolFailed` otherwise."""
    require(argv[0])
    result = subprocess.run(
        list(argv),
        input=stdin,
        capture_output=True,
        env=env(extra_env),
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout)[-2000:].decode("utf-8", "replace")
        raise ToolFailed(f"{argv[0]} exited {result.returncode}: {tail}")
    return result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")
