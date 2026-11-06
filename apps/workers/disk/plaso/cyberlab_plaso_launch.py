"""`/opt/plaso/bin/python -I -m cyberlab_plaso_launch <log2timeline|psort> [args...]`
(M9 phase 3, RT11 / RT24).

Installed into /opt/plaso as a single module (under `-I` that interpreter cannot see the
worker's `disk_worker` package), run as the tool uid by `stage.run_stage` under seccomp
(AF_UNIX only, no io_uring). In order:
1. refuses to run unless the interpreter is isolated (`-I`: no user site, no PYTHON* env, no
   cwd on `sys.path`) and bytecode writing is off;
2. checks the argv against the fixed shape root builds (`disk_worker.timeline.flags`): only
   `log2timeline` with `--single_process`, only `psort` with `-o json_line` and no analysis
   plugin or network output; anything else exits 2 before Plaso is imported;
3. installs the PEP 578 audit hook **before** Plaso is imported, refusing (raising into the
   caller) and counting per family: `socket.*`, `urllib.Request`, `subprocess.Popen`,
   `os.exec*`, `os.posix_spawn*` / `os.spawn*`, `os.system`, `os.fork` / `os.forkpty` (every
   `multiprocessing` start method goes through one of them);
4. calls the Plaso tool's `Main()` with `sys.argv` set to the tool's argv;
5. writes `status.json` into the stage's out dir (`TMPDIR`, set by `run_stage`), always:
   `status`, `error` (exception class name only), `error_code` (`timeline_failed`), `rows`
   (psort: the exported lines), `audit` (the counts; root copies them into the stage report
   and the engine tests assert zero).

Exit codes: 0 ok, 2 usage / refused argv, 4 the tool failed.

Seccomp stays the enforcing layer: the hook only sees Python-level events (a C extension's own
socket call is refused by the filter, not counted here).
"""

import importlib
import json
import os
import sys
from collections.abc import Callable
from typing import Any

EXIT_OK, EXIT_USAGE, EXIT_FAILED = 0, 2, 4
STATUS = "status.json"
TOOLS = {"log2timeline": "plaso.scripts.log2timeline", "psort": "plaso.scripts.psort"}
FAMILIES = ("socket", "urllib", "subprocess", "exec", "spawn", "system", "fork")
# Options never accepted, whatever the tool: analysis plugins (virustotal, nsrlsvr are network
# clients), network outputs and storage (opensearch, redis), multi-process workers.
FORBIDDEN_PREFIXES = (
    "--analysis",
    "--opensearch",
    "--elastic",
    "--redis",
    "--server",
    "--port",
    "--workers",
    "--worker_",
    "--use_zeromq",
    "--profilers",
)
MAX_COUNT_BYTES = 8 * 1024**3
AuditHook = Callable[[str, tuple[Any, ...]], None]


class Refused(RuntimeError):
    """Raised into the caller of a refused operation."""


class Guard:
    def __init__(self, add_hook: Callable[[AuditHook], None] = sys.addaudithook) -> None:
        self.counts: dict[str, int] = dict.fromkeys(FAMILIES, 0)
        self.installed = False
        self._add_hook = add_hook  # tests pass a fake: a real hook can never be removed

    @staticmethod
    def family(event: str) -> str | None:
        if event.startswith("socket."):
            return "socket"
        if event == "urllib.Request":
            return "urllib"
        if event == "subprocess.Popen":
            return "subprocess"
        if event == "os.exec":
            return "exec"
        if event in ("os.posix_spawn", "os.spawn"):
            return "spawn"
        if event == "os.system":
            return "system"
        if event in ("os.fork", "os.forkpty"):
            return "fork"
        return None

    def hook(self, event: str, args: tuple[Any, ...]) -> None:
        family = self.family(event)
        if family is not None:
            self.counts[family] += 1
            raise Refused(f"{event} refused in the Plaso sandbox")

    def install(self) -> None:
        if not self.installed:
            self._add_hook(self.hook)
            self.installed = True

    def snapshot(self) -> dict[str, int]:
        return dict(self.counts)


def _value(args: list[str], flag: str) -> str | None:
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


def check_argv(tool: str, args: list[str]) -> str | None:
    """None when the argv has the fixed shape, else the refusal reason."""
    if tool not in TOOLS:
        return "unknown_tool"
    for arg in args:
        if arg.startswith(FORBIDDEN_PREFIXES):
            return "forbidden_option"
    if tool == "log2timeline":
        if "--single_process" not in args:
            return "not_single_process"
        if _value(args, "--storage_file") is None:
            return "no_storage_file"
    if tool == "psort":
        output = _value(args, "-o") or _value(args, "--output_format")
        if output != "json_line" or sum(a in ("-o", "--output_format") for a in args) != 1:
            return "not_json_line"
        if _value(args, "-w") is None:
            return "no_output_file"
    return None


def isolated() -> bool:
    return bool(sys.flags.isolated and sys.flags.no_user_site and sys.flags.ignore_environment)


def count_lines(path: str | None) -> int:
    """Newlines in the tool's output file (bounded; 0 when absent)."""
    if not path:
        return 0
    lines = total = 0
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return 0
    with os.fdopen(fd, "rb") as f:
        while (chunk := f.read(1024 * 1024)) and total < MAX_COUNT_BYTES:
            total += len(chunk)
            lines += chunk.count(b"\n")
    return lines


def write_status(out_dir: str | None, doc: dict[str, Any]) -> None:
    if not out_dir:
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.path.join(out_dir, STATUS), flags, 0o600)
    except OSError:
        return
    with os.fdopen(fd, "w", encoding="ascii") as f:
        json.dump(doc, f, ensure_ascii=True, allow_nan=False)


def _prepare_temporary(args: list[str]) -> None:
    tmp = _value(args, "--temporary_directory")
    if tmp:
        os.makedirs(tmp, mode=0o700, exist_ok=True)


def run(
    tool: str,
    args: list[str],
    guard: Guard,
    load: Callable[[str], Any] = importlib.import_module,
) -> tuple[int, dict[str, Any]]:
    """Run one Plaso tool under the guard; returns (exit code, status document)."""
    status: dict[str, Any] = {"stage": tool, "status": "failed", "rows": 0}
    reason = check_argv(tool, args)
    if reason is not None:
        status.update(error="Usage", error_code="timeline_failed", reason=reason)
        return EXIT_USAGE, status
    guard.install()
    code = EXIT_FAILED
    try:
        _prepare_temporary(args)
        module = load(TOOLS[tool])
        sys.argv = [f"{tool}.py", *args]
        try:
            ok = bool(module.Main())
        except SystemExit as exc:
            ok = exc.code in (0, None)
        if ok:
            code = EXIT_OK
            status["status"] = "ok"
        else:
            status.update(error="ToolFailed", error_code="timeline_failed", reason="tool_failed")
    except Exception as exc:  # noqa: BLE001 - reported by class name only, never the message
        status.update(error=type(exc).__name__[:64], error_code="timeline_failed")
    if tool == "psort":
        status["rows"] = count_lines(_value(args, "-w"))
    status["audit"] = guard.snapshot()
    return code, status


def main(argv: list[str]) -> int:
    out_dir = os.environ.get("TMPDIR")
    if not argv:
        print("usage: cyberlab_plaso_launch <log2timeline|psort> [args...]", file=sys.stderr)
        return EXIT_USAGE
    if not isolated():
        write_status(out_dir, {"status": "failed", "error": "NotIsolated", "reason": "isolation"})
        return EXIT_USAGE
    sys.dont_write_bytecode = True
    code, status = run(argv[0], argv[1:], Guard())
    write_status(out_dir, status)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
