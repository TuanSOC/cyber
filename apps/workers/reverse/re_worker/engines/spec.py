"""What one stage process gets (M10 phases 2 and 3): argv, environment and resource limits.

Pure Python (no kit import), so the values are unit-tested on any host (`test_rlimits.py`,
`test_jvm_args.py`); `engines/ghidra.py` (and phase 3's `engines/r2.py`) turn a
`StageSpec` into one `sandbox.run_tool` call (uid 10010, seccomp AF_UNIX only + no io_uring,
a fresh out dir, cwd = the root-owned input dir).

Limits (PROVISIONAL until the phase-2 spike reports; the spike notes record the measured
values and the parent applies them here):
- JVM stages (`analyze`, `decompile`): RLIMIT_AS = `RE_TOOL_RLIMIT_AS` for `analyze`, the
  decompile heap + the same headroom (never more) for `decompile`; RLIMIT_CPU =
  `jvm_args.cpu_limit_s(stage timeout)` = 2 x t + 60 (RT3: it sums every JVM thread);
  RLIMIT_NPROC 256 (below `pids_limit` 512, so root can always fork its kill helper, RT13);
  RLIMIT_NOFILE 4096; RLIMIT_FSIZE 1 GiB (one file; the disk watchdog bounds the job, RT5).
- radare2 (`r2`, phase 3): RLIMIT_AS 1 GiB, CPU 2 x t, NPROC 64, NOFILE 1024, FSIZE 256 MiB
  (its stdout `r2.out`; a cut file is `truncated.r2_output`); the radare2 reducer probe:
  RLIMIT_AS 2 GiB (one JSON section of <= 64 MiB parsed at a time), CPU = t, NPROC 16,
  NOFILE 256, FSIZE 512 MiB.

Environment: the kit sets `PATH`, `LANG`, `HOME` / `XDG_CONFIG_HOME` / `TMPDIR` = the out
dir; a JVM stage overrides them with fresh subdirs root created in its out dir and adds
`JAVA_HOME`, `GHIDRA_INSTALL_DIR`, `MALLOC_ARENA_MAX=2`. Nothing is inherited from the
worker's own environment, so `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`,
`DEBUGINFOD_URLS` and `CLASSPATH` can never reach a stage (RT19, asserted by
`assert_clean_env`).
"""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from re_worker import jvm_args

KIB = 1024
MIB = 1024**2
GIB = 1024**3
PROBE_MODULE = "re_worker.probe"
# Subdirectories root creates (tool-owned 0700) in a JVM stage's fresh out dir.
JVM_SUBDIRS = ("home", "tmp", "xdg", "xdg/config", "xdg/cache")
JVM_NPROC = 256
JVM_NOFILE = 4096
JVM_FSIZE = 1 * GIB
R2_BINARY = Path("/usr/bin/radare2")
R2_AS = 1 * GIB
R2_NPROC = 64
R2_NOFILE = 1024
R2_MAX_OUTPUT_BYTES = 256 * MIB  # RE_R2_MAX_OUTPUT_BYTES (= its RLIMIT_FSIZE)
R2_OUTPUT = "r2.out"
REDUCER_AS = 2 * GIB
REDUCER_NPROC = 16
REDUCER_NOFILE = 256
REDUCER_FSIZE = 512 * MIB
ROWS = "rows.jsonl"
STATUS = "status.json"
DECOMPILE_LIST = "decompile_list.json"


@dataclass(frozen=True)
class Limits:
    """The values of one `sandbox.Rlimits` (kept here as plain ints for the unit tests)."""

    as_bytes: int
    cpu_s: int
    nproc: int
    nofile: int
    fsize_bytes: int


@dataclass(frozen=True)
class StageSpec:
    name: str  # also the out dir's name: `<root>/<name>-out`
    argv: tuple[str, ...]
    env: dict[str, str]
    limits: Limits
    timeout_s: float
    stdout_name: str
    subdirs: tuple[str, ...] = ()
    heap_bytes: int | None = None  # JVM stages: the -Xmx the probe passes
    step: str = ""  # one of several processes sharing the out dir (radare2); default `name`

    @property
    def key(self) -> str:
        """The process's name (the replay engine's file names)."""
        return self.step or self.name


class UnsafeEnvironment(ValueError):
    pass


def assert_clean_env(env: dict[str, str]) -> None:
    """RT19: no JVM option variable (and no debuginfod URL) ever reaches a stage."""
    present = sorted(set(env) & set(jvm_args.FORBIDDEN_ENV))
    if present:
        raise UnsafeEnvironment(f"forbidden variables in a stage environment: {present}")


def jvm_env(out: PurePosixPath, java_home: Path, ghidra_dir: Path) -> dict[str, str]:
    env = {
        "JAVA_HOME": str(java_home),
        "GHIDRA_INSTALL_DIR": str(ghidra_dir),
        "MALLOC_ARENA_MAX": "2",
        "HOME": str(out / "home"),
        "TMPDIR": str(out / "tmp"),
        "XDG_CONFIG_HOME": str(out / "xdg" / "config"),
        "XDG_CACHE_HOME": str(out / "xdg" / "cache"),
    }
    assert_clean_env(env)
    return env


def jvm_limits(as_bytes: int, timeout_s: float) -> Limits:
    return Limits(
        as_bytes=as_bytes,
        cpu_s=jvm_args.cpu_limit_s(max(1, int(timeout_s))),
        nproc=JVM_NPROC,
        nofile=JVM_NOFILE,
        fsize_bytes=JVM_FSIZE,
    )


def decompile_as(tool_rlimit_as: int, decompile_heap: int, headroom: int) -> int:
    """The decompile JVM's RLIMIT_AS: its smaller heap + the headroom, never above the
    analyze stage's (RT4: the native child is then lowered to RE_DECOMPILER_AS by prlimit)."""
    return min(tool_rlimit_as, decompile_heap + headroom)


def _probe(python: str, *args: str) -> tuple[str, ...]:
    return (python, "-I", "-s", "-B", "-m", PROBE_MODULE, *args)


def analyze_spec(
    *,
    python: str,
    out: PurePosixPath,
    sample: PurePosixPath,
    loader: str,
    project: PurePosixPath,
    heap: int,
    as_bytes: int,
    timeout_s: float,
    analysis_timeout_s: int,
    caps: dict[str, int],
    java_home: Path,
    ghidra_dir: Path,
) -> StageSpec:
    cap_args = [a for kind, n in sorted(caps.items()) for a in (f"--max-{kind}", str(n))]
    argv = _probe(
        python, "analyze",
        "--sample", str(sample), "--loader", loader, "--project", str(project),
        "--out", str(out), "--heap", str(heap), "--analysis-timeout", str(analysis_timeout_s),
        *cap_args,
    )  # fmt: skip
    return StageSpec(
        name="analyze",
        argv=argv,
        env=jvm_env(out, java_home, ghidra_dir),
        limits=jvm_limits(as_bytes, timeout_s),
        timeout_s=timeout_s,
        stdout_name=ROWS,
        subdirs=JVM_SUBDIRS,
        heap_bytes=heap,
    )


def decompile_spec(
    *,
    python: str,
    out: PurePosixPath,
    project: PurePosixPath,
    listing: PurePosixPath,
    heap: int,
    as_bytes: int,
    timeout_s: float,
    java_home: Path,
    ghidra_dir: Path,
) -> StageSpec:
    argv = _probe(
        python, "decompile",
        "--project", str(project), "--out", str(out), "--heap", str(heap),
        "--list", str(listing),
    )  # fmt: skip
    return StageSpec(
        name="decompile",
        argv=argv,
        env=jvm_env(out, java_home, ghidra_dir),
        limits=jvm_limits(as_bytes, timeout_s),
        timeout_s=timeout_s,
        stdout_name=ROWS,
        subdirs=JVM_SUBDIRS,
        heap_bytes=heap,
    )


def r2_spec(*, script: Path, sample: PurePosixPath, timeout_s: float) -> StageSpec:
    """RT9: one non-interactive run of the fixed, root-owned script; no command is ever built
    from binary-derived data. `-NN`: no rc files, no plugins; `-S`: radare2's own sandbox (a
    second layer only); `-2`: stderr closed; `-q`: quit after the script."""
    argv = (str(R2_BINARY), "-q", "-NN", "-S", "-2", "-i", str(script), str(sample))
    return StageSpec(
        name="r2",
        argv=argv,
        env={},
        limits=Limits(
            as_bytes=R2_AS,
            cpu_s=2 * max(1, int(timeout_s)),
            nproc=R2_NPROC,
            nofile=R2_NOFILE,
            fsize_bytes=R2_MAX_OUTPUT_BYTES,
        ),
        timeout_s=timeout_s,
        stdout_name=R2_OUTPUT,
    )


def reducer_spec(
    *, python: str, out: PurePosixPath, timeout_s: float, caps: dict[str, int]
) -> StageSpec:
    """The reducer probe, in the same out dir as the radare2 run (same uid)."""
    cap_args = [a for kind, n in sorted(caps.items()) for a in (f"--max-{kind}", str(n))]
    argv = _probe(python, "r2", "--input", str(out / R2_OUTPUT), "--out", str(out), *cap_args)
    return StageSpec(
        name="r2",
        argv=argv,
        env={},
        limits=Limits(
            as_bytes=REDUCER_AS,
            cpu_s=max(1, int(timeout_s)),
            nproc=REDUCER_NPROC,
            nofile=REDUCER_NOFILE,
            fsize_bytes=REDUCER_FSIZE,
        ),
        timeout_s=timeout_s,
        stdout_name=ROWS,
        step="r2_reduce",
    )


__all__ = [
    "DECOMPILE_LIST",
    "PROBE_MODULE",
    "R2_BINARY",
    "R2_MAX_OUTPUT_BYTES",
    "R2_OUTPUT",
    "JVM_SUBDIRS",
    "ROWS",
    "STATUS",
    "Limits",
    "StageSpec",
    "UnsafeEnvironment",
    "analyze_spec",
    "assert_clean_env",
    "decompile_as",
    "decompile_spec",
    "jvm_env",
    "jvm_limits",
    "r2_spec",
    "reducer_spec",
]
