"""The stages' resource limits (pure Python; RT3, RT4, RT13). Values are PROVISIONAL until the
phase-2 spike; these tests pin the rules, not the measured numbers."""

from re_worker.config import DEFAULT_DECOMPILE_JVM_HEAP, GIB, TOOL_AS_HEADROOM, load
from re_worker.engines.spec import JVM_NPROC, decompile_as, jvm_limits

PIDS_LIMIT = 512  # compose `pids_limit` of the re-worker


def test_cpu_limit_covers_every_jvm_thread() -> None:
    limits = jvm_limits(5 * GIB, 1800)
    assert limits.cpu_s == 2 * 1800 + 60  # RT3: RLIMIT_CPU sums all threads on 2 CPUs
    assert jvm_limits(5 * GIB, 0.4).cpu_s == 62  # a sub-second budget still gets a floor


def test_nproc_leaves_room_for_roots_kill_helper() -> None:
    limits = jvm_limits(5 * GIB, 60)
    assert limits.nproc == JVM_NPROC == 256
    assert limits.nproc <= PIDS_LIMIT - 64  # RT13
    assert limits.nofile == 4096 and limits.fsize_bytes == GIB


def test_decompile_jvm_is_never_larger_than_analyze() -> None:
    config = load({"BROKER_URL": "redis://x"})
    as_bytes = decompile_as(config.tool_rlimit_as, config.decompile_jvm_heap, TOOL_AS_HEADROOM)
    assert as_bytes == DEFAULT_DECOMPILE_JVM_HEAP + TOOL_AS_HEADROOM
    assert as_bytes <= config.tool_rlimit_as
    assert decompile_as(2 * GIB, GIB, TOOL_AS_HEADROOM) == 2 * GIB
    # RT4: the native child is lowered below the JVM's own limit.
    assert config.decompiler_as < as_bytes
