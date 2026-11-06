"""Worker settings (pure Python): the replay engine is refused outside the test profile, the
JVM heaps and the decompiler child's address space are bounded and ordered (RT4)."""

import pytest

from re_worker.config import (
    DEFAULT_DECOMPILE_JVM_HEAP,
    DEFAULT_DECOMPILER_AS,
    DEFAULT_JVM_HEAP,
    GIB,
    TOOL_AS_HEADROOM,
    ConfigError,
    load,
)

BASE = {"BROKER_URL": "redis://reverse:x@redis-broker:6379/0"}


def test_defaults() -> None:
    config = load(dict(BASE))
    assert config.engine == "ghidra"
    assert config.jvm_heap == DEFAULT_JVM_HEAP == 2 * GIB
    assert config.decompile_jvm_heap == DEFAULT_DECOMPILE_JVM_HEAP == GIB
    assert config.decompiler_as == DEFAULT_DECOMPILER_AS == 1536 * 1024**2
    assert config.tool_rlimit_as == config.jvm_heap + TOOL_AS_HEADROOM
    assert config.queue_prefix == ""


def test_replay_is_test_profile_only() -> None:
    with pytest.raises(ConfigError, match="refused outside the test profile"):
        load({**BASE, "RE_ENGINE": "replay"})
    assert load({**BASE, "RE_ENGINE": "replay", "TEST_PROFILE": "1"}).engine == "replay"
    with pytest.raises(ConfigError):
        load({**BASE, "RE_ENGINE": "radare2"})


@pytest.mark.parametrize(
    "env",
    [
        {"RE_JVM_HEAP": str(4 * GIB)},  # above 3 GiB
        {"RE_JVM_HEAP": "lots"},
        {"RE_DECOMPILER_AS": str(GIB)},  # not above the decompile heap (RT4)
        {"RE_TOOL_RLIMIT_AS": str(2 * GIB)},  # not above the heap
    ],
)
def test_bounds(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        load({**BASE, **env})
