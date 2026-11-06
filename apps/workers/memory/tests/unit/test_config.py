"""Worker settings (pure Python): the replay engine is refused outside the test profile, the
plugin address-space limit is bounded, the symbol store defaults to `/symbols`; the symbols CLI
is a stub with its frozen command names."""

from pathlib import PurePosixPath

import pytest

from memory_worker.config import DEFAULT_PLUGIN_RLIMIT_AS, ConfigError, load

BASE = {"BROKER_URL": "redis://memory:x@redis-broker:6379/0"}


def test_defaults() -> None:
    config = load(dict(BASE))
    assert config.engine == "volatility3"
    assert PurePosixPath(config.symbols_dir.as_posix()) == PurePosixPath("/symbols")
    assert config.plugin_rlimit_as == DEFAULT_PLUGIN_RLIMIT_AS == 2560 * 1024**2
    assert config.queue_prefix == ""


def test_replay_is_test_profile_only() -> None:
    with pytest.raises(ConfigError, match="refused outside the test profile"):
        load({**BASE, "MEMORY_ENGINE": "replay"})
    assert load({**BASE, "MEMORY_ENGINE": "replay", "TEST_PROFILE": "1"}).engine == "replay"
    with pytest.raises(ConfigError):
        load({**BASE, "MEMORY_ENGINE": "vol2"})


@pytest.mark.parametrize("value", ["1", str(17 * 1024**3)])
def test_rlimit_bounds(value: str) -> None:
    with pytest.raises(ConfigError):
        load({**BASE, "MEMORY_PLUGIN_RLIMIT_AS": value})


def test_symbols_cli_is_a_stub_with_the_frozen_commands() -> None:
    from memory_worker.symbols.__main__ import COMMANDS, main

    assert COMMANDS == ("fetch-windows", "import", "reindex", "verify", "list")
    assert main([]) == 2
    assert main(["fetch-windows", "--pdb", "ntkrnlmp.pdb"]) == 2
    assert main(["rm", "-rf"]) == 2
