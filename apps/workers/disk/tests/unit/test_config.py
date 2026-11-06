"""Worker settings (pure Python): the replay timeline engine and the M3 test rules are refused
outside the test profile, the free-space floor is bounded, the hash-set store defaults to
`/hashsets`; the hash-set tool is a stub with its frozen command names."""

from pathlib import PurePosixPath

import pytest

from disk_worker.config import DEFAULT_MIN_FREE_BYTES, ConfigError, load

BASE = {"BROKER_URL": "redis://disk:x@redis-broker:6379/0"}


def test_defaults() -> None:
    config = load(dict(BASE))
    assert config.timeline_engine == "plaso"
    assert PurePosixPath(config.hashsets_dir.as_posix()) == PurePosixPath("/hashsets")
    assert PurePosixPath(config.rules_dir.as_posix()) == PurePosixPath("/opt/rules/image")
    assert config.min_free_bytes == DEFAULT_MIN_FREE_BYTES == 4 * 1024**3
    assert config.queue_prefix == "" and config.test_rules_dir is None


def test_replay_and_test_rules_are_test_profile_only() -> None:
    with pytest.raises(ConfigError, match="refused outside the test profile"):
        load({**BASE, "DISK_TIMELINE_ENGINE": "replay"})
    replay = load({**BASE, "DISK_TIMELINE_ENGINE": "replay", "TEST_PROFILE": "1"})
    assert replay.timeline_engine == "replay"
    assert load({**BASE, "DISK_TIMELINE_ENGINE": "none"}).timeline_engine == "none"
    with pytest.raises(ConfigError):
        load({**BASE, "DISK_TIMELINE_ENGINE": "log2timeline"})
    with pytest.raises(ConfigError):
        load({**BASE, "DISK_TEST_RULES_DIR": "/srv/rules/test"})
    allowed = load({**BASE, "DISK_TEST_RULES_DIR": "/srv/rules/test", "TEST_PROFILE": "1"})
    assert allowed.test_rules_dir is not None


@pytest.mark.parametrize("value", ["-1", str(1024**4 + 1)])
def test_min_free_bounds(value: str) -> None:
    with pytest.raises(ConfigError):
        load({**BASE, "DISK_WORK_MIN_FREE_BYTES": value})


def test_hashsets_cli_is_a_stub_with_the_frozen_commands() -> None:
    from disk_worker.hashsets.__main__ import COMMANDS, main

    assert COMMANDS == ("import-nsrl", "import-list", "list", "verify", "remove")
    assert main([]) == 2
