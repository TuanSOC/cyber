"""drill_seed refuses to run outside the restore drill (M7 phase 2): without CYBERLAB_DRILL=1,
the drill project name and the drill overlay's EVIDENCE_LOCK_DAYS=1, `seed` and `check` exit 1
before any request, any owner write or any governance-bypass delete."""

import io
import json
from typing import Any

import pytest

from app.scripts import drill_seed

DRILL_ENV = {
    "CYBERLAB_DRILL": "1",
    "CYBERLAB_DRILL_PROJECT": "cyberlab-drill",
    "EVIDENCE_LOCK_DAYS": "1",
}


def test_require_drill_accepts_only_the_drill() -> None:
    drill_seed.require_drill(DRILL_ENV)
    for name, bad in (
        ("CYBERLAB_DRILL", None),
        ("CYBERLAB_DRILL", "true"),
        ("CYBERLAB_DRILL_PROJECT", None),
        ("CYBERLAB_DRILL_PROJECT", "cyberlab"),
        ("CYBERLAB_DRILL_PROJECT", "cyberlab-drill-x"),
        ("EVIDENCE_LOCK_DAYS", None),
        ("EVIDENCE_LOCK_DAYS", "30"),
    ):
        env = {k: v for k, v in DRILL_ENV.items() if k != name}
        if bad is not None:
            env[name] = bad
        with pytest.raises(drill_seed.DrillError, match="refusing"):
            drill_seed.require_drill(env)


@pytest.fixture
def no_side_effects(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    called: list[str] = []

    def boom(name: str) -> Any:
        def inner(*_: Any, **__: Any) -> Any:
            called.append(name)
            raise AssertionError(f"{name} ran outside the drill")

        return inner

    monkeypatch.setattr(drill_seed, "_seed_api", boom("_seed_api"))
    monkeypatch.setattr(drill_seed, "_client", boom("_client"))
    monkeypatch.setattr(drill_seed, "_delete_locked_version", boom("_delete_locked_version"))
    return called


@pytest.mark.parametrize("mode", ["seed", "check"])
def test_main_refuses_outside_the_drill(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    no_side_effects: list[str],
) -> None:
    for name in DRILL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert drill_seed.main([mode]) == 1
    assert "refusing" in json.loads(capsys.readouterr().out)["error"]
    # The main project's api env (EVIDENCE_LOCK_DAYS=30) with a forged marker: still refused.
    monkeypatch.setenv("CYBERLAB_DRILL", "1")
    monkeypatch.setenv("CYBERLAB_DRILL_PROJECT", "cyberlab-drill")
    monkeypatch.setenv("EVIDENCE_LOCK_DAYS", "30")
    assert drill_seed.main([mode]) == 1
    assert "EVIDENCE_LOCK_DAYS" in json.loads(capsys.readouterr().out)["error"]
    assert no_side_effects == []


async def test_owner_rows_refuse_outside_the_drill(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in DRILL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DRILL_OWNER_DATABASE_URL", "postgresql+asyncpg://x:y@nowhere:1/z")
    with pytest.raises(drill_seed.DrillError, match="CYBERLAB_DRILL"):
        await drill_seed._seed_owner_rows({})
