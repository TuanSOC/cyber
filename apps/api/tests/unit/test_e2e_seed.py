"""e2e_seed refuses to run outside the dev e2e (M7 phase 11, review L4): without
CYBERLAB_E2E_SEED=1, an explicit ENV=dev (also in the api settings), no secure cookies, an owner
URL naming the dev api's own database, a dev api URL (and a target api that serves the dev-only
docs) and a real seed password, `seed` exits 1 before any request or owner write, and it never
prints the password."""

import json
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from app.core.config import Settings
from app.scripts import e2e_seed

ENV = {
    "CYBERLAB_E2E_SEED": "1",
    "ENV": "dev",
    "COOKIE_SECURE": "false",
    "E2E_OWNER_DATABASE_URL": "postgresql+asyncpg://owner:pw@postgres:5432/cyberlab",
    "E2E_SEED_PASSWORD": "a-long-seed-password",
}


def _settings(**overrides: Any) -> Settings:
    values = {
        "env": "dev",
        "cookie_secure": False,
        "database_url": "postgresql+asyncpg://cyberlab_app:pw@postgres:5432/cyberlab",
        **overrides,
    }
    return cast(Settings, SimpleNamespace(**values))


def test_require_dev_accepts_only_the_dev_seed() -> None:
    assert e2e_seed.require_dev(ENV, _settings()) == "a-long-seed-password"
    for name, bad in (
        ("CYBERLAB_E2E_SEED", None),
        ("CYBERLAB_E2E_SEED", "true"),
        ("ENV", None),  # unset: refused, though the settings would default to dev
        ("ENV", "prod"),
        ("ENV", "test"),
        ("COOKIE_SECURE", "true"),
        ("COOKIE_SECURE", "1"),
        ("E2E_OWNER_DATABASE_URL", None),
        ("E2E_OWNER_DATABASE_URL", "postgresql+asyncpg://owner:pw@postgres:5432/cyberlab_test"),
        ("E2E_OWNER_DATABASE_URL", "postgresql+asyncpg://owner:pw@db.example.com/cyberlab"),
        ("E2E_OWNER_DATABASE_URL", "not a url"),
        ("E2E_API_URL", "https://api:8000"),
        ("E2E_API_URL", "http://cyberlab.example.com"),
        ("E2E_SEED_PASSWORD", None),
        ("E2E_SEED_PASSWORD", "short"),
    ):
        env = {k: v for k, v in ENV.items() if k != name}
        if bad is not None:
            env[name] = bad
        with pytest.raises(e2e_seed.SeedError):
            e2e_seed.require_dev(env, _settings())
    for settings in (
        _settings(env="prod"),
        _settings(env="test"),
        _settings(cookie_secure=True),
        _settings(database_url="postgresql+asyncpg://cyberlab_app:pw@postgres:5432/other"),
    ):
        with pytest.raises(e2e_seed.SeedError):
            e2e_seed.require_dev(ENV, settings)
    assert e2e_seed.require_dev({**ENV, "E2E_API_URL": "http://localhost:8000"}, _settings())


def test_the_target_api_must_serve_the_dev_docs() -> None:
    def client(status: int) -> httpx.Client:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/docs"
            return httpx.Response(status)

        return httpx.Client(base_url="http://api:8000", transport=httpx.MockTransport(handler))

    e2e_seed.require_dev_api(client(200))
    for status in (404, 500):
        with pytest.raises(e2e_seed.SeedError):
            e2e_seed.require_dev_api(client(status))


def test_prod_exits_before_any_request(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[str] = []
    monkeypatch.setattr(e2e_seed, "_seed_api", lambda p: called.append("api") or {})
    monkeypatch.setattr(e2e_seed, "_tombstone", lambda *a: called.append("owner"))
    monkeypatch.setattr(e2e_seed, "get_settings", lambda: _settings(env="prod"))
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    assert e2e_seed.main() == 1  # the api settings say prod
    monkeypatch.setattr(e2e_seed, "get_settings", _settings)
    monkeypatch.setenv("ENV", "prod")
    assert e2e_seed.main() == 1  # the environment says prod
    assert called == []
    out = capsys.readouterr()
    assert "a-long-seed-password" not in out.out + out.err


def test_the_output_carries_no_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seeded = {
        "email": "e2e-seed-x@example.com",
        "user_id": "u",
        "org_id": "o",
        "evidence_id": "e",
        "sha256": "0" * 64,
    }
    monkeypatch.setattr(e2e_seed, "_seed_api", lambda p: seeded)

    async def tombstone(seed: object, url: str) -> None:
        return None

    monkeypatch.setattr(e2e_seed, "_tombstone", tombstone)
    monkeypatch.setattr(e2e_seed, "get_settings", _settings)
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("E2E_API_URL", raising=False)
    assert e2e_seed.main() == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == {
        "email": "e2e-seed-x@example.com",
        "org_id": "o",
        "evidence_id": "e",
    }
    assert "a-long-seed-password" not in out.out + out.err
