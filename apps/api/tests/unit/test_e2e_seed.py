"""e2e_seed refuses to run outside the dev e2e (M7 phase 11): without CYBERLAB_E2E_SEED=1, the
dev api env (ENV=dev, no secure cookies), the owner URL and a real seed password, `seed` exits
1 before any request or owner write, and it never prints the password."""

import json

import pytest

from app.scripts import e2e_seed

ENV = {
    "CYBERLAB_E2E_SEED": "1",
    "ENV": "dev",
    "COOKIE_SECURE": "false",
    "E2E_OWNER_DATABASE_URL": "postgresql+asyncpg://owner@postgres/cyberlab",
    "E2E_SEED_PASSWORD": "a-long-seed-password",
}


def test_require_dev_accepts_only_the_dev_seed() -> None:
    assert e2e_seed.require_dev(ENV) == "a-long-seed-password"
    for name, bad in (
        ("CYBERLAB_E2E_SEED", None),
        ("CYBERLAB_E2E_SEED", "true"),
        ("ENV", "prod"),
        ("ENV", "test"),
        ("COOKIE_SECURE", "true"),
        ("COOKIE_SECURE", "1"),
        ("E2E_OWNER_DATABASE_URL", None),
        ("E2E_SEED_PASSWORD", None),
        ("E2E_SEED_PASSWORD", "short"),
    ):
        env = {k: v for k, v in ENV.items() if k != name}
        if bad is not None:
            env[name] = bad
        with pytest.raises(e2e_seed.SeedError):
            e2e_seed.require_dev(env)


def test_prod_exits_before_any_request(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[str] = []
    monkeypatch.setattr(e2e_seed, "_seed_api", lambda p: called.append("api") or {})
    monkeypatch.setattr(e2e_seed, "_tombstone", lambda *a: called.append("owner"))
    for key, value in {**ENV, "ENV": "prod"}.items():
        monkeypatch.setenv(key, value)
    assert e2e_seed.main() == 1
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
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    assert e2e_seed.main() == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == {
        "email": "e2e-seed-x@example.com",
        "org_id": "o",
        "evidence_id": "e",
    }
    assert "a-long-seed-password" not in out.out + out.err
