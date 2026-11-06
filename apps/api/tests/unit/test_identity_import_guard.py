"""M11: who may open identity and mail secrets (phase 1, FROZEN guard).

- `app.modules.identity.unseal` (TOTP secrets, IdP client secrets) only from the identity
  modules that need the plaintext: `identity/{mfa,discovery,idp_config}.py` and
  `identity/sso/*.py`. Never from a worker (the api role alone holds the key).
- `app.modules.mail.unseal` (link tokens) only from `mail/worker.py` and
  `app/workers/mail_*.py` (the mail worker; phase 2).
- The mail worker never imports `identity.unseal`, `threat_intel.unseal` or `ai.unseal`, and
  `mail/seal.py` / `mail/outbox.py` never open anything.
Every import form counts (the M4 RT21 parser of `test_ti_import_guard.py`).
"""

from pathlib import Path

import pytest

from tests.unit.test_ti_import_guard import imported_modules

APP = Path(__file__).resolve().parents[2] / "app"
IDENTITY_UNSEAL = "app.modules.identity.unseal"
MAIL_UNSEAL = "app.modules.mail.unseal"
OTHER_UNSEALS = ("app.modules.threat_intel.unseal", "app.modules.ai.unseal")
IDENTITY_OPENERS = frozenset(
    {"modules/identity/mfa.py", "modules/identity/discovery.py", "modules/identity/idp_config.py"}
)


def _matches(module: str, target: str) -> bool:
    return module == target or module.startswith(f"{target}.")


def _is_mail_worker(rel: str) -> bool:
    return rel == "modules/mail/worker.py" or (
        rel.startswith("workers/mail_") and rel.endswith(".py")
    )


def offenders(source: str, rel: str) -> list[str]:
    found: list[str] = []
    for line, module in imported_modules(source, rel):
        if _matches(module, IDENTITY_UNSEAL):
            ok = rel in IDENTITY_OPENERS or rel.startswith("modules/identity/sso/")
        elif _matches(module, MAIL_UNSEAL):
            ok = _is_mail_worker(rel)
        elif any(_matches(module, other) for other in OTHER_UNSEALS) and _is_mail_worker(rel):
            ok = False
        else:
            continue
        if not ok:
            found.append(f"{rel}:{line} {module}")
    return found


def test_identity_and_mail_secrets_open_only_where_needed() -> None:
    found: list[str] = []
    for path in APP.rglob("*.py"):
        rel = path.relative_to(APP).as_posix()
        found += offenders(path.read_text(encoding="utf-8"), rel)
    assert found == [], f"forbidden identity / mail unseal imports: {found}"


@pytest.mark.parametrize(
    "source",
    [
        "from app.modules.identity.unseal import open_identity_secret",
        "import app.modules.identity.unseal as u",
        "from app.modules.identity import unseal",
        "import importlib\nimportlib.import_module('app.modules.identity.unseal')",
    ],
)
@pytest.mark.parametrize(
    "rel",
    [
        "modules/identity/policy.py",
        "modules/identity/router_mfa.py",
        "modules/auth/service.py",
        "workers/mail_tasks.py",
        "workers/ingest.py",
    ],
)
def test_identity_unseal_is_refused_elsewhere(source: str, rel: str) -> None:
    assert offenders(source, rel)


def test_the_relative_form_counts_too() -> None:
    assert offenders("from . import unseal", "modules/identity/policy.py")
    assert offenders("from . import unseal", "modules/identity/mfa.py") == []


def test_identity_openers_are_allowed() -> None:
    source = "from app.modules.identity.unseal import open_identity_secret"
    for rel in (*sorted(IDENTITY_OPENERS), "modules/identity/sso/flow.py"):
        assert offenders(source, rel) == []


MAIL_OPEN = "from app.modules.mail.unseal import open_link_token"


@pytest.mark.parametrize(
    "rel",
    [
        "modules/mail/outbox.py",
        "modules/mail/seal.py",
        "modules/mail/render.py",
        "workers/ingest.py",
    ],
)
def test_mail_unseal_only_in_the_mail_worker(rel: str) -> None:
    assert offenders(MAIL_OPEN, rel)
    assert offenders(MAIL_OPEN, "modules/mail/worker.py") == []
    assert offenders("from app.modules.mail import unseal", "workers/mail_tasks.py") == []


@pytest.mark.parametrize(
    "source",
    [
        "from app.modules.identity.unseal import open_identity_secret",
        "from app.modules.threat_intel.unseal import open_sealed",
        "from app.modules.ai.unseal import open_sealed",
    ],
)
def test_the_mail_worker_opens_nothing_else(source: str) -> None:
    assert offenders(source, "workers/mail_tasks.py")
    assert offenders(source, "modules/mail/worker.py")
