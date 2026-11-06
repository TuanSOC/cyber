"""Only the analyst worker may reach LLM providers, the egress clients, the vendor SDKs and
AI unsealing (M5); `threat_intel.unseal` and `ai.unseal` are never importable by one role.

- `app.modules.ai.unseal` only from `app/workers/analyst*.py` (never the adapters).
- The generic `app.core.sealbox_open` only from the two unseal wrappers
  (`threat_intel/unseal.py`, `ai/unseal.py`).
- `ai.providers.{anthropic,gemini,mock,registry,errors}`, `ai.http` and the vendor SDKs
  (`anthropic`, `google.genai`, `httpx2`) only from `app/workers/analyst*.py` and the adapter
  side (those modules and `ai/http.py`); never from `ai/providers/__init__.py` or
  `ai/providers/fake.py`, which the API and the tests import too.
- `app/workers/analyst*.py` never imports `threat_intel.unseal` (the TI guard: only enrich),
  and `app/workers/enrich*.py` never imports `ai.unseal` (this guard: only analyst).
Every import form counts (the M4 RT21 parser of `test_ti_import_guard.py`).
"""

from pathlib import Path

import pytest

from tests.unit.test_ti_import_guard import imported_modules
from tests.unit.test_ti_import_guard import offenders as ti_offenders

APP = Path(__file__).resolve().parents[2] / "app"
AI = "app.modules.ai"
AI_UNSEAL = f"{AI}.unseal"
SEALBOX_OPEN = "app.core.sealbox_open"
ADAPTERS = tuple(f"{AI}.providers.{name}" for name in ("anthropic", "gemini", "mock", "registry"))
RESTRICTED = (
    *ADAPTERS,
    f"{AI}.providers.errors",
    f"{AI}.http",
    "anthropic",
    "google.genai",
    "httpx2",
)
ADAPTER_FILES = frozenset(
    {
        "modules/ai/http.py",
        *(
            f"modules/ai/providers/{n}.py"
            for n in ("anthropic", "gemini", "mock", "registry", "errors")
        ),
    }
)
# M11: the identity wrapper (the api opens TOTP and IdP client secrets) and the mail wrapper
# (the mail worker opens link tokens); `test_identity_import_guard.py` confines both.
UNSEAL_WRAPPERS = frozenset(
    {
        "modules/threat_intel/unseal.py",
        "modules/ai/unseal.py",
        "modules/identity/unseal.py",
        "modules/mail/unseal.py",
    }
)


def _matches(module: str, target: str) -> bool:
    return module == target or module.startswith(f"{target}.")


def _is_analyst(rel: str) -> bool:
    return rel.startswith("workers/analyst") and rel.endswith(".py")


def offenders(source: str, rel: str) -> list[str]:
    found: list[str] = []
    for line, module in imported_modules(source, rel):
        if _matches(module, AI_UNSEAL):
            ok = _is_analyst(rel)
        elif _matches(module, SEALBOX_OPEN):
            ok = rel in UNSEAL_WRAPPERS
        elif any(_matches(module, target) for target in RESTRICTED):
            ok = _is_analyst(rel) or rel in ADAPTER_FILES
        else:
            continue
        if not ok:
            found.append(f"{rel}:{line} {module}")
    return found


def test_only_the_analyst_worker_imports_providers_sdks_and_unseal() -> None:
    found: list[str] = []
    for path in APP.rglob("*.py"):
        rel = path.relative_to(APP).as_posix()
        found += offenders(path.read_text(encoding="utf-8"), rel)
    assert found == [], f"forbidden AI imports: {found}"


@pytest.mark.parametrize(
    "source",
    [
        "import app.modules.ai.unseal",
        "import app.modules.ai.unseal as u",
        "from app.modules.ai.unseal import open_sealed",
        "from app.modules.ai import unseal",
        "from app.modules.ai import seal, unseal as u",
        "from . import unseal",
        "from app.modules.ai import http",
        "from app.modules.ai.http import anthropic_client",
        "from app.modules.ai.providers import registry",
        "from app.modules.ai.providers.registry import build_provider",
        "import app.modules.ai.providers.anthropic",
        "from .providers import gemini",
        "from .providers.mock import MockProvider",
        "from app.modules.ai.providers.errors import map_error",
        "import anthropic",
        "from anthropic import AsyncAnthropic",
        "import google.genai",
        "from google import genai",
        "from google.genai import types",
        "import httpx2",
        "from app.core import sealbox_open",
        "from app.core.sealbox_open import open_in",
        "import importlib\nimportlib.import_module('app.modules.ai.unseal')",
        "__import__('anthropic')",
    ],
)
def test_guard_catches_every_import_form(source: str) -> None:
    assert offenders(source, "modules/ai/service_runs.py")


@pytest.mark.parametrize(
    "source",
    [
        "from app.modules.ai import seal, catalog, contracts, labels, text",
        "from app.modules.ai.providers.fake import FakeProvider",
        "from app.modules.ai import providers",
        "from .availability import provider_available",
        "import httpx",
        "from app.core.sealbox import seal_in",
        "import google.auth",
    ],
)
def test_guard_allows_the_shared_modules(source: str) -> None:
    assert offenders(source, "modules/ai/service_runs.py") == []


def test_the_analyst_worker_and_adapters_may_import_them() -> None:
    source = (
        "from app.modules.ai.unseal import open_sealed\n"
        "from app.modules.ai.providers.registry import build_provider\nimport anthropic"
    )
    assert offenders(source, "workers/analyst.py") == []
    assert offenders(source, "workers/analyst_tasks.py") == []
    adapter = "from .. import http\nfrom . import errors\nimport anthropic\nimport httpx2"
    for rel in ADAPTER_FILES:
        assert offenders(adapter, rel) == []
    assert offenders("from google import genai", "modules/ai/providers/gemini.py") == []


@pytest.mark.parametrize("rel", sorted(ADAPTER_FILES))
@pytest.mark.parametrize(
    "source", ["from app.modules.ai.unseal import open_sealed", "import app.modules.ai.unseal as u"]
)
def test_adapters_may_never_import_unseal(rel: str, source: str) -> None:
    assert offenders(source, rel)


@pytest.mark.parametrize(
    "rel", ["modules/ai/providers/__init__.py", "modules/ai/providers/fake.py"]
)
@pytest.mark.parametrize(
    "source", ["from . import registry", "from .anthropic import X", "import anthropic"]
)
def test_the_shared_provider_modules_get_no_exemption(rel: str, source: str) -> None:
    assert offenders(source, rel)


def test_sealbox_open_only_from_the_unseal_wrappers() -> None:
    source = "from app.core.sealbox_open import open_in"
    assert offenders(source, "modules/ai/unseal.py") == []
    assert offenders(source, "modules/threat_intel/unseal.py") == []
    assert offenders(source, "modules/identity/unseal.py") == []
    assert offenders(source, "modules/mail/unseal.py") == []
    for rel in (
        "workers/enrich.py",
        "workers/analyst.py",
        "modules/ai/seal.py",
        "core/config.py",
        "modules/identity/seal.py",
        "modules/mail/seal.py",
        "modules/mail/outbox.py",
    ):
        assert offenders(source, rel)


def test_one_role_never_holds_both_unseals() -> None:
    """The analyst never imports the TI unseal (the M4 guard), the enrich worker never the
    AI unseal (this guard), and neither reaches the other's adapters."""
    assert ti_offenders(
        "from app.modules.threat_intel.unseal import open_sealed", "workers/analyst.py"
    )
    assert ti_offenders("from app.modules.threat_intel import http", "workers/analyst_tasks.py")
    assert offenders("from app.modules.ai.unseal import open_sealed", "workers/enrich.py")
    assert offenders("from app.modules.ai.providers import registry", "workers/enrich_tasks.py")
    assert offenders("import anthropic", "workers/enrich.py")
