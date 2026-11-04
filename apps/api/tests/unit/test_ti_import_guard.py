"""Only the enrich worker may reach providers, the provider HTTP client and unsealing (M4).

The API seals keys and plans runs; it never calls a provider and never opens a sealed key.
- `threat_intel.unseal` may only be imported from `app/workers/enrich*.py`: nothing else is
  ever exempt for it, not even the adapters (review L5).
- The adapter modules and the registry (`threat_intel.providers.*` except the shared
  `providers.base`) and `threat_intel.http` may be imported from `app/workers/enrich*.py`
  and from the adapter and registry modules themselves (adapters use the HTTP client; the
  registry imports adapters), but not from `providers/base.py` or `providers/__init__.py`,
  which the API imports too.
Every import form counts: `import x`, `import x as y`, `from pkg import x`, relative imports,
and `importlib.import_module("x")` or `__import__("x")` with a constant name (RT21).
"""

import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[2] / "app"
TI = "app.modules.threat_intel"
UNSEAL = f"{TI}.unseal"
FORBIDDEN_EXACT = {f"{TI}.http", UNSEAL, f"{TI}.providers"}
SHARED = {f"{TI}.providers.base"}
# Imported by the API as well: no exemption at all.
SHARED_FILES = frozenset(
    {"modules/threat_intel/providers/base.py", "modules/threat_intel/providers/__init__.py"}
)


def forbidden(module: str) -> bool:
    if module in SHARED or any(module.startswith(f"{m}.") for m in SHARED):
        return False
    return any(module == m or module.startswith(f"{m}.") for m in FORBIDDEN_EXACT)


def _package(rel: str) -> list[str]:
    parts = ["app", *rel.removesuffix(".py").split("/")]
    return parts[:-1]  # the module's package (an __init__ is its own package's member)


def imported_modules(source: str, rel: str) -> list[tuple[int, str]]:
    """Every module name `source` (file `rel` under app/) imports, fully qualified."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [(node.lineno, alias.name) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package = _package(rel)
                base = package[: len(package) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            # `from pkg import name` reaches pkg.name (a submodule or an attribute of pkg).
            found += [(node.lineno, f"{module}.{alias.name}") for alias in node.names]
        elif (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and (
                (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
                or (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"__import__", "import_module"}
                )
            )
        ):
            found.append((node.lineno, node.args[0].value))
    return found


def _is_unseal(module: str) -> bool:
    return module == UNSEAL or module.startswith(f"{UNSEAL}.")


def allowed_importer(rel: str, module: str) -> bool:
    if rel.startswith("workers/enrich") and rel.endswith(".py"):
        return True
    adapter_side = rel.startswith("modules/threat_intel/providers/") and rel not in SHARED_FILES
    return adapter_side and not _is_unseal(module)


def offenders(source: str, rel: str) -> list[str]:
    return [
        f"{rel}:{line} {mod}"
        for line, mod in imported_modules(source, rel)
        if forbidden(mod) and not allowed_importer(rel, mod)
    ]


def test_only_the_enrich_worker_imports_providers_http_and_unseal() -> None:
    found: list[str] = []
    for path in APP.rglob("*.py"):
        rel = path.relative_to(APP).as_posix()
        found += offenders(path.read_text(encoding="utf-8"), rel)
    assert found == [], f"forbidden threat-intel imports: {found}"


@pytest.mark.parametrize(
    "source",
    [
        "import app.modules.threat_intel.unseal",
        "import app.modules.threat_intel.unseal as u",
        "from app.modules.threat_intel.unseal import open_sealed",
        "from app.modules.threat_intel import unseal",
        "from app.modules.threat_intel import seal, unseal as u",
        "from app.modules.threat_intel import http",
        "from app.modules.threat_intel.http import ti_client",
        "from app.modules.threat_intel import providers",
        "from app.modules.threat_intel.providers import virustotal",
        "from app.modules.threat_intel.providers.registry import get",
        "import app.modules.threat_intel.providers.otx",
        "from . import unseal",
        "from .providers import registry",
        "import importlib\nimportlib.import_module('app.modules.threat_intel.unseal')",
        "__import__('app.modules.threat_intel.http')",
    ],
)
def test_guard_catches_every_import_form(source: str) -> None:
    assert offenders(source, "modules/threat_intel/service_integrations.py")


@pytest.mark.parametrize(
    "source",
    [
        "from app.modules.threat_intel.providers.base import ProviderResult",
        "from app.modules.threat_intel.providers import base",
        "from .providers.base import IocType",
        "from app.modules.threat_intel import seal, catalog, summaries",
        "import app.modules.threat_intel.seal",
    ],
)
def test_guard_allows_the_shared_modules(source: str) -> None:
    assert offenders(source, "modules/threat_intel/service_integrations.py") == []


def test_the_enrich_worker_and_adapters_may_import_them() -> None:
    source = "from app.modules.threat_intel.unseal import open_sealed\nfrom .. import http"
    assert offenders(source, "workers/enrich.py") == []
    assert offenders(source, "workers/enrich_tasks.py") == []
    assert offenders(source, "workers/ingest.py")
    adapter = "from .. import http\nfrom . import registry\nfrom .registry import create"
    assert offenders(adapter, "modules/threat_intel/providers/virustotal.py") == []
    assert offenders(adapter, "modules/threat_intel/providers/registry.py") == []


@pytest.mark.parametrize(
    "source",
    [
        "from app.modules.threat_intel.unseal import open_sealed",
        "from .. import unseal",
        "import app.modules.threat_intel.unseal as u",
    ],
)
def test_adapters_may_never_import_unseal(source: str) -> None:
    assert offenders(source, "modules/threat_intel/providers/virustotal.py")
    assert offenders(source, "modules/threat_intel/providers/registry.py")


@pytest.mark.parametrize("rel", sorted(SHARED_FILES))
@pytest.mark.parametrize(
    "source",
    [
        "from .. import http",
        "from . import registry",
        "from .registry import create",
        "from . import mock",
        "from app.modules.threat_intel.unseal import open_sealed",
    ],
)
def test_the_shared_provider_modules_get_no_exemption(rel: str, source: str) -> None:
    assert offenders(source, rel)
