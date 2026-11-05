"""Only `app/modules/reports/signing.py` may load the report signing private keys (M6).

`app.core.signing.load_signing_keys` reads REPORT_SIGNING_KEYS_FILE (the api's compose
secret). The public helpers of `app.core.signing` (`load_public_keys`, `sign`, `verify`,
`public_key_b64`) are free to import by name; importing the loader by name, or the module
itself (`import app.core.signing`, `from app.core import signing`, which would reach the
loader as an attribute), is allowed only in `reports/signing.py`. Every import form counts
(the M4 RT21 parser of `test_ti_import_guard.py`).
"""

from pathlib import Path

import pytest

from tests.unit.test_ti_import_guard import imported_modules

APP = Path(__file__).resolve().parents[2] / "app"
MODULE = "app.core.signing"
LOADER = f"{MODULE}.load_signing_keys"
WRAPPER = "modules/reports/signing.py"
PUBLIC_NAMES = frozenset(
    f"{MODULE}.{name}"
    for name in (
        "load_public_keys",
        "sign",
        "verify",
        "public_key_b64",
        "SigningError",
        "ALGORITHM",
        "KEY_BYTES",
        "SIGNATURE_BYTES",
    )
)


def offenders(source: str, rel: str) -> list[str]:
    if rel == WRAPPER or rel == "core/signing.py":
        return []
    found: list[str] = []
    for line, module in imported_modules(source, rel):
        if module in PUBLIC_NAMES:
            continue
        if module == MODULE or module == LOADER or module.startswith(f"{MODULE}."):
            found.append(f"{rel}:{line} {module}")
    return found


def test_only_the_reports_wrapper_loads_signing_keys() -> None:
    found: list[str] = []
    for path in APP.rglob("*.py"):
        rel = path.relative_to(APP).as_posix()
        found += offenders(path.read_text(encoding="utf-8"), rel)
    assert found == [], f"forbidden signing-key imports: {found}"


def test_the_wrapper_exists_and_uses_the_loader() -> None:
    source = (APP / WRAPPER).read_text(encoding="utf-8")
    assert any(m == LOADER for _, m in imported_modules(source, WRAPPER))


@pytest.mark.parametrize(
    "source",
    [
        "from app.core.signing import load_signing_keys",
        "from app.core.signing import load_signing_keys as l",
        "from app.core.signing import sign, load_signing_keys",
        "import app.core.signing",
        "import app.core.signing as s",
        "from app.core import signing",
        "from app.core import signing as s",
        "import importlib\nimportlib.import_module('app.core.signing')",
        "__import__('app.core.signing')",
    ],
)
def test_guard_catches_every_import_form(source: str) -> None:
    assert offenders(source, "modules/reports/service.py")


@pytest.mark.parametrize(
    "source",
    [
        "from app.core.signing import load_public_keys, verify, public_key_b64",
        "from app.core.signing import SigningError, sign",
        "from app.core import sealbox",
        "from app.modules.reports import signing",
    ],
)
def test_guard_allows_the_public_helpers(source: str) -> None:
    assert offenders(source, "modules/reports/router_keys.py") == []


def test_relative_imports_count_too() -> None:
    assert offenders("from .signing import load_signing_keys", "core/stubs.py")
    assert offenders("from . import signing", "core/stubs.py")


def test_the_wrapper_may_import_the_loader() -> None:
    assert offenders("from app.core.signing import load_signing_keys", WRAPPER) == []
