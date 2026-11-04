"""Provider name -> adapter module (imported lazily). Enrich worker only (import guard).

Every provider is listed here once, with its module, factory and auth header; phases 3 and 4
only add the modules (`virustotal.py`, `abuseipdb.py`, `abusech.py`, `otx.py`, `misp.py`),
never edit this file. A module's factory takes a `ProviderContext` and returns an object
satisfying the frozen `Provider` protocol (`providers/base.py`). A provider whose module does
not exist yet is reported unavailable (`ProviderUnavailable`).
"""

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from app.modules.threat_intel.availability import provider_available
from app.modules.threat_intel.providers.base import Provider, ProviderName

if TYPE_CHECKING:
    from app.core.config import Settings

_PACKAGE = "app.modules.threat_intel.providers"


@dataclass(frozen=True)
class AdapterSpec:
    module: str
    factory: str
    # The only header the key ever travels in (attached per request by http.KeyAuth, RT11).
    auth_header: str


SPECS: dict[ProviderName, AdapterSpec] = {
    ProviderName.VIRUSTOTAL: AdapterSpec(f"{_PACKAGE}.virustotal", "create", "x-apikey"),
    ProviderName.ABUSEIPDB: AdapterSpec(f"{_PACKAGE}.abuseipdb", "create", "Key"),
    ProviderName.URLHAUS: AdapterSpec(f"{_PACKAGE}.abusech", "create_urlhaus", "Auth-Key"),
    ProviderName.MALWAREBAZAAR: AdapterSpec(
        f"{_PACKAGE}.abusech", "create_malwarebazaar", "Auth-Key"
    ),
    ProviderName.OTX: AdapterSpec(f"{_PACKAGE}.otx", "create", "X-OTX-API-KEY"),
    ProviderName.MISP: AdapterSpec(f"{_PACKAGE}.misp", "create", "Authorization"),
    ProviderName.MOCK: AdapterSpec(f"{_PACKAGE}.mock", "create", "X-Mock-Key"),
}

if set(SPECS) != set(ProviderName):
    raise RuntimeError("every provider needs a registry entry")


class ProviderUnavailable(Exception):
    """The provider cannot be used in this process (no adapter yet, mock in prod, TI off)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProviderContext:
    settings: "Settings"
    # MISP only: the normalized base URL the key is bound to (seal AAD); "" otherwise.
    base_url_norm: str = ""


def available(name: ProviderName, settings: "Settings") -> bool:
    # dev_only (catalog, the mock): never when ENV=prod, and only with TI_MOCK_ENABLED.
    return provider_available(name, settings)


def auth_header(name: ProviderName) -> str:
    return SPECS[name].auth_header


def create(name: ProviderName, ctx: ProviderContext) -> Provider:
    if not available(name, ctx.settings):
        raise ProviderUnavailable("provider_unavailable")
    spec = SPECS[name]
    try:
        module = importlib.import_module(spec.module)
    except ModuleNotFoundError as exc:
        if exc.name == spec.module:
            raise ProviderUnavailable("adapter_missing") from None
        raise
    factory = cast(Callable[[ProviderContext], Provider], getattr(module, spec.factory))
    return factory(ctx)


__all__ = [
    "SPECS",
    "AdapterSpec",
    "ProviderContext",
    "ProviderUnavailable",
    "auth_header",
    "available",
    "create",
]
