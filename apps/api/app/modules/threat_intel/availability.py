"""Whether a provider may be used in this deployment (shared by the API and the worker)."""

from app.core.config import Settings
from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.providers.base import ProviderName


def provider_available(name: ProviderName, settings: Settings) -> bool:
    """False for everything when `TI_ENABLED=false`; a `dev_only` provider (the mock) only
    outside prod and with `TI_MOCK_ENABLED`."""
    if not settings.ti_enabled:
        return False
    if CATALOG[name].dev_only:
        return settings.env != "prod" and settings.ti_mock_enabled
    return True
