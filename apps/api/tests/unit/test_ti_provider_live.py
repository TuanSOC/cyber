"""Opt-in live smoke tests of the public provider adapters (M4 phase 3).

Skipped unless `CYBERLAB_LIVE_TI=1` and the provider's key is in the environment
(`CYBERLAB_TI_KEY_<PROVIDER>`; URLhaus and MalwareBazaar fall back to
`CYBERLAB_TI_KEY_ABUSECH`). Never run in CI or the verify gate, and only from a container
with egress (the enrich-worker network): one verify and one lookup of a well-known public
value per provider. Each lookup costs one call of the provider's quota.
"""

import os

import pytest
from pydantic import SecretStr

from app.core.config import get_settings
from app.modules.threat_intel.http import KeyAuth, ti_client
from app.modules.threat_intel.providers import registry
from app.modules.threat_intel.providers.base import (
    IocRef,
    IocType,
    ProviderName,
    ResultStatus,
    VerifyStatus,
)

LIVE = os.environ.get("CYBERLAB_LIVE_TI") == "1"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
LOOKUPS = {
    ProviderName.VIRUSTOTAL: IocRef.of(IocType.SHA256, EICAR),
    ProviderName.ABUSEIPDB: IocRef.of(IocType.IPV4, "8.8.8.8"),
    ProviderName.URLHAUS: IocRef.of(IocType.SHA256, EICAR),
    ProviderName.MALWAREBAZAAR: IocRef.of(IocType.SHA256, EICAR),
    ProviderName.OTX: IocRef.of(IocType.IPV4, "8.8.8.8"),
}
_ABUSECH = {ProviderName.URLHAUS, ProviderName.MALWAREBAZAAR}


def _key(name: ProviderName) -> str | None:
    key = os.environ.get(f"CYBERLAB_TI_KEY_{name.value.upper()}")
    if key is None and name in _ABUSECH:
        key = os.environ.get("CYBERLAB_TI_KEY_ABUSECH")
    return key or None


pytestmark = pytest.mark.skipif(not LIVE, reason="live TI tests need CYBERLAB_LIVE_TI=1")


@pytest.mark.parametrize("name", list(LOOKUPS))
async def test_live_verify_and_lookup(name: ProviderName) -> None:
    key = _key(name)
    if key is None:
        pytest.skip(f"no live key for {name.value}")
    adapter = registry.create(name, registry.ProviderContext(get_settings()))
    auth = KeyAuth(registry.auth_header(name), SecretStr(key))
    async with ti_client(adapter, auth=auth) as client:
        assert (await adapter.verify(client)).status is VerifyStatus.VALID
        result = await adapter.lookup(client, LOOKUPS[name])
    assert result.status in (ResultStatus.OK, ResultStatus.NOT_FOUND)
    assert key not in result.model_dump_json()
