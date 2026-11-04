"""Provider metadata (frozen in M4 phase 1, RT14): read by the API and the worker alike.

No adapter imports: this is data. Limits are self-imposed; `default_limits` apply until an
org lowers them, and an org can never go above `ceilings`. An operator with a paid tier
raises a ceiling through `TI_CEILINGS` (settings), never through the org API.
"""

from dataclasses import dataclass
from types import MappingProxyType

from app.modules.threat_intel.providers.base import HASH_TYPES, IP_TYPES, IocType, ProviderName


@dataclass(frozen=True)
class ProviderLimits:
    per_minute: int
    # None: no daily cap (self-hosted MISP, the mock).
    per_day: int | None
    # Concurrent requests per provider inside one worker slice (global cap: 16).
    concurrency: int = 4


@dataclass(frozen=True)
class CatalogEntry:
    name: ProviderName
    label: str
    supported_types: frozenset[IocType]
    tos_note: str
    privacy_note: str
    default_limits: ProviderLimits
    ceilings: ProviderLimits
    # Available only when ENV is not prod and TI_MOCK_ENABLED=true.
    dev_only: bool = False
    # Needs an org-supplied https base URL (bound to the sealed key, RT1).
    needs_base_url: bool = False


_PUBLIC_PRIVACY = (
    "Every enabled lookup tells {label} which indicators your organization is investigating. "
    "Private IPs, internal names, URL query strings, emails, paths and registry keys are "
    "never sent."
)


def _entry(
    name: ProviderName,
    label: str,
    types: frozenset[IocType],
    tos_note: str,
    limits: ProviderLimits,
    *,
    privacy_note: str | None = None,
    dev_only: bool = False,
    needs_base_url: bool = False,
) -> CatalogEntry:
    return CatalogEntry(
        name=name,
        label=label,
        supported_types=types,
        tos_note=tos_note,
        privacy_note=privacy_note or _PUBLIC_PRIVACY.format(label=label),
        default_limits=limits,
        ceilings=limits,
        dev_only=dev_only,
        needs_base_url=needs_base_url,
    )


_NETWORK = IP_TYPES | {IocType.DOMAIN, IocType.URL}

_ENTRIES = (
    _entry(
        ProviderName.VIRUSTOTAL,
        "VirusTotal",
        _NETWORK | HASH_TYPES,
        "The VirusTotal public API must not be used in commercial products or workflows, and "
        "one person may hold only one account. Commercial use needs a premium key.",
        ProviderLimits(per_minute=4, per_day=500),
    ),
    _entry(
        ProviderName.ABUSEIPDB,
        "AbuseIPDB",
        IP_TYPES,
        "Free plan: 1,000 checks per day. Results are AbuseIPDB's community reports, quoted "
        "with attribution.",
        ProviderLimits(per_minute=30, per_day=1000),
    ),
    _entry(
        ProviderName.URLHAUS,
        "URLhaus (abuse.ch)",
        _NETWORK | {IocType.MD5, IocType.SHA256},
        "abuse.ch free access is for not-for-profit use within fair-use volumes; commercial "
        "use needs a Spamhaus subscription, and redistribution needs consent.",
        ProviderLimits(per_minute=30, per_day=2000),
    ),
    _entry(
        ProviderName.MALWAREBAZAAR,
        "MalwareBazaar (abuse.ch)",
        HASH_TYPES,
        "abuse.ch free access is for not-for-profit use within fair-use volumes; commercial "
        "use needs a Spamhaus subscription, and redistribution needs consent. Only hashes are "
        "sent, never files.",
        ProviderLimits(per_minute=30, per_day=2000),
    ),
    _entry(
        ProviderName.OTX,
        "AlienVault OTX",
        _NETWORK | HASH_TYPES,
        "LevelBlue (AlienVault) OTX terms apply; no published hard limit, so CyberLab keeps "
        "a conservative self-imposed one.",
        ProviderLimits(per_minute=30, per_day=5000),
    ),
    _entry(
        ProviderName.MISP,
        "MISP",
        _NETWORK | HASH_TYPES | {IocType.EMAIL},
        "Your own MISP instance: its sharing rules and the TLP markings of its events apply.",
        ProviderLimits(per_minute=120, per_day=None, concurrency=4),
        privacy_note=(
            "Lookups go to the MISP URL your admins configured, including email addresses. "
            "The key only works with the URL it was saved with."
        ),
        needs_base_url=True,
    ),
    _entry(
        ProviderName.MOCK,
        "Test provider",
        frozenset(IocType),
        "Development and test sink only; refused in production.",
        ProviderLimits(per_minute=6000, per_day=None, concurrency=4),
        privacy_note="Lookups go to the local ti-mock container; nothing leaves the host.",
        dev_only=True,
    ),
)

CATALOG: MappingProxyType[ProviderName, CatalogEntry] = MappingProxyType(
    {entry.name: entry for entry in _ENTRIES}
)
PROVIDER_NAMES: tuple[str, ...] = tuple(name.value for name in ProviderName)

if set(CATALOG) != set(ProviderName):
    raise RuntimeError("every provider needs a catalog entry")
