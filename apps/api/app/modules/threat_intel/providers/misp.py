"""The MISP provider: attribute lookups against the org's own MISP (enrich worker only).

The org supplies the base URL, so this adapter is SSRF-hardened (RT1, RT5):
- the key was sealed with `base_url_norm` in the AAD, so the worker only ever opens it for
  that URL; `create` re-validates the URL syntactically and refuses one that is not already
  normalized;
- `pinned_transport` wraps the HTTP transport in `ssrf.PinnedTransport`: before EVERY request
  the host is resolved, every address must be public, and the request goes to the first
  address with `Host` and TLS SNI set to the hostname (the certificate is verified against
  it). Optional private CA bundle (`TI_MISP_CA_FILE`); `TI_MISP_INSECURE_TLS` is dev-only;
- only `POST {prefix}/attributes/restSearch` and `GET {prefix}/servers/getVersion` (verify)
  may be sent; redirects are never followed; bodies are capped at 2 MiB.

The key travels raw in `Authorization` (no `Bearer`, MISP's convention), attached per request
by `http.KeyAuth`. MISP results never become IOC sources and are never forwarded to another
provider. The summary is the frozen `MispSummary`: up to 20 attributes, every TLP marking seen
(a cap never hides one), ATT&CK galaxy tags as `attack_ids`, and a permalink built only from
`base_url_norm` and a validated numeric event id.
"""

import logging
import re
import ssl
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.http import MISP_MAX_BODY_BYTES, fetch_json
from app.modules.threat_intel.providers.base import (
    AllowedPath,
    IocRef,
    IocType,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.threat_intel.providers.registry import ProviderContext
from app.modules.threat_intel.ssrf import (
    MispUrlNotPublic,
    PinnedTransport,
    Resolver,
    ValidatedBase,
    validate_base_url,
)
from app.modules.threat_intel.summaries import MispAttribute, MispSummary, clean_text

log = logging.getLogger(__name__)

SEARCH_LIMIT = 50
MAX_ATTRIBUTES = 20
MAX_TAGS = 32
MAX_FAMILIES = 16
_EVENT_ID = re.compile(r"[1-9][0-9]{0,17}")
_EPOCH = re.compile(r"[0-9]{1,11}")
_ATTACK_IN_TAG = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![0-9.])")
_GALAXY = re.compile(r'misp-galaxy:([a-z0-9-]{1,64})="(.*)"', re.DOTALL)
# Most restrictive first: the summary keeps at most 4, so RED/AMBER are never cut.
_TLP_ORDER = (
    "tlp:red",
    "tlp:amber+strict",
    "tlp:amber",
    "tlp:green",
    "tlp:clear",
    "tlp:white",
)
_FAMILY_GALAXIES = frozenset({"malpedia", "mitre-malware", "mitre-tool"})

# IOC type -> the MISP attribute types searched (composites match on either half).
MISP_TYPES: Mapping[IocType, tuple[str, ...]] = {
    IocType.IPV4: ("ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"),
    IocType.IPV6: ("ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"),
    IocType.DOMAIN: ("domain", "hostname", "domain|ip", "hostname|port"),
    IocType.URL: ("url", "uri", "link"),
    IocType.MD5: ("md5", "filename|md5"),
    IocType.SHA1: ("sha1", "filename|sha1"),
    IocType.SHA256: ("sha256", "filename|sha256"),
    IocType.EMAIL: ("email", "email-src", "email-dst", "email-reply-to"),
}


def search_body(ioc: IocRef) -> dict[str, Any]:
    return {
        "returnFormat": "json",
        "value": ioc.value_norm,
        "type": list(MISP_TYPES[ioc.ioc_type]),
        "limit": SEARCH_LIMIT,
        "page": 1,
        "includeEventTags": True,
        "includeContext": False,
        "deleted": False,
        "enforceWarninglist": True,
    }


# --- defensive field coercion (provider data is untrusted) ---------------------------------


def _event_id(value: Any) -> int | None:
    """A strictly numeric, positive event id (never `42/../admin`, `-1` or `abc`)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value < 2**63 else None
    if isinstance(value, str) and _EVENT_ID.fullmatch(value):
        return int(value)
    return None


def _timestamp(value: Any) -> datetime | None:
    try:
        if isinstance(value, int) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, UTC) if value > 0 else None
        if not isinstance(value, str) or len(value) > 40:
            return None
        if _EPOCH.fullmatch(value):
            return datetime.fromtimestamp(int(value), UTC) if int(value) > 0 else None
        parsed = datetime.fromisoformat(value)
    except (ValueError, OverflowError, OSError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _uuid(value: Any) -> uuid.UUID | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _tag_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names = []
    for tag in value:
        name = tag.get("name") if isinstance(tag, dict) else None
        if isinstance(name, str) and name.strip():
            names.append(name)
    return names


def _attribute_tags(attribute: Mapping[str, Any]) -> list[str]:
    """The attribute's own tags, then its event's (`includeEventTags`), de-duplicated."""
    event = attribute.get("Event")
    names = _tag_names(attribute.get("Tag"))
    if isinstance(event, dict):
        names += _tag_names(event.get("Tag"))
    seen: dict[str, None] = {}
    for name in names:
        seen.setdefault(name, None)
    return list(seen)


def tlp_labels(names: Iterable[str]) -> list[str]:
    """Known TLP markings only (TLP 1.0 and 2.0), most restrictive first."""
    found = {clean_text(n).lower() for n in names}
    return [label for label in _TLP_ORDER if label in found]


def attack_ids(names: Iterable[str]) -> list[str]:
    """T-ids from ATT&CK galaxy tags (`misp-galaxy:mitre-attack-pattern="Name - T1059.001"`)."""
    ids: list[str] = []
    for name in names:
        match = _GALAXY.fullmatch(name.strip())
        if match is None or "attack-pattern" not in match.group(1):
            continue
        for tid in _ATTACK_IN_TAG.findall(match.group(2)):
            if tid not in ids:
                ids.append(tid)
    return ids


def families(names: Iterable[str]) -> list[str]:
    found: list[str] = []
    for name in names:
        match = _GALAXY.fullmatch(name.strip())
        if match is None or match.group(1) not in _FAMILY_GALAXIES:
            continue
        family = clean_text(match.group(2).split(" - ")[0])
        if family and family not in found:
            found.append(family)
    return found


def _attribute(raw: Mapping[str, Any], tags: list[str]) -> MispAttribute | None:
    attr_type = _str(raw.get("type"))
    if attr_type is None:
        return None
    event_raw = raw.get("Event")
    event: Mapping[str, Any] = event_raw if isinstance(event_raw, dict) else {}
    event_id = _event_id(raw.get("event_id"))
    if event_id is None and "event_id" not in raw:
        event_id = _event_id(event.get("id"))
    try:
        return MispAttribute(
            type=attr_type,
            category=_str(raw.get("category")),
            to_ids=raw.get("to_ids") is True,
            first_seen=_timestamp(raw.get("first_seen")),
            last_seen=_timestamp(raw.get("last_seen")),
            timestamp=_timestamp(raw.get("timestamp")),
            event_id=event_id,
            event_info=_str(event.get("info")),
            event_uuid=_uuid(event.get("uuid")),
            tags=tags,
        )
    except ValidationError:
        return None


def build_result(base_url_norm: str, data: Any) -> ProviderResult:
    """`{"response": {"Attribute": [...]}}` -> a verdict-free result. Raises `bad_json` on any
    other shape."""
    response = data.get("response") if isinstance(data, dict) else None
    if isinstance(response, list) and not response:
        response = {"Attribute": []}  # some MISP versions answer an empty search with []
    raw_attributes = response.get("Attribute") if isinstance(response, dict) else None
    if not isinstance(raw_attributes, list):
        raise ProviderError(ProviderErrorKind.BAD_JSON)
    raw_attributes = [a for a in raw_attributes if isinstance(a, dict)]
    if not raw_attributes:
        return ProviderResult(provider=ProviderName.MISP, status=ResultStatus.NOT_FOUND)

    seen_tags: dict[str, None] = {}  # insertion-ordered set over EVERY attribute
    attributes: list[MispAttribute] = []
    for raw in raw_attributes:
        tags = _attribute_tags(raw)
        for tag in tags:
            seen_tags.setdefault(tag, None)
        if len(attributes) < MAX_ATTRIBUTES:
            attribute = _attribute(raw, tags)
            if attribute is not None:
                attributes.append(attribute)

    all_tags = list(seen_tags)
    event_ids = [a.event_id for a in attributes if a.event_id is not None]
    first = [a.first_seen for a in attributes if a.first_seen is not None]
    last = [a.last_seen for a in attributes if a.last_seen is not None]
    summary = MispSummary(
        attribute_count=len(raw_attributes),
        attributes=attributes,
        tlp=tlp_labels(all_tags),
    )
    return ProviderResult(
        provider=ProviderName.MISP,
        status=ResultStatus.OK,
        found=True,
        tags=all_tags[:MAX_TAGS],
        families=families(all_tags)[:MAX_FAMILIES],
        attack_ids=attack_ids(all_tags),
        first_seen=min(first) if first else None,
        last_seen=max(last) if last else None,
        summary=summary,
        permalink=f"{base_url_norm}/events/view/{event_ids[0]}" if event_ids else None,
    )


# --- TLS -----------------------------------------------------------------------------------


def tls_verify(settings: Settings) -> ssl.SSLContext | bool:
    """The certificate check for MISP: the default trust store, or `TI_MISP_CA_FILE`.
    `TI_MISP_INSECURE_TLS` (dev only; `_prod_guards` refuses it in prod) disables it."""
    if settings.ti_misp_insecure_tls and settings.env != "prod":
        log.warning("TI_MISP_INSECURE_TLS is set: MISP certificates are NOT verified (dev only)")
        return False
    if settings.ti_misp_ca_file:
        return ssl.create_default_context(cafile=settings.ti_misp_ca_file)
    return True


# --- the adapter ---------------------------------------------------------------------------


class MispProvider:
    def __init__(
        self,
        base: ValidatedBase,
        *,
        settings: Settings | None = None,
        resolver: Resolver | None = None,
        allow_private: bool | None = None,
    ) -> None:
        self._base = base
        self._settings = settings
        self._resolver = resolver
        self._allow_private = (
            allow_private
            if allow_private is not None
            else (settings.ti_misp_allow_private if settings is not None else None)
        )
        prefix = re.escape(base.path_prefix)
        self._allowed = (
            AllowedPath("POST", None, re.compile(rf"{prefix}/attributes/restSearch")),
            AllowedPath("GET", None, re.compile(rf"{prefix}/servers/getVersion")),
        )

    @property
    def name(self) -> ProviderName:
        return ProviderName.MISP

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.MISP].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return self._allowed

    @property
    def base(self) -> ValidatedBase:
        return self._base

    @property
    def org_host(self) -> str:
        """What `AllowedPath(host=None)` entries refer to (`ti_client(org_host=...)`)."""
        return self._base.host

    def pinned_transport(
        self, inner: httpx.AsyncBaseTransport | None = None
    ) -> httpx.AsyncBaseTransport:
        """The transport every MISP request must use: resolve + check + pin per request.
        `inner` (tests) replaces the real TLS transport."""
        if inner is None:
            verify: ssl.SSLContext | bool = True
            if self._settings is not None:
                verify = tls_verify(self._settings)
            inner = httpx.AsyncHTTPTransport(verify=verify, trust_env=False, retries=0)
        return PinnedTransport(
            inner, self._base, resolver=self._resolver, allow_private=self._allow_private
        )

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        if ioc.ioc_type not in MISP_TYPES:
            raise ProviderError(ProviderErrorKind.INVALID_INPUT)
        response = await fetch_json(
            client,
            "POST",
            f"{self._base.base_url_norm}/attributes/restSearch",
            json_body=search_body(ioc),
            headers={"Content-Type": "application/json"},
            max_bytes=MISP_MAX_BODY_BYTES,
        )
        try:
            return build_result(self._base.base_url_norm, response.data)
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        try:
            response = await fetch_json(
                client,
                "GET",
                f"{self._base.base_url_norm}/servers/getVersion",
                max_bytes=MISP_MAX_BODY_BYTES,
            )
        except MispUrlNotPublic:
            return VerifyOutcome(VerifyStatus.INVALID, MispUrlNotPublic.code)
        except ProviderError as exc:
            if exc.kind is ProviderErrorKind.AUTH:
                return VerifyOutcome(VerifyStatus.INVALID, "auth")
            return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
        data = response.data
        if not isinstance(data, dict) or not isinstance(data.get("version"), str):
            return VerifyOutcome(VerifyStatus.ERROR, ProviderErrorKind.BAD_JSON.value)
        return VerifyOutcome(VerifyStatus.VALID)


def create(ctx: ProviderContext) -> MispProvider:
    """Raises `MispUrlInvalid` (a `ValueError`) for a URL that is not a normalized, valid
    MISP base URL: the stored URL is exactly the one the key is bound to."""
    settings = ctx.settings
    base = validate_base_url(
        ctx.base_url_norm,
        allowed_ports=settings.ti_misp_allowed_ports,
        allow_private=settings.ti_misp_allow_private,
    )
    if base.base_url_norm != ctx.base_url_norm:
        raise ValueError("misp base_url is not normalized")
    return MispProvider(base, settings=settings)


__all__ = [
    "MISP_TYPES",
    "MispProvider",
    "attack_ids",
    "build_result",
    "create",
    "families",
    "search_body",
    "tlp_labels",
    "tls_verify",
]
