"""The correlation key of one observable (M7 phase 4; frozen signature from phase 1).

It delegates to M6's `ioc_collections.normalize.normalize_item` (RT8), which runs the M4 TI
normalizer, keeps private values and internal names, and keys the pcap-only types with
`opaque_key`, so `key` is byte-identical to `ti_results.ioc_key` and
`ioc_collection_items.ioc_key`. Nothing here re-normalizes on top of it (no lowercasing of a
JA3, no other rule): an extra rule would break the join.

`registry_key` and `file_path` are not indexed (host-specific noise); a value
`normalize_item` refuses (`Invalid`) yields None and is counted by the caller, never raised.
"""

import ipaddress
import re

from app.modules.correlation.models import CORRELATION_KINDS, VALUE_MAX_CHARS
from app.modules.ioc_collections.normalize import Item, normalize_item
from app.modules.threat_intel.normalize import refang

NOT_INDEXED = frozenset({"registry_key", "file_path"})
_KINDS = frozenset(CORRELATION_KINDS)
_HEX = re.compile(r"[0-9a-fA-F]+")
# A JA3 / JA3S string (`771,4865-4866,0-23,29-23,0`) as Zeek and the pcap analyzer emit it.
_JA3_STRING = re.compile(r"[0-9]+(,[0-9-]*){4}")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

Key = tuple[str, str, str]


def correlation_key(ioc_type: str, raw: str) -> Key | None:
    """`(kind, key, value_norm)`, or None when the type is not indexed or the value does not
    normalize."""
    if ioc_type.strip().lower() in NOT_INDEXED:
        return None
    item = normalize_item(ioc_type, raw)
    if not isinstance(item, Item) or item.ioc_type not in _KINDS:
        return None
    if not 1 <= len(item.value_norm) <= VALUE_MAX_CHARS:
        return None
    return item.ioc_type, item.ioc_key, item.value_norm


def _detected_type(text: str) -> str:
    """The M4 `_detect` order for an untyped value (after refanging): IP by parse, a hash by
    length, `://` a URL, `@` an email, else a domain."""
    stripped = text.strip()
    candidate = stripped[1:-1] if stripped.startswith("[") and stripped.endswith("]") else stripped
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass
    if len(stripped) in _HASH_TYPES and _HEX.fullmatch(stripped):
        return _HASH_TYPES[len(stripped)]
    if "://" in stripped:
        return "url"
    if "@" in stripped:
        return "email"
    return "domain"


def candidate_keys(raw: str) -> list[Key]:
    """Every key an untyped search value may name, most likely first: the detected type, then
    the pcap-only types (a 32-hex value may be a JA3 / JA3S hash, a 64-hex one a certificate
    hash, a comma list a JA3 string). Duplicates removed; possibly empty."""
    text = raw.strip()
    found: list[Key] = []
    first = correlation_key(_detected_type(refang(text)), text)
    if first is not None:
        found.append(first)
    extra: tuple[str, ...] = ()
    if _HEX.fullmatch(text) and len(text) == 32:
        extra = ("ja3", "ja3s")
    elif _HEX.fullmatch(text) and len(text) == 64:
        extra = ("cert_sha256",)
    elif _JA3_STRING.fullmatch(text):
        extra = ("ja3", "ja3s")
    for kind in extra:
        key = correlation_key(kind, text)
        if key is not None and key not in found:
            found.append(key)
    return found
