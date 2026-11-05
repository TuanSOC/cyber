"""Value transforms (M5 phase 4), applied to every string field in this order:

1. `text.sanitize` (strip counts recorded) + NFC, then neutralize pseudonym-shaped tokens
   already present in the raw value (`INT_IP_7` -> `INT-IP-7`, counted, RT15);
2. URL query values replaced (`?a=…&b=…`, keys kept) and fragments dropped;
3. pseudonymize internal IPs / hostnames / usernames in value fields only (structural
   fields such as types, detection methods, ids and hashes are left alone, see
   `fields.STRUCTURAL`; hostname-typed fields also treat a
   single-label name as internal);
4. `text.defang` URLs and domains (IPs stay plain);
5. `text.truncate(256)`, counted per kind (the marker stays inside the value; `context_stats`
   never carries field names, RT4).

Digest claims (`D` items) are model output that already went through post-processing and
carry real pseudonyms: they skip steps 1b-3 (no neutralization, no new pseudonyms).
Non-string scalars pass through unchanged.
"""

import re
from collections import Counter
from dataclasses import dataclass, field

from app.modules.ai import text as aitext
from app.modules.ai.context.fields import HostList, RawItem, RawValue, is_structural
from app.modules.ai.context.pseudonymize import Pseudonymizer, neutralize
from app.modules.ai.contracts import FieldValue, RefKind

MAX_FIELD_CHARS = 256
REDACTED = "…"
_URL = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s\"'<>]+", re.IGNORECASE)


# A schemeless query in free text (`/login.php?user=alice&s=x`, `?a=1`): a `?` directly
# followed by `key=` (so prose like "why? because" is untouched), up to whitespace.
_QUERY = re.compile(r"\?([^\s?#\"'<>=&]*=[^\s#\"'<>]*)(#[^\s\"'<>]*)?")


def redact_query(query: str) -> str:
    parts = []
    for part in query.split("&"):
        if not part:
            continue
        key, eq, _ = part.partition("=")
        parts.append(f"{key}={REDACTED}" if eq else REDACTED)
    return "&".join(parts)


def redact_url(url: str) -> str:
    """Query values -> `…` (keys kept; a bare parameter is replaced whole); no fragment."""
    url = url.partition("#")[0]
    base, sep, query = url.partition("?")
    if not sep:
        return base
    parts = redact_query(query)
    return f"{base}?{parts}" if parts else base


def redact_urls(value: str) -> str:
    """Every URL (with a scheme) and every schemeless `?key=value` query in a text."""
    value = _URL.sub(lambda m: redact_url(m.group(0)), value)
    return _QUERY.sub(lambda m: "?" + redact_query(m.group(1)), value)


@dataclass
class ItemCounts:
    """What transforming one item recorded (added to the context stats only if it is sent)."""

    stripped: aitext.StripCounts = field(default_factory=aitext.StripCounts)
    neutralized: int = 0
    truncated: int = 0


@dataclass
class Totals:
    stripped: aitext.StripCounts = field(default_factory=aitext.StripCounts)
    neutralized: int = 0
    truncated_fields: Counter[RefKind] = field(default_factory=Counter)
    dropped_keys: int = 0

    def add(self, kind: RefKind, item: RawItem, counts: ItemCounts) -> None:
        self.stripped.add(counts.stripped)
        self.neutralized += counts.neutralized
        truncated = counts.truncated + item.capped
        if truncated:
            self.truncated_fields[kind] += truncated
        self.dropped_keys += item.dropped_keys


class Transformer:
    def __init__(self, pseudonymizer: Pseudonymizer, *, max_chars: int = MAX_FIELD_CHARS) -> None:
        self.pseudonymizer = pseudonymizer
        self.max_chars = max_chars

    def _clean(self, value: str, counts: ItemCounts, *, trusted: bool) -> str:
        clean, stripped = aitext.sanitize(value)
        counts.stripped.add(stripped)
        clean = aitext.nfc(clean)
        if not trusted:
            clean, n = neutralize(clean)
            counts.neutralized += n
            clean = redact_urls(clean)
        return clean

    def _string(
        self,
        value: str,
        counts: ItemCounts,
        *,
        host: bool,
        trusted: bool,
        structural: bool,
        url: bool = False,
    ) -> str:
        clean = self._clean(value, counts, trusted=trusted)
        if url and not trusted:
            # A URI-typed value: even a bare query (`?abcd1234`) and the fragment go.
            clean = " ".join(redact_url(part) for part in clean.split(" "))
        if not trusted and not structural:
            if host:
                clean = self.pseudonymizer.host_field(clean)
            else:
                clean = self.pseudonymizer.text(clean)
        clean = aitext.defang(clean)
        out = aitext.truncate(clean, self.max_chars)
        if out != clean:
            counts.truncated += 1
        return out

    def _host_list(self, value: HostList, counts: ItemCounts) -> str:
        parts = []
        for name, n in value.entries:
            clean = self._clean(name, counts, trusted=False)
            parts.append(f"{aitext.defang(self.pseudonymizer.host_field(clean))} ({n})")
        joined = ", ".join(parts)
        out = aitext.truncate(joined, self.max_chars)
        if out != joined:
            counts.truncated += 1
        return out

    def value(
        self,
        value: RawValue,
        counts: ItemCounts,
        *,
        host: bool = False,
        trusted: bool = False,
        structural: bool = False,
        url: bool = False,
    ) -> FieldValue:
        if isinstance(value, HostList):
            return self._host_list(value, counts)
        if isinstance(value, str):
            return self._string(
                value, counts, host=host, trusted=trusted, structural=structural, url=url
            )
        return value

    def fields(
        self, item: RawItem, *, trusted: bool = False
    ) -> tuple[dict[str, FieldValue], ItemCounts]:
        counts = ItemCounts()
        out: dict[str, FieldValue] = {}
        for name in sorted(item.fields):
            out[name] = self.value(
                item.fields[name],
                counts,
                host=name in item.host_fields,
                trusted=trusted,
                structural=is_structural(item.kind, name),
                url=name in item.url_fields,
            )
        return out, counts
