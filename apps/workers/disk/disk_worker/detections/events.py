"""Reading normalised events (M9 phase 6): bounded, attribute first, Plaso message second.

Attribute names follow Plaso's event data (phase 3 keeps them as allow-listed scalars; lists are
flattened to `<name>.<i>` with `<name>_count`, see `evtx_fields.flatten_strings`). When an
attribute is missing, a few fields fall back to Plaso's formatted `message` (never to
`xml_string`, which is not exported). Every regex here is linear and runs on text of at most a
few KiB.
"""

import ipaddress
import re
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from cyberlab_jobs.disk import DiskEventRecord

from disk_worker.detections.base import CitedEvent, quoted

MAX_TEXT = 4096
_SYSLOG_MESSAGE = re.compile(r"^\[([^,\]]{1,64})(?:, pid: \d{1,10})?\] (.{0,4096})$", re.DOTALL)


def text(event: DiskEventRecord, name: str) -> str | None:
    value = event.attributes.get(name)
    return value[:MAX_TEXT] if isinstance(value, str) and value else None


def texts(event: DiskEventRecord, name: str, limit: int = 32) -> list[str]:
    """A flattened list attribute (`<name>.<i>`), or the plain attribute."""
    single = text(event, name)
    out = [single] if single else []
    for i in range(limit):
        value = text(event, f"{name}.{i}")
        if value is None:
            break
        out.append(value)
    return out


def number(event: DiskEventRecord, name: str) -> int | None:
    value = event.attributes.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def syslog(event: DiskEventRecord) -> tuple[str, str] | None:
    """(reporter, body) of a syslog-like line; None for other events."""
    if not event.data_type.startswith("syslog"):
        return None
    reporter = text(event, "reporter")
    body = text(event, "body")
    if reporter and body:
        return reporter, body
    found = _SYSLOG_MESSAGE.match(event.message)
    if found:
        return reporter or found.group(1), body or found.group(2)
    return None


def registry_key(event: DiskEventRecord) -> str | None:
    key = text(event, "key_path")
    if key:
        return key
    if event.message.startswith("["):
        end = event.message.find("]", 1, 1025)
        if end > 0:
            return event.message[1:end]
    return None


def message_after_key(event: DiskEventRecord) -> str:
    if event.message.startswith("["):
        end = event.message.find("]", 1, 1025)
        if end > 0:
            return event.message[end + 1 :].strip()
    return event.message


def address(value: str | None) -> IPv4Address | IPv6Address | None:
    """A routable-looking source address: not empty, `-`, loopback or unspecified."""
    if not value:
        return None
    raw = value.strip().strip("[]")
    if raw.startswith("::ffff:") and "." in raw:
        raw = raw[7:]
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified:
        return None
    return ip


def cited(event: DiskEventRecord, kind: str, title: str, src_ip: str | None = None) -> CitedEvent:
    """What a finding keeps of an event it cites (the title is masked here)."""
    return CitedEvent(event.ordinal, event.ts, kind, quoted(title, 255), src_ip)


def minute(ts: datetime) -> int:
    return int(ts.timestamp() // 60)


__all__ = [
    "address",
    "cited",
    "message_after_key",
    "minute",
    "number",
    "registry_key",
    "syslog",
    "text",
    "texts",
]
