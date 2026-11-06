"""Value helpers of the normalizers: tool values -> contract-safe values, or None."""

import ipaddress
from datetime import UTC, datetime

EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
LATEST = datetime(2100, 1, 1, tzinfo=UTC)
U64 = 2**64 - 1
U32 = 2**32 - 1


def text(value: object, limit: int) -> str | None:
    """str only, NUL removed, lone surrogates replaced, cut; empty -> None."""
    if not isinstance(value, str):
        return None
    clean = value.replace("\x00", "")[:limit]
    clean = clean.encode("utf-8", "replace").decode("utf-8")
    return clean if clean.strip() else None


def u64(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= U64:
        return value
    return None


def u32(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= U32:
        return value
    return None


def count(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**63:
        return value
    return None


def port(value: object) -> int | None:
    if isinstance(value, str) and value.isdigit() and len(value) <= 5:
        value = int(value)
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535:
        return value
    return None


def ip(value: object) -> str | None:
    """Plain IPv4 / IPv6 (no zone id); `*`, empty or anything else -> None."""
    if not isinstance(value, str) or "%" in value or not 0 < len(value) <= 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def timestamp(value: object) -> datetime | None:
    """ISO 8601 (the probe writes UTC) inside the contract's 1970..2100 window."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    try:
        parsed = parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        return None
    return parsed if EARLIEST <= parsed < LATEST else None


def iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def hex_head(value: object, max_bytes: int = 64) -> str:
    """Lowercase hex of at most `max_bytes` bytes (an odd or non-hex value -> empty)."""
    if not isinstance(value, str):
        return ""
    head = value.strip().lower()[: max_bytes * 2]
    if len(head) % 2 or any(c not in "0123456789abcdef" for c in head):
        return ""
    return head


def has_pe(head_hex: str) -> bool:
    """`MZ`, plus `PE\\0\\0` at `e_lfanew` when that offset lies inside the captured head
    (when it lies beyond the head, the MZ header alone counts)."""
    head = bytes.fromhex(head_hex)
    if head[:2] != b"MZ":
        return False
    if len(head) < 0x40:
        return True
    lfanew = int.from_bytes(head[0x3C:0x40], "little")
    if lfanew + 4 <= len(head):
        return head[lfanew : lfanew + 4] == b"PE\x00\x00"
    return True


__all__ = [
    "count",
    "has_pe",
    "hex_head",
    "ip",
    "iso",
    "port",
    "text",
    "timestamp",
    "u32",
    "u64",
]
