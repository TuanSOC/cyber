"""Keyset cursors of the M6 case-management lists (notes, status history, IOC collections and
their items): the last row's `(timestamp, id)` as an opaque URL-safe token. Lists are newest
first, so the next page holds the rows strictly before that key."""

import base64
import binascii
import json
import uuid
from datetime import datetime

from app.core.errors import AppError


class InvalidCursor(AppError):
    status_code = 400
    code = "invalid_cursor"
    message = "The cursor is not valid for this list"


def encode(ts: datetime, row_id: uuid.UUID) -> str:
    raw = json.dumps([ts.isoformat(), str(row_id)]).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode(token: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        ts, row_id = json.loads(raw)
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            raise ValueError("cursor")
        return parsed, uuid.UUID(row_id)
    except (ValueError, TypeError, binascii.Error):
        raise InvalidCursor() from None


def encode_offset(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def decode_offset(token: str, *, maximum: int = 10_000_000) -> int:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        offset = json.loads(raw)["o"]
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= maximum:
            raise ValueError("cursor")
        return offset
    except (ValueError, TypeError, KeyError, binascii.Error):
        raise InvalidCursor() from None
