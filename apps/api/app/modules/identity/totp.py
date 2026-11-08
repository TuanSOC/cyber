"""RFC 6238 TOTP verifier (M11 phase 5).

Implements RFC 6238 (TOTP) and RFC 4226 (HOTP dynamic truncation) with HMAC-SHA1,
30-second step, 6-digit default, candidate step verification with timing-safe
digest comparisons, and otpauth URI formatting.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote

STEP_SECONDS = 30
SECRET_BYTES = 20
DEFAULT_DIGITS = 6


def new_secret() -> bytes:
    """Generate 20 cryptographically secure random bytes (160 bits)."""
    return secrets.token_bytes(SECRET_BYTES)


def b32(secret: bytes) -> str:
    """Encode secret bytes to RFC 3548 Base32 uppercase string without padding."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def decode_b32(b32_secret: str) -> bytes:
    """Decode a Base32 string (with or without padding) back to bytes."""
    clean = b32_secret.strip().replace(" ", "").upper()
    pad_len = (8 - (len(clean) % 8)) % 8
    clean += "=" * pad_len
    return base64.b32decode(clean)


def otpauth_uri(secret: bytes, account: str, issuer: str = "CyberLab") -> str:
    """Generate an RFC-compliant otpauth:// URI for QR code generation."""
    secret_str = b32(secret)
    label = f"{quote(issuer)}:{quote(account)}"
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret_str}"
        f"&issuer={quote(issuer)}"
        f"&algorithm=SHA1"
        f"&digits={DEFAULT_DIGITS}"
        f"&period={STEP_SECONDS}"
    )


def code_at(secret: bytes, step: int, digits: int = DEFAULT_DIGITS) -> str:
    """Compute TOTP / HOTP code for given step using RFC 4226 dynamic truncation."""
    counter_bytes = struct.pack(">Q", step)
    digest = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = binary % (10**digits)
    return f"{code:0{digits}d}"


def verify(
    secret: bytes,
    code: str,
    now: float | datetime,
    window: int = 1,
) -> int | None:
    """Verify a 6-digit TOTP code against a candidate window [step - window, step + window].

    Only 6 ASCII digits are accepted. Every candidate step is compared with hmac.compare_digest
    and all candidate steps are always evaluated to avoid timing leakage.
    Returns the matched step (int) if valid, or None.
    """
    if not isinstance(code, str) or len(code) != DEFAULT_DIGITS or not code.isascii() or not code.isdigit():
        return None

    if isinstance(now, datetime):
        ts = now.timestamp()
    else:
        ts = float(now)

    current_step = int(ts // STEP_SECONDS)
    matched_step: int | None = None

    for offset in range(-window, window + 1):
        candidate_step = current_step + offset
        expected_code = code_at(secret, candidate_step, digits=DEFAULT_DIGITS)
        if hmac.compare_digest(expected_code, code):
            if matched_step is None:
                matched_step = candidate_step

    return matched_step

