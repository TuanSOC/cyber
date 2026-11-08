import base64
import time
from datetime import UTC, datetime

try:
    import pyotp
except ImportError:
    pyotp = None
import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.modules.identity import totp

# RFC 6238 Appendix B test seed: ASCII "12345678901234567890" (20 bytes)
RFC_6238_SEED = b"12345678901234567890"

# RFC 6238 Appendix B SHA-1 8-digit test vectors: (time_seconds, expected_step, expected_8_digit)
RFC_6238_VECTORS = [
    (59, 1, "94287082"),
    (1111111109, 37037036, "07081804"),
    (1111111111, 37037037, "14050471"),
    (1234567890, 41152263, "89005924"),
    (2000000000, 66666666, "69279037"),
    (20000000000, 666666666, "65353130"),
]

# RFC 4226 Appendix D 6-digit HOTP test vectors: (count, expected_6_digit)
RFC_4226_VECTORS = [
    (0, "755224"),
    (1, "287082"),
    (2, "359152"),
    (3, "969429"),
    (4, "338314"),
    (5, "254676"),
    (6, "287922"),
    (7, "162583"),
    (8, "399871"),
    (9, "520489"),
]


def test_rfc_6238_sha1_vectors():
    for t, step, expected_8_digit in RFC_6238_VECTORS:
        code_8 = totp.code_at(RFC_6238_SEED, step, digits=8)
        assert code_8 == expected_8_digit


def test_rfc_4226_hotp_vectors():
    for count, expected_6_digit in RFC_4226_VECTORS:
        code_6 = totp.code_at(RFC_6238_SEED, count, digits=6)
        assert code_6 == expected_6_digit


def test_totp_secret_generation_and_b32():
    secret = totp.new_secret()
    assert len(secret) == 20
    b32_str = totp.b32(secret)
    assert len(b32_str) == 32
    decoded = totp.decode_b32(b32_str)
    assert decoded == secret


def test_otpauth_uri_format():
    secret = totp.new_secret()
    uri = totp.otpauth_uri(secret, "analyst@cyberlab.local", issuer="CyberLab")
    b32_str = totp.b32(secret)
    assert uri.startswith("otpauth://totp/CyberLab:analyst%40cyberlab.local?")
    assert f"secret={b32_str}" in uri
    assert "issuer=CyberLab" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_verify_window_edges():
    secret = totp.new_secret()
    t0 = 1000000.0
    current_step = int(t0 // 30)

    # Window = 1 accepts step - 1, step, step + 1
    code_prev = totp.code_at(secret, current_step - 1)
    code_curr = totp.code_at(secret, current_step)
    code_next = totp.code_at(secret, current_step + 1)
    code_too_early = totp.code_at(secret, current_step - 2)
    code_too_late = totp.code_at(secret, current_step + 2)

    assert totp.verify(secret, code_prev, t0, window=1) == current_step - 1
    assert totp.verify(secret, code_curr, t0, window=1) == current_step
    assert totp.verify(secret, code_next, t0, window=1) == current_step + 1

    # Outside window should be rejected
    assert totp.verify(secret, code_too_early, t0, window=1) is None
    assert totp.verify(secret, code_too_late, t0, window=1) is None


def test_verify_datetime_support():
    secret = totp.new_secret()
    dt = datetime(2026, 11, 7, 12, 0, 0, tzinfo=UTC)
    current_step = int(dt.timestamp() // 30)
    code = totp.code_at(secret, current_step)
    assert totp.verify(secret, code, dt) == current_step


@pytest.mark.parametrize(
    "invalid_code",
    [
        "",
        "12345",
        "1234567",
        "abcdef",
        "12345a",
        "12 345",
        "12345\n",
        "-12345",
        None,
        123456,
    ],
)
def test_verify_invalid_code_formats(invalid_code):
    secret = totp.new_secret()
    assert totp.verify(secret, invalid_code, time.time()) is None


def test_pyotp_cross_check():
    if pyotp is None:
        pytest.skip("pyotp not installed in environment")
    secret = totp.new_secret()
    b32_str = totp.b32(secret)
    pyotp_inst = pyotp.TOTP(b32_str, digits=6, interval=30)

    now = time.time()
    expected = pyotp_inst.at(now)
    actual = totp.code_at(secret, int(now // 30))
    assert actual == expected

    # Verify matching
    assert totp.verify(secret, expected, now) == int(now // 30)


@given(st.integers(min_value=0, max_value=2000000000))
def test_hypothesis_pyotp_equivalence(ts):
    if pyotp is None:
        pytest.skip("pyotp not installed in environment")
    secret = totp.new_secret()
    b32_str = totp.b32(secret)
    pyotp_inst = pyotp.TOTP(b32_str, digits=6, interval=30)

    pyotp_code = pyotp_inst.at(ts)
    our_code = totp.code_at(secret, ts // 30)
    assert our_code == pyotp_code
