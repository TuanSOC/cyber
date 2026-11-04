"""MISP base URL: the syntactic check run by the API on save (no DNS, RT5)."""

import pytest

from app.modules.threat_intel.ssrf import MispUrlInvalid, validate_base_url

PORTS = (443, 8443)


def _valid(url: str) -> str:
    return validate_base_url(url, allowed_ports=PORTS, allow_private=False).base_url_norm


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://MISP.Acme-Corp.net", "https://misp.acme-corp.net"),
        ("https://misp.acme-corp.net/", "https://misp.acme-corp.net"),
        ("https://misp.acme-corp.net:443/", "https://misp.acme-corp.net"),
        ("https://misp.acme-corp.net:8443//misp//", "https://misp.acme-corp.net:8443/misp"),
        ("https://bücher.de/misp", "https://xn--bcher-kva.de/misp"),
        ("https://8.8.8.8/", "https://8.8.8.8"),
        ("https://[2606:4700::1111]:8443/a", "https://[2606:4700::1111]:8443/a"),
        ("  https://misp.acme-corp.net/a/b  ", "https://misp.acme-corp.net/a/b"),
    ],
)
def test_valid_urls(url: str, expected: str) -> None:
    assert _valid(url) == expected


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://misp.acme-corp.net", "scheme"),
        ("ftp://misp.acme-corp.net", "scheme"),
        ("misp.acme-corp.net", "scheme"),
        ("https://user:pw@misp.acme-corp.net", "userinfo"),
        ("https://user@misp.acme-corp.net", "userinfo"),
        ("https://misp.acme-corp.net/?a=b", "query"),
        ("https://misp.acme-corp.net/?", "query"),
        ("https://misp.acme-corp.net/#x", "fragment"),
        ("https://misp.acme-corp.net:22/", "port"),
        ("https://misp.acme-corp.net:80/", "port"),
        ("https://2130706433/", "host"),  # decimal 127.0.0.1
        ("https://0177.0.0.1/", "host"),  # octal
        ("https://0x7f.0.0.1/", "host"),
        ("https://127.0.0.1/", "ip_not_public"),
        ("https://10.0.0.5/", "ip_not_public"),
        ("https://169.254.169.254/", "ip_not_public"),
        ("https://[::ffff:10.0.0.1]/", "ip_not_public"),
        ("https://[64:ff9b::a00:1]/", "ip_not_public"),
        ("https://misp.local/", "special_use_name"),
        ("https://misp.internal/", "special_use_name"),
        ("https://misp.corp/", "special_use_name"),
        ("https://1.0.168.192.in-addr.arpa/", "special_use_name"),
        ("https://localhost/", "special_use_name"),
        ("https://misp/", "host"),
        ("https://misp.acme-corp.net/../etc", "path"),
        ("https://misp.acme-corp.net/a%2f..", "path"),
        ("https://misp.acme-corp.net/" + "a/" * 200, "path"),
        ("https://misp.acme-corp.net/a b", "invalid"),
        ("https://misp.acme-corp.net:99999/", "invalid"),
        ("https://" + "a" * 600 + ".com", "too_long"),
        ("", "invalid"),
    ],
)
def test_refused_urls(url: str, reason: str) -> None:
    with pytest.raises(MispUrlInvalid) as caught:
        validate_base_url(url, allowed_ports=PORTS, allow_private=False)
    assert caught.value.reason == reason
    assert caught.value.code == "misp_url_invalid"
    assert "pw" not in str(caught.value)  # the URL (userinfo) is never echoed


def test_dev_allow_private_keeps_loopback_and_metadata_refused() -> None:
    assert validate_base_url("https://10.0.0.5/", allowed_ports=PORTS, allow_private=True)
    for url in ("https://127.0.0.1/", "https://169.254.169.254/", "https://0.0.0.0/"):
        with pytest.raises(MispUrlInvalid):
            validate_base_url(url, allowed_ports=PORTS, allow_private=True)


def test_result_fields() -> None:
    v = validate_base_url(
        "https://Misp.Acme-Corp.net:8443/misp/", allowed_ports=PORTS, allow_private=False
    )
    assert (v.host, v.port, v.path_prefix, v.is_ip_literal) == (
        "misp.acme-corp.net",
        8443,
        "/misp",
        False,
    )


def test_default_ports_come_from_settings() -> None:
    # TI_MISP_ALLOWED_PORTS defaults to 443 and 8443.
    assert validate_base_url("https://misp.acme-corp.net:8443").port == 8443
    with pytest.raises(MispUrlInvalid):
        validate_base_url("https://misp.acme-corp.net:9443")
