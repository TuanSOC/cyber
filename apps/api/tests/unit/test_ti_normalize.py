"""IOC normalization and provider eligibility (M4 phase 2; RT4, RT13)."""

import pytest

from app.modules.threat_intel.normalize import (
    Normalized,
    Note,
    Skip,
    SkipReason,
    eligible,
    normalize,
    normalize_suffix,
    refang,
)
from app.modules.threat_intel.providers.base import IocType, ProviderName, compute_ioc_key

REAL = [p for p in ProviderName if p is not ProviderName.MOCK]


def _ok(hint: str | None, raw: str) -> Normalized:
    out = normalize(hint, raw)
    assert isinstance(out, Normalized), out
    assert out.ioc_key == compute_ioc_key(out.ioc_type, out.value_norm)
    return out


def _skip(hint: str | None, raw: str) -> Skip:
    out = normalize(hint, raw)
    assert isinstance(out, Skip), out
    return out


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hxxp://evil[.]example[.]net/a", "http://evil.example.net/a"),
        ("hxxps[:]//evil(.)example(.)net/", "https://evil.example.net/"),
        ("evil[dot]example[.]net", "evil.example.net"),
        ("user[@]evil[.]example[.]net", "user@evil.example.net"),
        ("HXXPS://a[.]b", "https://a.b"),
    ],
)
def test_refang(raw: str, expected: str) -> None:
    assert refang(raw) == expected


def test_refanged_values_are_noted() -> None:
    out = _ok("domain", "evil[.]acme-corp[.]net")
    assert out.value_norm == "evil.acme-corp.net"
    assert Note.REFANGED in out.notes


@pytest.mark.parametrize(
    "raw",
    [
        "100.64.0.1",  # CGNAT
        "10.0.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",  # link-local / cloud metadata
        "0.0.0.0",  # noqa: S104
        "192.0.2.10",  # documentation
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "2002:c0a8:0101::1",  # 6to4 of 192.168.1.1
        "64:ff9b::a00:1",  # NAT64 of 10.0.0.1 (ipaddress calls it global)
        "64:ff9b:1::1",  # local-use NAT64
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
        "2001:db8::1",  # documentation
        "fe80::1",
        "fc00::1",
        "ff0e::1",  # global-scope multicast
        "::8.8.8.8",  # IPv4-compatible (deprecated)
    ],
)
def test_non_global_ips_are_skipped(raw: str) -> None:
    assert _skip("ip", raw).reason is SkipReason.NOT_GLOBAL_IP


@pytest.mark.parametrize(
    ("raw", "ioc_type", "value"),
    [
        ("8.8.8.8", IocType.IPV4, "8.8.8.8"),
        ("::ffff:8.8.8.8", IocType.IPV4, "8.8.8.8"),
        ("2001:4860:4860:0::8888", IocType.IPV6, "2001:4860:4860::8888"),
        ("64:ff9b::808:808", IocType.IPV6, "64:ff9b::808:808"),
        ("[2606:4700::1111]", IocType.IPV6, "2606:4700::1111"),
    ],
)
def test_global_ips(raw: str, ioc_type: IocType, value: str) -> None:
    out = _ok("ip", raw)
    assert (out.ioc_type, out.value_norm) == (ioc_type, value)


@pytest.mark.parametrize("raw", ["2130706433", "0177.0.0.1", "127.1", "1.2.3.4.5", "fe80::1%eth0"])
def test_ip_tricks_are_invalid(raw: str) -> None:
    assert _skip("ip", raw).reason is SkipReason.INVALID


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Evil.Acme-Corp.NET.", "evil.acme-corp.net"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("_dmarc.acme-corp.net", "_dmarc.acme-corp.net"),
    ],
)
def test_domains(raw: str, expected: str) -> None:
    assert _ok("domain", raw).value_norm == expected


@pytest.mark.parametrize(
    "raw",
    [
        "printer.local",
        "nas.home.arpa",
        "5.1.168.192.in-addr.arpa",
        "1.0.0.0.ip6.arpa",
        "nas.home",
        "fs.corp",
        "db.internal",
        "box.lan",
        "x.private",
        "wiki.intranet",
        "host.localdomain",
        "a.test",
        "a.example",
        "a.invalid",
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "localhost",
        "example.com",
        "hit.example.com",
        "x.example.net",
        "x.example.org",
    ],
)
def test_special_use_names_are_skipped(raw: str) -> None:
    out = _skip("domain", raw)
    assert out.reason is SkipReason.SPECIAL_USE_NAME
    assert out.value_norm == raw.lower()  # kept for the report and the mock exemption


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("intranetbox", SkipReason.SINGLE_LABEL),
        ("a" * 64 + ".com", SkipReason.INVALID),
        ("-bad.com", SkipReason.INVALID),
        ("bad..com", SkipReason.INVALID),
        ("10.0.0.1", SkipReason.INVALID),  # an IP typed as a domain
        ("1.2.3.999", SkipReason.INVALID),
        (("a" * 60 + ".") * 5 + "com", SkipReason.TOO_LONG),
        ("x" * 3000, SkipReason.TOO_LONG),
    ],
)
def test_bad_domains(raw: str, reason: SkipReason) -> None:
    assert _skip("domain", raw).reason is reason


def test_url_query_and_fragment_are_removed() -> None:
    out = _ok("url", "https://Login.Acme-Corp.net/reset?token=s3cr3t&user=bob#frag")
    assert out.value_norm == "https://login.acme-corp.net/reset"
    assert Note.QUERY_REMOVED in out.notes
    assert out.ioc_key == compute_ioc_key(IocType.URL, "https://login.acme-corp.net/reset")
    assert _ok("url", "http://acme-corp.net:8080").value_norm == "http://acme-corp.net:8080/"
    assert _ok("url", "https://acme-corp.net:443/a").value_norm == "https://acme-corp.net/a"
    assert _ok("url", "http://8.8.8.8/x?y").value_norm == "http://8.8.8.8/x"
    assert _ok("url", "http://[2606:4700::1111]/").value_norm == "http://[2606:4700::1111]/"
    assert Note.QUERY_REMOVED not in _ok("url", "https://acme-corp.net/a").notes


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("https://user:pw@acme-corp.net/", SkipReason.HAS_USERINFO),
        ("https://user@acme-corp.net/", SkipReason.HAS_USERINFO),
        ("ftp://acme-corp.net/file", SkipReason.BAD_SCHEME),
        ("javascript:alert(1)", SkipReason.BAD_SCHEME),
        ("acme-corp.net/path", SkipReason.BAD_SCHEME),
        ("http://10.0.0.1/admin", SkipReason.NOT_GLOBAL_IP),
        ("http://[::ffff:192.168.0.1]/", SkipReason.NOT_GLOBAL_IP),
        ("http://169.254.169.254/latest/meta-data", SkipReason.NOT_GLOBAL_IP),
        ("http://router.lan/", SkipReason.SPECIAL_USE_NAME),
        ("http://5.1.168.192.in-addr.arpa/", SkipReason.SPECIAL_USE_NAME),
        ("http://fileserver/", SkipReason.SINGLE_LABEL),
        ("http://intranet/", SkipReason.SPECIAL_USE_NAME),
        ("http://acme-corp.net/a b", SkipReason.INVALID),
        ("http://acme-corp.net:99999/", SkipReason.INVALID),
        ("https://acme-corp.net/" + "a" * 2100, SkipReason.TOO_LONG),
    ],
)
def test_bad_urls(raw: str, reason: SkipReason) -> None:
    assert _skip("url", raw).reason is reason


@pytest.mark.parametrize(
    ("hint", "raw"),
    [
        # WHATWG URL parsers and inet_aton read a numeric (hex/octal/decimal) last label as
        # an IPv4 address: these are private/loopback IPs in disguise, never names.
        ("url", "http://10.0.0.0x1/a"),
        ("url", "http://127.0.0.0x1:8080/x"),
        ("url", "http://0x7f.0x0.0x0.0x1/"),
        ("url", "http://0X7F.0X0.0X0.0X1/"),
        ("url", "http://0x7f000001/"),
        ("url", "http://127.0x/"),
        ("url", "http://169.254.169.0xfe/latest"),
        ("domain", "192.168.0.0x1"),
        ("domain", "0x7f.0x0.0x0.0x1"),
        ("domain", "acme-corp.0x1"),
        ("domain", "10.0.0.010"),
        ("email", "a@10.0.0.0x1"),
        (None, "192.168.0.0x1"),
        (None, "http://10.0.0.0x1/"),
    ],
)
def test_numeric_last_labels_are_never_names(hint: str | None, raw: str) -> None:
    out = normalize(hint, raw)
    assert isinstance(out, Skip), out
    assert out.reason in (SkipReason.INVALID, SkipReason.NOT_GLOBAL_IP), out
    for provider in ProviderName:
        assert isinstance(eligible(out, provider), Skip)


@pytest.mark.parametrize("raw", ["0xdead.acme-corp.net", "x0x1.com", "a.0xyz", "a.co"])
def test_hex_looking_labels_that_are_names(raw: str) -> None:
    assert _ok("domain", raw).value_norm == raw


@pytest.mark.parametrize(
    ("hint", "raw", "ioc_type"),
    [
        ("file_md5", "D41D8CD98F00B204E9800998ECF8427E", IocType.MD5),
        ("file_sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", IocType.SHA1),
        (
            "file_sha256",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            IocType.SHA256,
        ),
        (None, "d41d8cd98f00b204e9800998ecf8427e", IocType.MD5),
    ],
)
def test_hashes(hint: str | None, raw: str, ioc_type: IocType) -> None:
    out = _ok(hint, raw)
    assert out.ioc_type is ioc_type
    assert out.value_norm == raw.lower()


@pytest.mark.parametrize(
    ("hint", "raw"),
    [
        ("file_md5", "d41d8cd98f00b204e9800998ecf8427"),  # 31
        ("file_sha256", "d41d8cd98f00b204e9800998ecf8427e"),  # md5 length
        ("file_sha1", "zz39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ],
)
def test_bad_hashes(hint: str, raw: str) -> None:
    assert _skip(hint, raw).reason is SkipReason.INVALID


@pytest.mark.parametrize("hint", ["ja3", "ja3s", "cert_sha256", "registry_key", "file_path", "x"])
def test_never_sent_types(hint: str) -> None:
    assert _skip(hint, "anything").reason is SkipReason.UNSUPPORTED_TYPE


def test_detection_for_manual_lookups() -> None:
    assert _ok(None, "8.8.8.8").ioc_type is IocType.IPV4
    assert _ok(None, "acme-corp.net").ioc_type is IocType.DOMAIN
    assert _ok(None, "https://acme-corp.net/x").ioc_type is IocType.URL
    assert _ok(None, "Bob@Acme-Corp.net").value_norm == "bob@acme-corp.net"
    assert _ok(None, "a" * 64).ioc_type is IocType.SHA256


def test_emails_only_go_to_misp_and_mock() -> None:
    out = _ok("email", "mailto:Alice@Acme-Corp.net")
    assert out.value_norm == "alice@acme-corp.net"
    for provider in REAL:
        verdict = eligible(out, provider)
        if provider is ProviderName.MISP:
            assert verdict == out
        else:
            assert isinstance(verdict, Skip) and verdict.reason is SkipReason.UNSUPPORTED_TYPE
    assert eligible(out, ProviderName.MOCK) == out
    assert _skip("email", "bob@printer.local").reason is SkipReason.SPECIAL_USE_NAME
    assert _skip("email", "not-an-email").reason is SkipReason.INVALID


def test_provider_type_support() -> None:
    ip = _ok("ip", "8.8.8.8")
    assert eligible(ip, ProviderName.ABUSEIPDB) == ip
    md5 = _ok("file_md5", "d41d8cd98f00b204e9800998ecf8427e")
    assert eligible(md5, ProviderName.ABUSEIPDB) == Skip(SkipReason.UNSUPPORTED_TYPE, IocType.MD5)
    sha1 = _ok("file_sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert isinstance(eligible(sha1, ProviderName.URLHAUS), Skip)  # URLhaus: md5/sha256 only
    assert eligible(sha1, ProviderName.MALWAREBAZAAR) == sha1


def test_excluded_suffixes() -> None:
    excluded = ("corp.acme-corp.net",)
    for raw, hint in [
        ("fs.corp.acme-corp.net", "domain"),
        ("corp.acme-corp.net", "domain"),
        ("https://wiki.corp.acme-corp.net/x", "url"),
    ]:
        verdict = eligible(normalize(hint, raw), ProviderName.VIRUSTOTAL, excluded)
        assert isinstance(verdict, Skip) and verdict.reason is SkipReason.EXCLUDED_SUFFIX
    other = _ok("domain", "notcorp.acme-corp.net")
    assert eligible(other, ProviderName.VIRUSTOTAL, excluded) == other
    assert normalize_suffix(".Corp.Acme-Corp.NET") == "corp.acme-corp.net"
    assert normalize_suffix("not a suffix!") is None


@pytest.mark.parametrize(
    ("hint", "raw"),
    [
        ("domain", "hit.example.com"),
        ("domain", "ratelimit-ra.example.com"),
        ("url", "http://hit.example.com/path?q=1"),
        ("email", "user@hit.example.com"),
    ],
)
def test_only_mock_accepts_its_example_com_names(hint: str, raw: str) -> None:
    out = normalize(hint, raw)
    assert isinstance(out, Skip) and out.reason is SkipReason.SPECIAL_USE_NAME
    for provider in REAL:
        assert eligible(out, provider) == out, provider
    accepted = eligible(out, ProviderName.MOCK)
    assert isinstance(accepted, Normalized)
    assert "?" not in accepted.value_norm
    # ...but not when the org excluded the suffix, nor for the other example names.
    assert isinstance(eligible(out, ProviderName.MOCK, ("example.com",)), Skip)
    assert isinstance(eligible(normalize("domain", "x.example.net"), ProviderName.MOCK), Skip)
    assert isinstance(eligible(normalize("domain", "a.local"), ProviderName.MOCK), Skip)


def test_skips_never_become_eligible_for_real_providers() -> None:
    for hint, raw in [
        ("ip", "10.0.0.1"),
        ("domain", "5.1.168.192.in-addr.arpa"),
        ("url", "http://10.1.1.1/?a=b"),
        ("domain", "nas.home"),
    ]:
        out = normalize(hint, raw)
        for provider in ProviderName:
            assert isinstance(eligible(out, provider), Skip), (raw, provider)


def test_garbage_input() -> None:
    assert _skip(None, "").reason is SkipReason.INVALID
    assert _skip(None, "   ").reason is SkipReason.INVALID
    assert _skip(None, "x" * 2049).reason is SkipReason.TOO_LONG
    assert _skip("domain", "evil‮.com").reason is SkipReason.INVALID
