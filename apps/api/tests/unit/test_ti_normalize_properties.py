"""Property tests of normalization and eligibility (M4 phase 7, hypothesis).

Whatever the input, nothing `eligible()` lets through for a provider is ever:
- a non-global IP, including one embedded in an IPv6 address (IPv4-mapped/compatible, 6to4,
  NAT64, Teredo);
- a special-use or internal name, or anything under `.arpa` (only `mock` accepts its own
  `example.com` behaviour names);
- a URL with a query string or fragment (or userinfo).

The oracle below is written independently of `normalize.py` (its own range and TLD lists),
so a regression there is not mirrored here.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from app.modules.threat_intel.normalize import Normalized, eligible, normalize
from app.modules.threat_intel.providers.base import IocType, ProviderName

PROFILE = settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    derandomize=True,  # reproducible in the gate; new seeds only when the strategies change
)

# --- the independent oracle ------------------------------------------------------------------

NOT_GLOBAL_V4 = [
    ipaddress.IPv4Network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
]
NOT_GLOBAL_V6 = [
    ipaddress.IPv6Network(n)
    for n in (
        "::/96",  # unspecified, loopback, IPv4-compatible
        "64:ff9b:1::/48",  # NAT64 local use
        "100::/64",  # discard
        "2001:db8::/32",  # documentation
        "2001::/32",  # Teredo (its client address is checked too)
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
]
NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
SPECIAL_TLDS = {
    "local",
    "localhost",
    "internal",
    "lan",
    "home",
    "corp",
    "private",
    "intranet",
    "localdomain",
    "test",
    "example",
    "invalid",
    "onion",
    "alt",
    "arpa",
}
EXAMPLE_SLDS = ("example.com", "example.net", "example.org")
PROVIDERS = list(ProviderName)


def _embedded_v4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    found = [a for a in (ip.ipv4_mapped, ip.sixtofour) if a is not None]
    if ip.teredo is not None:
        found += list(ip.teredo)
    if ip in NAT64:
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def _assert_global_ip(text: str) -> None:
    ip = ipaddress.ip_address(text.strip("[]"))
    if isinstance(ip, ipaddress.IPv4Address):
        assert not any(ip in net for net in NOT_GLOBAL_V4), f"non-global {ip} sent"
        return
    assert not any(ip in net for net in NOT_GLOBAL_V6), f"non-global {ip} sent"
    for v4 in _embedded_v4(ip):
        assert not any(v4 in net for net in NOT_GLOBAL_V4), f"{ip} embeds non-global {v4}"


def _assert_public_name(name: str, provider: ProviderName) -> None:
    assert name == name.lower() and not name.endswith(".") and "." in name, name
    labels = name.split(".")
    assert labels[-1] not in SPECIAL_TLDS, f"special-use name {name} sent to {provider}"
    for sld in EXAMPLE_SLDS:
        if name == sld or name.endswith(f".{sld}"):
            assert provider is ProviderName.MOCK and sld == "example.com", (name, provider)
    assert not re.fullmatch(r"[0-9]+|0x[0-9a-f]*", labels[-1]), f"numeric last label: {name}"


def _assert_sendable(item: Normalized, provider: ProviderName) -> None:
    value = item.value_norm
    if item.ioc_type in (IocType.IPV4, IocType.IPV6):
        _assert_global_ip(value)
    elif item.ioc_type is IocType.DOMAIN:
        _assert_public_name(value, provider)
    elif item.ioc_type is IocType.URL:
        assert "?" not in value and "#" not in value, f"query/fragment sent: {value}"
        parts = urlsplit(value)
        assert parts.scheme in ("http", "https") and not parts.query and not parts.fragment
        assert "@" not in parts.netloc, f"userinfo sent: {value}"
        host = parts.hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            _assert_public_name(host, provider)
        else:
            _assert_global_ip(host)
    elif item.ioc_type is IocType.EMAIL:
        assert provider in (ProviderName.MISP, ProviderName.MOCK), (value, provider)
        _assert_public_name(value.rpartition("@")[2], provider)
    else:
        assert re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value), value


def _check(hint: str | None, raw: str) -> None:
    """For every provider: an eligible item satisfies the oracle and is a fixed point (the
    worker re-normalizes what it sends and gets the same value back)."""
    outcome = normalize(hint, raw)
    for provider in PROVIDERS:
        verdict = eligible(outcome, provider)
        if not isinstance(verdict, Normalized):
            continue
        _assert_sendable(verdict, provider)
        again = eligible(normalize(verdict.ioc_type, verdict.value_norm), provider)
        assert isinstance(again, Normalized) and again.value_norm == verdict.value_norm, raw


def _never_sent(hint: str | None, raw: str) -> None:
    outcome = normalize(hint, raw)
    for provider in PROVIDERS:
        assert not isinstance(eligible(outcome, provider), Normalized), (raw, provider)


# --- strategies --------------------------------------------------------------------------------


def _in(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> st.SearchStrategy[int]:
    return st.integers(int(net.network_address), int(net.broadcast_address))


bad_v4 = st.sampled_from(NOT_GLOBAL_V4).flatmap(_in).map(ipaddress.IPv4Address)
any_v4 = st.one_of(bad_v4, st.ip_addresses(v=4))
bad_v6_direct = st.sampled_from(NOT_GLOBAL_V6).flatmap(_in).map(ipaddress.IPv6Address)


def _embed(v4: ipaddress.IPv4Address, how: str, salt: int) -> ipaddress.IPv6Address:
    n = int(v4)
    if how == "mapped":
        return ipaddress.IPv6Address((0xFFFF << 32) | n)
    if how == "compat":
        return ipaddress.IPv6Address(n)
    if how == "6to4":
        return ipaddress.IPv6Address((0x2002 << 112) | (n << 80) | (salt & ((1 << 80) - 1)))
    if how == "nat64":
        return ipaddress.IPv6Address((0x64FF9B << 96) | n)
    if how == "nat64-local":
        return ipaddress.IPv6Address((0x0064FF9B0001 << 80) | n)
    # Teredo: 2001:0::/32, server IPv4, flags/port, then the client IPv4 XOR 0xffffffff.
    server = salt & 0xFFFFFFFF
    return ipaddress.IPv6Address((0x20010000 << 96) | (server << 64) | (n ^ 0xFFFFFFFF))


embedded_bad = st.builds(
    _embed,
    bad_v4,
    st.sampled_from(["mapped", "compat", "6to4", "nat64", "nat64-local", "teredo"]),
    st.integers(0, 2**80 - 1),
)
any_v6 = st.one_of(bad_v6_direct, embedded_bad, st.ip_addresses(v=6))


def _render(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, style: int) -> str:
    text = ip.exploded if style % 3 == 1 else ip.compressed
    if style % 3 == 2:
        text = text.upper()
    if isinstance(ip, ipaddress.IPv4Address) and style % 2:
        text = text.replace(".", "[.]")
    return text


label = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?", fullmatch=True)
special_suffix = st.one_of(
    st.sampled_from(sorted(SPECIAL_TLDS)),
    st.sampled_from(EXAMPLE_SLDS),
    st.sampled_from(["in-addr.arpa", "ip6.arpa", "home.arpa", "corp.internal"]),
    st.builds(lambda ip: ip.reverse_pointer, any_v4),
)
special_name = st.builds(
    lambda labels, suffix: ".".join([*labels, suffix]),
    st.lists(label, min_size=0, max_size=3),
    special_suffix,
)


def _disguise(name: str, style: int) -> str:
    if style & 1:
        name = name.upper()
    if style & 2:
        name += "."
    if style & 4:
        name = name.replace(".", "[.]", 1)
    return name


query = st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), max_size=24)


# --- properties --------------------------------------------------------------------------------


@PROFILE
@given(ip=any_v4, style=st.integers(0, 5), hint=st.sampled_from(["ip", "ipv4", None]))
def test_ipv4_values(ip: ipaddress.IPv4Address, style: int, hint: str | None) -> None:
    _check(hint, _render(ip, style))


@PROFILE
@given(ip=bad_v4, style=st.integers(0, 5), hint=st.sampled_from(["ip", "ipv4", None]))
def test_non_global_ipv4_is_never_sent(
    ip: ipaddress.IPv4Address, style: int, hint: str | None
) -> None:
    _never_sent(hint, _render(ip, style))


@PROFILE
@given(ip=st.one_of(bad_v6_direct, embedded_bad), style=st.integers(0, 5))
@example(ip=ipaddress.IPv6Address("2002:a00:1::1"), style=0)  # 6to4 of 10.0.0.1
@example(ip=ipaddress.IPv6Address("64:ff9b::7f00:1"), style=0)  # NAT64 of 127.0.0.1
@example(ip=ipaddress.IPv6Address("2001:0:4136:e378:8000:63bf:f5ff:fffe"), style=0)  # Teredo
def test_non_global_and_embedding_ipv6_is_never_sent(ip: ipaddress.IPv6Address, style: int) -> None:
    for hint in ("ip", "ipv6", None):
        _never_sent(hint, _render(ip, style))
    _never_sent("url", f"http://[{_render(ip, style)}]/x")


@PROFILE
@given(ip=any_v6, style=st.integers(0, 5), hint=st.sampled_from(["ip", "ipv6", None]))
def test_ipv6_values(ip: ipaddress.IPv6Address, style: int, hint: str | None) -> None:
    _check(hint, _render(ip, style))
    _check("url", f"https://[{ip.compressed}]:8443/p?q=1")


@PROFILE
@given(name=special_name, style=st.integers(0, 7))
def test_special_use_and_arpa_names(name: str, style: int) -> None:
    text = _disguise(name, style)
    for hint, raw in (
        ("domain", text),
        (None, text),
        ("url", f"https://{text}/a"),
        ("email", f"user@{text}"),
    ):
        _check(hint, raw)
        outcome = normalize(hint, raw)
        for provider in PROVIDERS:
            if provider is not ProviderName.MOCK:
                assert not isinstance(eligible(outcome, provider), Normalized), (raw, provider)


@PROFILE
@given(
    host=st.one_of(
        st.builds(lambda a, b: f"{a}.{b}.net", label, label),
        special_name,
        any_v4.map(str),
        any_v6.map(lambda ip: f"[{ip.compressed}]"),
    ),
    path=st.from_regex(r"(/[A-Za-z0-9._~%-]{0,8}){0,3}", fullmatch=True),
    query=query,
    fragment=query,
    marker=st.sampled_from(["?", "#", "?#", ""]),
    hint=st.sampled_from(["url", None]),
)
def test_urls_never_carry_a_query_or_fragment(
    host: str, path: str, query: str, fragment: str, marker: str, hint: str | None
) -> None:
    tail = ""
    if "?" in marker:
        tail += f"?{query}"
    if "#" in marker:
        tail += f"#{fragment}"
    for scheme in ("http", "https", "hxxps"):
        _check(hint, f"{scheme}://{host}{path}{tail}")


@PROFILE
@given(
    hint=st.sampled_from(["ip", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha256", None]),
    raw=st.text(max_size=80),
)
def test_arbitrary_text(hint: str | None, raw: str) -> None:
    _check(hint, raw)


def test_the_oracle_is_not_vacuous() -> None:
    """Positive control: real values do get through, and the oracle rejects bad ones."""
    for hint, raw in (
        ("ip", "8.8.8.8"),
        ("ipv6", "2606:4700:4700::1111"),
        ("ip", "64:ff9b::808:808"),  # NAT64 of a global address stands for 8.8.8.8
        ("domain", "malware.example-corp.net"),
        ("url", "https://evil.example-corp.net/a?token=x"),
    ):
        verdict = eligible(normalize(hint, raw), ProviderName.VIRUSTOTAL)
        assert isinstance(verdict, Normalized), raw
        _assert_sendable(verdict, ProviderName.VIRUSTOTAL)
    for bad in (
        Normalized.of(IocType.IPV4, "10.0.0.1"),
        Normalized.of(IocType.IPV6, "2002:a00:1::1"),
        Normalized.of(IocType.DOMAIN, "1.0.0.10.in-addr.arpa"),
        Normalized.of(IocType.DOMAIN, "printer.corp"),
        Normalized.of(IocType.URL, "https://evil.example-corp.net/a?token=x"),
    ):
        try:
            _assert_sendable(bad, ProviderName.VIRUSTOTAL)
        except AssertionError:
            continue
        raise AssertionError(f"oracle accepted {bad}")
