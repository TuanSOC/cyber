"""Correlation keys follow M6 `normalize_item` byte for byte (RT8), so they join
`ti_results.ioc_key` (built by the M4 normalizer / `compute_ioc_key`) and
`ioc_collection_items.ioc_key` without new code."""

import pytest

from app.modules.correlation.normalize import candidate_keys, correlation_key
from app.modules.ioc_collections.normalize import Item, normalize_item, opaque_key
from app.modules.threat_intel.normalize import Normalized, normalize
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key

JA3_MIXED = "E7D705A3286E19EA42F587B344EE6865"


@pytest.mark.parametrize(
    ("ioc_type", "raw", "kind", "value_norm"),
    [
        ("ip", "8.8.8.8", "ipv4", "8.8.8.8"),
        ("ip", "2606:4700:4700:0:0:0:0:1111", "ipv6", "2606:4700:4700::1111"),
        ("domain", "Evil.Example-Corp.NET", "domain", "evil.example-corp.net"),
        ("file_sha256", "A" * 64, "sha256", "a" * 64),
        ("file_md5", "B" * 32, "md5", "b" * 32),
        ("url", "https://evil.example-corp.net/p?q=1", "url", "https://evil.example-corp.net/p"),
    ],
)
def test_ti_eligible_values_equal_the_m4_ti_result_key(
    ioc_type: str, raw: str, kind: str, value_norm: str
) -> None:
    key = correlation_key(ioc_type, raw)
    ti = normalize(ioc_type, raw)
    item = normalize_item(ioc_type, raw)
    assert isinstance(ti, Normalized) and isinstance(item, Item)
    assert key == (kind, ti.ioc_key, value_norm)
    assert key[1] == item.ioc_key == compute_ioc_key(IocType(kind), value_norm)


@pytest.mark.parametrize(
    ("ioc_type", "raw", "kind", "value_norm"),
    [
        ("ip", "10.1.2.3", "ipv4", "10.1.2.3"),  # private: kept, not TI-eligible
        ("ip", "2001:DB8::1", "ipv6", "2001:db8::1"),  # documentation range, mixed case
        ("domain", "fileserver.corp.local", "domain", "fileserver.corp.local"),
    ],
)
def test_private_values_are_kept_with_the_collection_key(
    ioc_type: str, raw: str, kind: str, value_norm: str
) -> None:
    key = correlation_key(ioc_type, raw)
    item = normalize_item(ioc_type, raw)
    assert isinstance(item, Item) and not item.ti_eligible
    assert key == (kind, item.ioc_key, value_norm)
    assert key[1] == compute_ioc_key(IocType(kind), value_norm)


def test_ja3_keeps_its_case_and_uses_the_opaque_key() -> None:
    key = correlation_key("ja3", f"  {JA3_MIXED} ")
    item = normalize_item("ja3", f"  {JA3_MIXED} ")
    assert isinstance(item, Item)
    assert key == ("ja3", item.ioc_key, JA3_MIXED)
    assert key[1] == opaque_key("ja3", JA3_MIXED)
    assert key[1] != opaque_key("ja3", JA3_MIXED.lower())  # never lowercased (RT8)


@pytest.mark.parametrize("ioc_type", ["ja3s", "cert_sha256"])
def test_pcap_only_types_are_indexed(ioc_type: str) -> None:
    key = correlation_key(ioc_type, "AbC123")
    assert key == (ioc_type, opaque_key(ioc_type, "AbC123"), "AbC123")


@pytest.mark.parametrize(
    ("ioc_type", "raw"),
    [
        ("registry_key", r"HKLM\Software\Evil"),
        ("file_path", r"C:\Users\x\evil.exe"),
        ("file_sha256", "not-a-hash"),
        ("ip", "999.1.1.1"),
        ("url", "ftp://evil.example-corp.net/"),
        ("unknown_type", "x"),
        ("domain", "   "),
    ],
)
def test_unindexed_types_and_invalid_values_are_none(ioc_type: str, raw: str) -> None:
    assert correlation_key(ioc_type, raw) is None


def test_candidate_keys_detect_then_add_the_pcap_only_types() -> None:
    assert [k[0] for k in candidate_keys("8.8.8.8")] == ["ipv4"]
    assert [k[0] for k in candidate_keys("hxxp://evil[.]example-corp.net/a")] == ["url"]
    assert [k[0] for k in candidate_keys(JA3_MIXED)] == ["md5", "ja3", "ja3s"]
    assert [k[0] for k in candidate_keys("c" * 64)] == ["sha256", "cert_sha256"]
    ja3 = "771,4865-4866-4867,0-23-65281,29-23-24,0"
    assert ("ja3", opaque_key("ja3", ja3), ja3) in candidate_keys(ja3)
    assert candidate_keys("a b c") == []
