"""Frozen TI contracts: summary models, ProviderResult, catalog, errors (M4 phase 1)."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from app.modules.threat_intel import summaries as s
from app.modules.threat_intel.catalog import CATALOG, PROVIDER_NAMES
from app.modules.threat_intel.models import IOC_TYPES
from app.modules.threat_intel.providers.base import (
    HASH_TYPES,
    IocRef,
    IocType,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
    compute_ioc_key,
)

LONG = "a" * 20_000
TS = datetime(2026, 11, 5, 12, 34, 56, 123456, tzinfo=UTC)
BIG = 10**12


def many(item: Any) -> list[Any]:
    return [item] * 1_000


# Every field at its worst case: strings past their byte budget, lists past their cap.
WORST: dict[str, dict[str, Any]] = {
    "virustotal": {
        "last_analysis_stats": dict.fromkeys(
            ("malicious", "suspicious", "harmless", "undetected", "timeout"), BIG
        ),
        "reputation": -BIG,
        "total_votes": {"harmless": BIG, "malicious": BIG},
        "tags": many(LONG),
        "last_analysis_date": TS,
        "first_submission_date": TS,
        "last_submission_date": TS,
        "suggested_threat_label": LONG,
        "meaningful_name": LONG,
        "type_tag": LONG,
        "as_owner": LONG,
        "country": LONG,
    },
    "abuseipdb": {
        "abuse_confidence_score": 100,
        "total_reports": BIG,
        "num_distinct_users": BIG,
        "last_reported_at": TS,
        "is_whitelisted": False,
        "is_tor": False,
        "usage_type": LONG,
        "isp": LONG,
        "country_code": LONG,
        "categories": many(255),
    },
    "urlhaus": {
        "lookup": "payload",
        "url_status": LONG,
        "threat": LONG,
        "tags": many(LONG),
        "date_added": TS,
        "last_online": TS,
        "blacklists": {"spamhaus_dbl": LONG, "surbl": LONG},
        "url_count": BIG,
        "first_seen": TS,
        "last_seen": TS,
        "signature": LONG,
    },
    "malwarebazaar": {
        "first_seen": TS,
        "last_seen": TS,
        "signature": LONG,
        "tags": many(LONG),
        "file_type": LONG,
        "imphash": LONG,
        "ssdeep": LONG,
        "tlsh": LONG,
        "vendor_intel": many(LONG),
    },
    "otx": {
        "pulse_count": BIG,
        "pulses": many(
            {
                "name": LONG,
                "tags": many(LONG),
                "malware_families": many(LONG),
                "attack_ids": [f"T{1000 + i}.{100 + i}" for i in range(50)],
                "modified": TS,
            }
        ),
        "reputation": -BIG,
        "validation": many({"source": LONG, "name": LONG, "message": LONG}),
    },
    "misp": {
        "attribute_count": BIG,
        "attributes": many(
            {
                "type": LONG,
                "category": LONG,
                "to_ids": False,
                "first_seen": TS,
                "last_seen": TS,
                "timestamp": TS,
                "event_id": 2**63 - 1,
                "event_info": LONG,
                "event_uuid": uuid.uuid4(),
                "tags": many(LONG),
            }
        ),
        "tlp": many(LONG),
    },
    "mock": {"behaviour": LONG, "label": LONG, "hits": BIG, "tags": many(LONG)},
}


def test_every_provider_has_a_summary_model_and_a_worst_case() -> None:
    assert set(s.SUMMARY_MODELS) == set(PROVIDER_NAMES) == set(WORST)


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_worst_case_summary_fits_the_db_limit(provider: str) -> None:
    model = s.SUMMARY_MODELS[provider].model_validate(WORST[provider])
    size = s.summary_size(model)
    assert size <= s.SUMMARY_MAX_BYTES, (provider, size)


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_multibyte_worst_case_also_fits(provider: str) -> None:
    # 4-byte characters and JSON escapes: budgets are in serialized bytes, not characters.
    hostile = '\U0001f600"\\' * 5_000

    def swap(value: Any) -> Any:
        if value == LONG:
            return hostile
        if isinstance(value, dict):
            return {k: swap(v) for k, v in value.items()}
        if isinstance(value, list):
            return [swap(v) for v in value]
        return value

    model = s.SUMMARY_MODELS[provider].model_validate(swap(WORST[provider]))
    assert s.summary_size(model) <= s.SUMMARY_MAX_BYTES


def test_summary_union_is_discriminated_by_provider() -> None:
    adapter: TypeAdapter[Any] = TypeAdapter(s.ProviderSummary)
    parsed = adapter.validate_python({"provider": "abuseipdb", "abuse_confidence_score": 87})
    assert isinstance(parsed, s.AbuseIpdbSummary)
    dumped = parsed.model_dump(mode="json")
    assert adapter.validate_python(dumped) == parsed
    with pytest.raises(ValidationError):
        adapter.validate_python({"provider": "abuseipdb", "raw_body": "x"})


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("evil‮gnp.exe", "evilgnp.exe"),  # bidi override
        ("a​b⁦c⁩", "abc"),  # zero-width, isolates
        ("line1\nline2\r\n\tline3", "line1 line2 line3"),
        ("bell\x07\x00null", "bellnull"),
        ("para graph", "para graph"),
        ("  padded  ", "padded"),
    ],
)
def test_control_and_bidi_characters_are_stripped(raw: str, clean: str) -> None:
    assert s.MockSummary(label=raw).label == clean


def test_strings_are_truncated_and_lists_capped() -> None:
    summary = s.VirusTotalSummary.model_validate(WORST["virustotal"])
    assert summary.as_owner == "a" * 128
    assert len(summary.tags) == 20 and all(len(t) == 64 for t in summary.tags)


def test_attack_ids_are_validated_and_capped() -> None:
    pulse = s.OtxPulse(
        name="p", attack_ids=["t1055", "T1059.001", "T1055", "javascript:alert(1)", "T12", 7]
    )
    assert pulse.attack_ids == ["T1055", "T1059.001"]


def test_unknown_fields_and_wrong_types_are_refused() -> None:
    with pytest.raises(ValidationError):
        s.VirusTotalSummary.model_validate({"raw": {"x": 1}})
    with pytest.raises(ValidationError):
        s.AbuseIpdbSummary(abuse_confidence_score=101)
    with pytest.raises(ValidationError):
        s.MockSummary.model_validate({"label": {"nested": "object"}})


def _result(**fields: Any) -> ProviderResult:
    base: dict[str, Any] = {"provider": "mock", "status": "ok", "found": True}
    return ProviderResult.model_validate({**base, **fields})


def test_provider_result_permalinks_are_https_only() -> None:
    assert _result(permalink="https://www.virustotal.com/gui/file/abc").permalink
    for bad in (
        "javascript:alert(1)",
        "http://example.com/x",
        "https://user:pw@example.com/",
        "https://example.com/a b",
        "data:text/html,x",
        "https:///nohost",
    ):
        with pytest.raises(ValidationError):
            _result(permalink=bad)


def test_provider_result_is_coherent() -> None:
    with pytest.raises(ValidationError):
        _result(summary={"provider": "otx"})
    with pytest.raises(ValidationError):
        _result(status="not_found", found=True)
    with pytest.raises(ValidationError):
        _result(score=float("nan"))
    result = _result(
        score=87, score_scale="abuseipdb_confidence_0_100", attack_ids=["T1055", "bogus"]
    )
    assert result.attack_ids == ["T1055"] and result.status is ResultStatus.OK
    assert _result(summary={"provider": "mock", "label": "x"}).summary is not None


def test_ioc_key_is_type_scoped_sha256() -> None:
    key = compute_ioc_key(IocType.DOMAIN, "example.com")
    assert len(key) == 64 and key != compute_ioc_key(IocType.URL, "example.com")
    assert IocRef.of(IocType.DOMAIN, "example.com").ioc_key == key


def test_ioc_types_match_the_db_checks() -> None:
    assert {t.value for t in IocType} == set(IOC_TYPES)


def test_catalog_is_complete_and_conservative() -> None:
    assert set(CATALOG) == set(ProviderName)
    for entry in CATALOG.values():
        assert entry.supported_types and entry.tos_note and entry.privacy_note
        assert entry.default_limits.per_minute <= entry.ceilings.per_minute
        assert entry.ceilings.concurrency <= 4
    # Emails go to MISP and the mock only (never to a public provider).
    for name, entry in CATALOG.items():
        if name not in (ProviderName.MISP, ProviderName.MOCK):
            assert IocType.EMAIL not in entry.supported_types
    assert CATALOG[ProviderName.ABUSEIPDB].supported_types == {IocType.IPV4, IocType.IPV6}
    assert CATALOG[ProviderName.MALWAREBAZAAR].supported_types == HASH_TYPES
    assert IocType.SHA1 not in CATALOG[ProviderName.URLHAUS].supported_types
    assert [n for n, e in CATALOG.items() if e.dev_only] == [ProviderName.MOCK]
    assert [n for n, e in CATALOG.items() if e.needs_base_url] == [ProviderName.MISP]


def test_provider_error_carries_no_body() -> None:
    error = ProviderError(ProviderErrorKind.AUTH, http_status=401)
    assert str(error) == "auth (401)"
    assert repr(error) == "ProviderError('auth', http_status=401)"
    assert error.args == ("auth",)
