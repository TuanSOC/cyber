"""Public provider adapters: field mapping, allowlists, key placement and verify (M4 phase 3).

The full fixture matrix lives in `test_ti_provider_fixtures.py`; this file pins what the
mapping must produce for the rich fixtures, proves that no adapter can reach an upload, scan
or download endpoint, and checks each `verify` call.
"""

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import get_settings
from app.modules.threat_intel.http import KeyAuth, PathNotAllowed, path_allowed, ti_client
from app.modules.threat_intel.providers import abusech, registry, virustotal
from app.modules.threat_intel.providers.base import (
    IocRef,
    IocType,
    Provider,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
    VerifyStatus,
)
from app.modules.threat_intel.summaries import (
    AbuseIpdbSummary,
    MalwareBazaarSummary,
    OtxSummary,
    UrlhausSummary,
    VirusTotalSummary,
)
from tests.ti_helpers import SENTINEL_KEY
from tests.unit.test_ti_provider_fixtures import StreamedMock

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ti"
PUBLIC = (
    ProviderName.VIRUSTOTAL,
    ProviderName.ABUSEIPDB,
    ProviderName.URLHAUS,
    ProviderName.MALWAREBAZAAR,
    ProviderName.OTX,
)
SHA256 = "afd186792fddd1fb440680e3ce3dd11c1e279bcd95ef234e5d04f91a19848063"
MD5 = "b3f2dbcce7819dcbb219d332cc8159e6"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
URL = "http://malicious.example.com/payload/dropper.exe"
VT, ABUSEIPDB = "www.virustotal.com", "api.abuseipdb.com"
URLHAUS, MB, OTX = "urlhaus-api.abuse.ch", "mb-api.abuse.ch", "otx.alienvault.com"
_ID = virustotal.url_id(URL)

Handler = Callable[[httpx.Request], httpx.Response]


def _adapter(name: ProviderName) -> Provider:
    return registry.create(name, registry.ProviderContext(get_settings()))


def _fixture(provider: str, name: str) -> bytes:
    return (FIXTURES / provider / name).read_bytes()


async def _run(
    name: ProviderName, handler: Handler, ioc: IocRef | None = None
) -> tuple[ProviderResult | Any, list[httpx.Request]]:
    """A lookup (or verify when `ioc` is None) on the hardened client; returns the outcome
    (result, VerifyOutcome or ProviderError) and the requests the transport received."""
    adapter = _adapter(name)
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    auth = KeyAuth(registry.auth_header(name), SecretStr(SENTINEL_KEY))
    async with ti_client(adapter, auth=auth, transport=StreamedMock(record)) as client:
        try:
            outcome = await (adapter.verify(client) if ioc is None else adapter.lookup(client, ioc))
        except ProviderError as exc:
            outcome = exc
    for request in seen:
        assert path_allowed(request, adapter.allowed_paths)
        assert request.headers[registry.auth_header(name)] == SENTINEL_KEY
        assert SENTINEL_KEY not in str(request.url) and SENTINEL_KEY.encode() not in request.content
    return outcome, seen


def _serve(provider: str, name: str, status: int = 200) -> Handler:
    return lambda _: httpx.Response(status, content=_fixture(provider, name))


# --- mapping --------------------------------------------------------------------------------


async def test_virustotal_file_hit_mapping() -> None:
    result, [request] = await _run(
        ProviderName.VIRUSTOTAL,
        _serve("virustotal", "file_hit.json"),
        IocRef.of(IocType.SHA256, SHA256),
    )
    assert request.url.path == f"/api/v3/files/{SHA256}"
    assert (result.status, result.found) == (ResultStatus.OK, True)
    assert result.detections is not None
    assert result.detections.model_dump() == {"malicious": 48, "suspicious": 2, "total": 70}
    assert (result.score, result.score_scale) == (-60, "virustotal_reputation")
    assert result.tags == ["peexe", "spreader", "detect-debug-environment"]
    assert result.families == ["examplebot", "fixture"]
    assert result.first_seen == datetime.fromtimestamp(1792800000, UTC)
    assert result.last_seen == datetime.fromtimestamp(1793577600, UTC)
    assert result.permalink == f"https://www.virustotal.com/gui/file/{SHA256}"
    summary = result.summary
    assert isinstance(summary, VirusTotalSummary)
    assert summary.suggested_threat_label == "trojan.examplebot/fixture"
    assert (summary.meaningful_name, summary.type_tag) == ("dropper.exe", "peexe")
    assert summary.total_votes is not None and summary.total_votes.malicious == 21


async def test_virustotal_ip_and_url_mapping() -> None:
    result, _ = await _run(
        ProviderName.VIRUSTOTAL,
        _serve("virustotal", "ip_hit.json"),
        IocRef.of(IocType.IPV4, "192.0.2.10"),
    )
    assert isinstance(result.summary, VirusTotalSummary)
    assert (result.summary.as_owner, result.summary.country) == (
        "Example Hosting LLC (documentation ASN)",
        "US",
    )
    assert result.permalink == "https://www.virustotal.com/gui/ip-address/192.0.2.10"
    assert result.last_seen == datetime.fromtimestamp(1793660400, UTC)  # last analysis
    result, [request] = await _run(
        ProviderName.VIRUSTOTAL, _serve("virustotal", "url_hit.json"), IocRef.of(IocType.URL, URL)
    )
    assert request.url.path == f"/api/v3/urls/{_ID}"
    assert result.families == ["ExampleBot"]
    # The GUI link uses VirusTotal's own sha256 id of the URL object.
    assert result.permalink == (
        "https://www.virustotal.com/gui/url/"
        "5459470f90619181be416ef903bc5df7f02b992e7dbf6ed6b25bb5fe6a7e90eb"
    )


def test_virustotal_url_id_is_unpadded_base64url() -> None:
    assert _ID == "aHR0cDovL21hbGljaW91cy5leGFtcGxlLmNvbS9wYXlsb2FkL2Ryb3BwZXIuZXhl"
    assert virustotal.url_id("http://a.example.net/?") == "aHR0cDovL2EuZXhhbXBsZS5uZXQvPw"
    assert virustotal.url_id("https://b.example.net/?>~") == "aHR0cHM6Ly9iLmV4YW1wbGUubmV0Lz8-fg"


async def test_virustotal_hostile_values_are_dropped_or_cleaned() -> None:
    result, _ = await _run(
        ProviderName.VIRUSTOTAL,
        _serve("virustotal", "file_hostile.json"),
        IocRef.of(IocType.SHA256, SHA256),
    )
    assert isinstance(result.summary, VirusTotalSummary)
    assert result.summary.meaningful_name == "invoicegpj.exe"  # bidi override stripped
    assert "" not in result.tags and "padded" in result.tags
    assert "ctrlnulbel[31mANSI-red[0m FAKE-LOG-LINE level=critical" in result.tags
    assert all("\n" not in tag and "\x1b" not in tag for tag in result.tags)


async def test_abuseipdb_hit_and_not_found() -> None:
    result, [request] = await _run(
        ProviderName.ABUSEIPDB,
        _serve("abuseipdb", "ip_hit.json"),
        IocRef.of(IocType.IPV4, "192.0.2.10"),
    )
    assert request.url.path == "/api/v2/check"
    assert parse_qs(request.url.query.decode(), keep_blank_values=True) == {
        "ipAddress": ["192.0.2.10"],
        "maxAgeInDays": ["90"],
        "verbose": [""],
    }
    assert (result.status, result.found) == (ResultStatus.OK, True)
    assert (result.score, result.score_scale) == (100, "abuseipdb_confidence_0_100")
    assert result.permalink == "https://www.abuseipdb.com/check/192.0.2.10"
    summary = result.summary
    assert isinstance(summary, AbuseIpdbSummary)
    assert (summary.total_reports, summary.num_distinct_users) == (1234, 210)
    assert summary.categories[:3] == [18, 22, 14]
    assert summary.last_reported_at == datetime(2026, 11, 2, 22, 15, 7, tzinfo=UTC)
    # Score 0 and no reports: not found, but the context is kept.
    result, _ = await _run(
        ProviderName.ABUSEIPDB,
        _serve("abuseipdb", "ip_not_found.json"),
        IocRef.of(IocType.IPV4, "198.51.100.7"),
    )
    assert (result.status, result.found, result.score) == (ResultStatus.NOT_FOUND, False, 0)
    summary = result.summary
    assert isinstance(summary, AbuseIpdbSummary)
    assert (summary.usage_type, summary.isp) == ("Fixed Line ISP", "Example Broadband Co.")
    assert (summary.is_tor, summary.is_whitelisted) == (False, None)
    # Whitelisted with reports is still a hit (AbuseIPDB's own flag is quoted, not judged).
    result, _ = await _run(
        ProviderName.ABUSEIPDB,
        _serve("abuseipdb", "ip_whitelisted.json"),
        IocRef.of(IocType.IPV4, "198.51.100.53"),
    )
    assert result.found and isinstance(result.summary, AbuseIpdbSummary)
    assert result.summary.is_whitelisted is True


async def test_abuseipdb_hostile_categories() -> None:
    result, _ = await _run(
        ProviderName.ABUSEIPDB,
        _serve("abuseipdb", "ip_hostile.json"),
        IocRef.of(IocType.IPV4, "203.0.113.66"),
    )
    assert isinstance(result.summary, AbuseIpdbSummary)
    assert all(0 <= c <= 255 for c in result.summary.categories)
    assert 999 not in result.summary.categories and -1 not in result.summary.categories
    assert result.summary.country_code == "US"


async def test_urlhaus_lookups() -> None:
    result, [request] = await _run(
        ProviderName.URLHAUS, _serve("urlhaus", "url_hit.json"), IocRef.of(IocType.URL, URL)
    )
    assert (request.method, request.url.path) == ("POST", "/v1/url/")
    assert result.permalink == "https://urlhaus.abuse.ch/url/3000001/"
    summary = result.summary
    assert isinstance(summary, UrlhausSummary)
    assert (summary.lookup, summary.url_status, summary.threat) == (
        "url",
        "online",
        "malware_download",
    )
    assert summary.date_added == datetime(2026, 10, 30, 12, 34, 56, tzinfo=UTC)
    assert summary.blacklists is not None and summary.blacklists.surbl == "listed"
    assert result.families == ["ExampleBot"] and result.tags == ["exe", "ExampleBot", "opendir"]

    result, [request] = await _run(
        ProviderName.URLHAUS,
        _serve("urlhaus", "domain_hit.json"),
        IocRef.of(IocType.DOMAIN, "malicious.example.com"),
    )
    assert request.url.path == "/v1/host/"
    assert isinstance(result.summary, UrlhausSummary)
    assert (result.summary.lookup, result.summary.url_count) == ("host", 3)
    assert result.permalink == "https://urlhaus.abuse.ch/host/malicious.example.com/"

    result, [request] = await _run(
        ProviderName.URLHAUS, _serve("urlhaus", "file_hit.json"), IocRef.of(IocType.MD5, MD5)
    )
    assert parse_qs(request.content.decode()) == {"md5_hash": [MD5]}
    assert isinstance(result.summary, UrlhausSummary)
    assert (result.summary.lookup, result.summary.signature) == ("payload", "ExampleBot")
    assert result.summary.last_seen == datetime(2026, 11, 2, 1, 2, 3, tzinfo=UTC)
    assert result.permalink == f"https://urlhaus.abuse.ch/browse.php?search={MD5}"


@pytest.mark.parametrize(
    "reference",
    [
        "https://urlhaus.abuse.ch.evil.example.com/url/1/",
        "http://urlhaus.abuse.ch/url/1/",
        "javascript:alert(document.domain)",
        "https://user@urlhaus.abuse.ch/url/1/",
        "https://urlhaus.abuse.ch:8443/url/1/",
        "https://urlhaus.abuse.ch/url/1/\r\nx",
        "data:text/html;base64,PHNjcmlwdD4=",
        "https://urlhaus.abuse.ch/url/1/‮gpj.exe",  # RIGHT-TO-LEFT OVERRIDE
        "https://urlhaus.abuse.ch/url/1/​",  # zero-width space
        "https://urlhaus.abuse.ch/url/１/",  # fullwidth digit
    ],
)
def test_provider_links_only_on_their_own_https_host(reference: str) -> None:
    assert abusech.own_https(reference, "urlhaus.abuse.ch") is None
    ok = "https://urlhaus.abuse.ch/url/1/"
    assert abusech.own_https(ok, "urlhaus.abuse.ch") == ok


async def test_malwarebazaar_hit() -> None:
    result, [request] = await _run(
        ProviderName.MALWAREBAZAAR,
        _serve("malwarebazaar", "file_hit.json"),
        IocRef.of(IocType.MD5, MD5),
    )
    assert parse_qs(request.content.decode()) == {"query": ["get_info"], "hash": [MD5]}
    assert result.permalink == f"https://bazaar.abuse.ch/sample/{SHA256}/"
    summary = result.summary
    assert isinstance(summary, MalwareBazaarSummary)
    assert (summary.signature, summary.file_type) == ("ExampleBot", "exe")
    assert summary.vendor_intel[:2] == ["ExampleSandbox", "FixtureIntel"]
    assert summary.first_seen == datetime(2026, 10, 30, 12, 34, 56, tzinfo=UTC)
    assert result.families == ["ExampleBot"]


async def test_otx_hit_quiet_and_attack_ids() -> None:
    result, [request] = await _run(
        ProviderName.OTX, _serve("otx", "ip_hit.json"), IocRef.of(IocType.IPV4, "192.0.2.10")
    )
    assert request.url.path == "/api/v1/indicators/IPv4/192.0.2.10/general"
    assert result.attack_ids == ["T1071.001", "T1059.001", "T1566.001"]
    assert result.families == ["ExampleBot", "FixtureStealer"]
    assert result.permalink == "https://otx.alienvault.com/indicator/ip/192.0.2.10"
    summary = result.summary
    assert isinstance(summary, OtxSummary)
    assert (summary.pulse_count, summary.reputation, len(summary.pulses)) == (3, 3, 3)
    assert summary.pulses[0].modified == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    # The quiet 200 is not found and keeps OTX's validation hints.
    result, _ = await _run(
        ProviderName.OTX,
        _serve("otx", "domain_quiet.json"),
        IocRef.of(IocType.DOMAIN, "clean.example.net"),
    )
    assert (result.status, result.found) == (ResultStatus.NOT_FOUND, False)
    assert isinstance(result.summary, OtxSummary) and result.summary.pulse_count == 0
    assert result.summary.validation[0].source == "whitelist"
    # Only well-formed technique ids survive hostile pulses.
    result, _ = await _run(
        ProviderName.OTX, _serve("otx", "ip_hostile.json"), IocRef.of(IocType.IPV4, "203.0.113.66")
    )
    assert result.attack_ids == ["T1055"]
    assert isinstance(result.summary, OtxSummary)
    assert result.summary.reputation is None and result.summary.pulses[0].modified is None


async def test_otx_huge_keeps_the_top_ten_pulses() -> None:
    body = json.loads(_fixture("otx", "ip_huge.json"))
    body["pulse_info"]["pulses"] *= 3
    result, _ = await _run(
        ProviderName.OTX,
        lambda _: httpx.Response(200, json=body),
        IocRef.of(IocType.IPV4, "203.0.113.66"),
    )
    assert isinstance(result.summary, OtxSummary) and len(result.summary.pulses) == 10


async def test_otx_url_dot_segments_are_refused_before_sending() -> None:
    url = "http://a.example.net/x/../../../../api/v1/pulses/create"
    error, seen = await _run(
        ProviderName.OTX, lambda _: httpx.Response(200), IocRef.of(IocType.URL, url)
    )
    assert isinstance(error, ProviderError) and error.kind is ProviderErrorKind.INVALID_INPUT
    assert seen == []


@pytest.mark.parametrize(
    ("name", "ioc"),
    [
        (ProviderName.ABUSEIPDB, IocRef.of(IocType.DOMAIN, "malicious.example.com")),
        (ProviderName.MALWAREBAZAAR, IocRef.of(IocType.URL, URL)),
        (ProviderName.URLHAUS, IocRef.of(IocType.SHA1, "a" * 40)),
        (ProviderName.VIRUSTOTAL, IocRef.of(IocType.EMAIL, "a@example.com")),
        (ProviderName.OTX, IocRef.of(IocType.EMAIL, "a@example.com")),
    ],
)
async def test_unsupported_types_never_leave(name: ProviderName, ioc: IocRef) -> None:
    error, seen = await _run(name, lambda _: httpx.Response(200, json={}), ioc)
    assert isinstance(error, ProviderError) and error.kind is ProviderErrorKind.INVALID_INPUT
    assert seen == []


@pytest.mark.parametrize(
    ("name", "body", "kind"),
    [
        (ProviderName.VIRUSTOTAL, {"data": []}, ProviderErrorKind.BAD_JSON),
        (ProviderName.VIRUSTOTAL, [1, 2], ProviderErrorKind.BAD_JSON),
        (ProviderName.ABUSEIPDB, {"errors": []}, ProviderErrorKind.BAD_JSON),
        (ProviderName.URLHAUS, {"query_status": 5}, ProviderErrorKind.BAD_JSON),
        (ProviderName.URLHAUS, {"query_status": "surprise"}, ProviderErrorKind.UNEXPECTED_STATUS),
        (
            ProviderName.MALWAREBAZAAR,
            {"query_status": "ok", "data": []},
            ProviderErrorKind.BAD_JSON,
        ),
        (
            ProviderName.MALWAREBAZAAR,
            {"query_status": "rate_limited"},
            ProviderErrorKind.RATE_LIMITED,
        ),
        (ProviderName.OTX, "quiet", ProviderErrorKind.BAD_JSON),
    ],
)
async def test_unexpected_shapes(name: ProviderName, body: Any, kind: ProviderErrorKind) -> None:
    ioc = {
        ProviderName.ABUSEIPDB: IocRef.of(IocType.IPV4, "192.0.2.10"),
        ProviderName.URLHAUS: IocRef.of(IocType.URL, URL),
    }.get(name, IocRef.of(IocType.SHA256, SHA256))
    error, _ = await _run(name, lambda _: httpx.Response(200, json=body), ioc)
    assert isinstance(error, ProviderError) and error.kind is kind


# --- allowlists -----------------------------------------------------------------------------

FORBIDDEN = [
    # VirusTotal: uploads, URL scans, re-analysis, downloads, votes/comments, users (RT11).
    ("POST", VT, "/api/v3/files"),
    ("GET", VT, "/api/v3/files/upload_url"),
    ("POST", VT, "/api/v3/urls"),
    ("POST", VT, f"/api/v3/files/{SHA256}/analyse"),
    ("POST", VT, f"/api/v3/urls/{_ID}/analyse"),
    ("GET", VT, f"/api/v3/files/{SHA256}/download"),
    ("GET", VT, f"/api/v3/files/{SHA256}/download_url"),
    ("POST", VT, f"/api/v3/files/{SHA256}/votes"),
    ("POST", VT, "/api/v3/ip_addresses/192.0.2.10/comments"),
    ("GET", VT, f"/api/v3/users/{SENTINEL_KEY}"),
    ("GET", VT, "/api/v3/analyses/u-0000-0000"),
    ("POST", VT, f"/api/v3/files/{SHA256}"),
    ("GET", "virustotal.com", f"/api/v3/files/{SHA256}"),
    # AbuseIPDB: reporting, clearing, blacklist, block checks.
    ("POST", ABUSEIPDB, "/api/v2/report"),
    ("POST", ABUSEIPDB, "/api/v2/bulk-report"),
    ("DELETE", ABUSEIPDB, "/api/v2/clear-address"),
    ("GET", ABUSEIPDB, "/api/v2/blacklist"),
    ("GET", ABUSEIPDB, "/api/v2/check-block"),
    ("POST", ABUSEIPDB, "/api/v2/check"),
    # URLhaus: sample downloads, feeds, submissions.
    ("GET", URLHAUS, f"/v1/download/{SHA256}/"),
    ("POST", URLHAUS, f"/v1/download/{SHA256}/"),
    ("GET", URLHAUS, "/v1/url/"),
    ("POST", URLHAUS, "/v1/urls/recent/"),
    ("POST", URLHAUS, "/v1/payloads/recent/"),
    ("POST", "urlhaus.abuse.ch", "/api/"),
    # MalwareBazaar: other hosts/methods (get_file/uploads share the path: see the form test).
    ("GET", MB, "/api/v1/"),
    ("POST", MB, "/api/v1/upload/"),
    ("POST", "bazaar.abuse.ch", "/api/v1/"),
    ("GET", "datalake.abuse.ch", f"/malware-bazaar/download/{SHA256}.zip"),
    # OTX: pulse creation, subscriptions, submissions, other sections.
    ("POST", OTX, "/api/v1/pulses/create"),
    ("POST", OTX, "/api/v1/pulses/0123/subscribe"),
    ("GET", OTX, "/api/v1/pulses/subscribed"),
    ("POST", OTX, "/api/v1/indicators/submit_file"),
    ("POST", OTX, "/api/v1/indicators/submit_url"),
    ("POST", OTX, "/api/v1/indicators/submit_urls"),
    ("GET", OTX, f"/api/v1/indicators/file/{SHA256}/analysis"),
    ("POST", OTX, "/api/v1/indicators/IPv4/192.0.2.10/general"),
    ("GET", OTX, "/api/v1/users/me"),
]


@pytest.mark.parametrize("name", PUBLIC)
@pytest.mark.parametrize(("method", "host", "path"), FORBIDDEN)
def test_forbidden_routes_match_no_allowlist(
    name: ProviderName, method: str, host: str, path: str
) -> None:
    adapter = _adapter(name)
    assert not any(entry.matches(method, host, path) for entry in adapter.allowed_paths)
    assert not path_allowed(httpx.Request(method, f"https://{host}{path}"), adapter.allowed_paths)


@pytest.mark.parametrize("name", PUBLIC)
async def test_forbidden_routes_are_never_sent(name: ProviderName) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    adapter = _adapter(name)
    async with ti_client(adapter, transport=StreamedMock(handler)) as client:
        for method, host, path in FORBIDDEN:
            with pytest.raises(PathNotAllowed):
                await client.request(method, f"https://{host}{path}")
    assert calls == 0


def test_allowlists_are_lookup_only() -> None:
    methods = {
        ProviderName.VIRUSTOTAL: ("GET", {VT}),
        ProviderName.ABUSEIPDB: ("GET", {ABUSEIPDB}),
        ProviderName.URLHAUS: ("POST", {URLHAUS}),
        ProviderName.MALWAREBAZAAR: ("POST", {MB}),
        ProviderName.OTX: ("GET", {OTX}),
    }
    for name, (method, hosts) in methods.items():
        for entry in _adapter(name).allowed_paths:
            assert entry.method == method and entry.host in hosts, (name, entry)


@pytest.mark.parametrize("query", ["get_file", "get_taginfo", "upload", "GET_INFO", ""])
def test_malwarebazaar_sends_only_get_info(query: str) -> None:
    with pytest.raises(PathNotAllowed):
        abusech.malwarebazaar_form(query, SHA256)
    assert abusech.malwarebazaar_form("get_info", SHA256) == {"query": "get_info", "hash": SHA256}


# --- verify ---------------------------------------------------------------------------------

VERIFY_REQUESTS = {
    ProviderName.VIRUSTOTAL: ("GET", f"/api/v3/files/{EICAR}", {}, None),
    ProviderName.ABUSEIPDB: (
        "GET",
        "/api/v2/check",
        {"ipAddress": ["8.8.8.8"], "maxAgeInDays": ["1"]},
        None,
    ),
    ProviderName.URLHAUS: ("POST", "/v1/payload/", {}, {"sha256_hash": [EICAR]}),
    ProviderName.MALWAREBAZAAR: (
        "POST",
        "/api/v1/",
        {},
        {"query": ["get_info"], "hash": [EICAR]},
    ),
    ProviderName.OTX: ("GET", "/api/v1/user/me", {}, None),
}
ABUSECH_NOT_FOUND = {
    ProviderName.URLHAUS: "no_results",
    ProviderName.MALWAREBAZAAR: "hash_not_found",
}


def _verify_cases() -> list[Any]:
    cases: list[Any] = []
    for name in PUBLIC:
        ok: dict[str, Any] = {"data": {}}
        if name in ABUSECH_NOT_FOUND:
            ok = {"query_status": ABUSECH_NOT_FOUND[name]}
            cases.append((name, 200, {"query_status": "unknown_auth_key"}, VerifyStatus.INVALID))
            cases.append((name, 200, {"query_status": "no_api_key"}, VerifyStatus.INVALID))
        cases += [
            (name, 200, ok, VerifyStatus.VALID),
            (name, 401, {"error": SENTINEL_KEY}, VerifyStatus.INVALID),
            (name, 403, {}, VerifyStatus.INVALID),
            (name, 429, {}, VerifyStatus.ERROR),
            (name, 503, {}, VerifyStatus.ERROR),
        ]
    cases.append((ProviderName.VIRUSTOTAL, 404, {"error": {}}, VerifyStatus.VALID))
    return [pytest.param(*case, id=f"{case[0].value}-{case[1]}-{case[3].value}") for case in cases]


@pytest.mark.parametrize(("name", "status", "body", "expected"), _verify_cases())
async def test_verify(
    name: ProviderName,
    status: int,
    body: Any,
    expected: VerifyStatus,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    outcome, [request] = await _run(name, lambda _: httpx.Response(status, json=body))
    assert outcome.status is expected
    if expected is VerifyStatus.INVALID:
        assert outcome.error_code == "auth"
    method, path, query, form = VERIFY_REQUESTS[name]
    assert (request.method, request.url.path) == (method, path)
    assert "/users/" not in request.url.path  # never the key-bearing VT user route (RT11)
    assert parse_qs(request.url.query.decode()) == query
    if form is not None:
        assert parse_qs(request.content.decode()) == form
    assert SENTINEL_KEY not in repr(outcome) + caplog.text


@pytest.mark.parametrize("name", PUBLIC)
def test_registry_builds_every_public_adapter(name: ProviderName) -> None:
    adapter = _adapter(name)
    assert adapter.name is name
    assert adapter.supported_types
    assert SENTINEL_KEY not in repr(adapter)
