"""The MISP adapter against the committed fixtures (M4 phase 4).

Every request goes through the real stack: `ti_client` (allowlist guard, `KeyAuth`) and the
pinned transport (a fake resolver answers a public address) in front of a MockTransport.
"""

import json
import logging
import re
import ssl
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import get_settings
from app.modules.threat_intel.http import KeyAuth, PathNotAllowed, path_allowed, ti_client
from app.modules.threat_intel.providers import misp as misp_module
from app.modules.threat_intel.providers.base import (
    IocRef,
    IocType,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
    VerifyStatus,
)
from app.modules.threat_intel.providers.misp import (
    MISP_TYPES,
    MispProvider,
    attack_ids,
    build_result,
    create,
    search_body,
    tlp_labels,
    tls_verify,
)
from app.modules.threat_intel.providers.registry import ProviderContext
from app.modules.threat_intel.ssrf import MispUrlInvalid, validate_base_url
from app.modules.threat_intel.summaries import MispSummary, summary_size

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ti"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
SPEC = MANIFEST["providers"]["misp"]
CASES: dict[str, dict[str, Any]] = SPEC["cases"]
SENTINEL = MANIFEST["sentinel_key"]
# The manifest says https://misp.example.org, but example.org is special-use (RFC 2606) and
# refused as a MISP host: the fixtures are served for an ordinary name instead.
BASE_URL = "https://misp.acme-corp.net"
PUBLIC_IP = "8.8.8.8"

_TYPES = {
    "ip": None,  # v4 or v6 by value
    "domain": IocType.DOMAIN,
    "url": IocType.URL,
    "email": IocType.EMAIL,
    "file_md5": IocType.MD5,
    "file_sha1": IocType.SHA1,
    "file_sha256": IocType.SHA256,
}


def _ioc(case: dict[str, Any]) -> IocRef:
    value = case["ioc_value"]
    ioc_type = _TYPES[case["ioc_type"]] or (IocType.IPV6 if ":" in value else IocType.IPV4)
    return IocRef.of(ioc_type, value)


class _Body(httpx.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._data


class Streamed(httpx.AsyncBaseTransport):
    """`httpx.MockTransport` whose responses arrive as a stream, as from the network (a
    `Response(content=...)` built by a handler is already read in memory)."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self._handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = self._handler(request)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=_Body(response.content),
            request=request,
        )


class Resolver:
    def __init__(self, *answer: str) -> None:
        self.answer = list(answer) or [PUBLIC_IP]
        self.calls = 0

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls += 1
        return self.answer


class Sink:
    """Serves one manifest case and records what reached the wire."""

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        case = self.case
        simulate = case.get("simulate", "")
        if simulate.startswith("httpx.ReadTimeout"):
            raise httpx.ReadTimeout("slow", request=request)
        if case["expect"] == "oversize":
            return httpx.Response(200, content=b"[" + b" " * (2 * 1024 * 1024) + b"]")
        body = (FIXTURES / "misp" / case["file"]).read_bytes()
        return httpx.Response(case["http_status"], headers=case["headers"], content=body)


def _provider(url: str = BASE_URL, resolver: Resolver | None = None) -> MispProvider:
    base = validate_base_url(url, allowed_ports=(443, 8443), allow_private=False)
    return MispProvider(base, resolver=resolver or Resolver(), allow_private=False)


def _client(provider: MispProvider, handler: Any) -> httpx.AsyncClient:
    return ti_client(
        provider,
        auth=KeyAuth("Authorization", SecretStr(SENTINEL)),
        transport=provider.pinned_transport(Streamed(handler)),
        org_host=provider.org_host,
    )


async def _lookup(case_name: str, url: str = BASE_URL) -> tuple[ProviderResult, Sink]:
    case = CASES[case_name]
    sink = Sink(case)
    provider = _provider(url)
    async with _client(provider, sink) as client:
        result = await provider.lookup(client, _ioc(case))
    return result, sink


def _check_wire(sink: Sink, case: dict[str, Any], prefix: str = "") -> None:
    (request,) = sink.requests
    assert request.method == case["request"]["method"]
    assert request.url.path == prefix + case["request"]["path"]
    assert request.url.host == PUBLIC_IP  # pinned
    assert request.headers["host"] == "misp.acme-corp.net"
    assert request.extensions["sni_hostname"] == "misp.acme-corp.net"
    assert request.headers["authorization"] == SENTINEL  # raw, never "Bearer"
    assert request.headers["accept"] == "application/json"
    if request.method == "POST":
        assert request.headers["content-type"] == "application/json"
        body = json.loads(request.content)
        expected = {**SPEC["request_body_template"], "value": case["ioc_value"]}
        assert {k: body[k] for k in expected} == expected
        assert body["type"] == list(MISP_TYPES[_ioc(case).ioc_type])


_ERRORS = {
    "auth": {ProviderErrorKind.AUTH},
    "rate_limited": {ProviderErrorKind.RATE_LIMITED},
    "unavailable": {ProviderErrorKind.HTTP_5XX, ProviderErrorKind.REDIRECT},
    "parse_error": {ProviderErrorKind.BAD_JSON},
    "timeout": {ProviderErrorKind.TIMEOUT},
    "oversize": {ProviderErrorKind.OVERSIZE},
}
LOOKUP_CASES = sorted(n for n, c in CASES.items() if c["ioc_type"] is not None)


def test_manifest_lists_every_case() -> None:
    assert len(CASES) == SPEC["case_count"]
    assert SPEC["auth_header"] == "Authorization"


@pytest.mark.parametrize("name", LOOKUP_CASES)
async def test_lookup_fixture(name: str) -> None:
    case = CASES[name]
    expect = case["expect"]
    if expect in _ERRORS:
        with pytest.raises(ProviderError) as caught:
            await _lookup(name)
        error = caught.value
        assert error.kind in _ERRORS[expect], error
        assert SENTINEL not in str(error) and SENTINEL not in repr(error)
        if "Retry-After" in case["headers"]:
            assert error.retry_after_s == 60
        return
    result, sink = await _lookup(name)
    _check_wire(sink, case)
    if expect == "not_found":
        assert result.status is ResultStatus.NOT_FOUND and not result.found
        assert result.summary is None and result.permalink is None
        return
    assert expect in ("found", "found_sanitized", "found_capped")
    assert result.status is ResultStatus.OK and result.found
    assert isinstance(result.summary, MispSummary)
    assert summary_size(result.summary) <= 16 * 1024
    dumped = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    for bad in ("\u0000", "\u0007", "\u001b", "‮", "⁦", "​", "\r", "\n"):
        assert bad not in dumped
    assert SENTINEL not in dumped
    if result.permalink is not None:
        assert re.fullmatch(
            r"https://misp\.acme-corp\.net/events/view/[1-9][0-9]*", result.permalink
        )


async def test_ip_hit_summary() -> None:
    result, _ = await _lookup("ip_hit")
    summary = result.summary
    assert isinstance(summary, MispSummary)
    assert summary.attribute_count == 2 and len(summary.attributes) == 2
    first = summary.attributes[0]
    assert (first.type, first.category, first.to_ids) == ("ip-dst", "Network activity", True)
    assert first.event_id == 42
    assert first.event_info == "ExampleBot C2 infrastructure (fixture)"
    assert first.event_uuid == uuid.UUID("5f1c0000-0000-4000-8000-000000000042")
    assert first.first_seen == datetime(2026, 10, 20, 8, tzinfo=UTC)
    assert first.timestamp == datetime.fromtimestamp(1793660400, UTC)
    assert "tlp:amber" in first.tags
    assert summary.tlp == ["tlp:amber", "tlp:green"]  # TLP kept, most restrictive first
    assert result.attack_ids == ["T1059.001"]  # from the ATT&CK galaxy tag
    assert result.families == ["ExampleBot"]
    assert "tlp:amber" in result.tags and "tlp:green" in result.tags
    assert result.permalink == "https://misp.acme-corp.net/events/view/42"
    assert result.first_seen == datetime(2026, 10, 20, 8, tzinfo=UTC)
    assert result.last_seen == datetime(2026, 11, 2, 22, tzinfo=UTC)
    assert result.score is None and result.detections is None  # verdict-free


async def test_email_hit_searches_email_types_and_keeps_tlp_red() -> None:
    result, sink = await _lookup("email_hit")
    body = json.loads(sink.requests[0].content)
    assert {"email-src", "email-dst"} <= set(body["type"])
    assert isinstance(result.summary, MispSummary)
    assert [a.type for a in result.summary.attributes] == ["email-src", "email-dst"]
    assert result.summary.tlp == ["tlp:red"]


async def test_hostile_attributes_are_sanitized_and_build_no_permalink() -> None:
    result, _ = await _lookup("ip_hostile")
    summary = result.summary
    assert isinstance(summary, MispSummary)
    assert summary.attribute_count == 2
    # "42/../../admin/users" and "-1" are not numeric event ids.
    assert [a.event_id for a in summary.attributes] == [None, None]
    assert result.permalink is None
    assert result.attack_ids == ["T1059.001"]  # "T99999" dropped
    assert summary.tlp == ["tlp:red"]  # the bidi "tlp:invoice..." is not a TLP marking
    first, second = summary.attributes
    assert first.event_uuid is None and second.event_uuid is None
    assert first.first_seen is None and first.last_seen is None
    assert second.to_ids is False  # "yes" is not a boolean
    assert second.type == "invoicegpj.exe"  # bidi overrides stripped


async def test_huge_answer_is_capped_but_counted() -> None:
    result, _ = await _lookup("ip_huge")
    summary = result.summary
    raw = json.loads((FIXTURES / "misp" / "attributes_huge.json").read_bytes())
    assert isinstance(summary, MispSummary)
    assert summary.attribute_count == len(raw["response"]["Attribute"]) > 20
    assert len(summary.attributes) == 20
    assert summary.tlp == ["tlp:green"]


async def test_permalink_uses_base_url_norm_with_port_and_prefix() -> None:
    case = CASES["ip_hit"]
    sink = Sink(case)
    provider = _provider("https://misp.acme-corp.net:8443/misp")
    async with _client(provider, sink) as client:
        result = await provider.lookup(client, _ioc(case))
    assert result.permalink == "https://misp.acme-corp.net:8443/misp/events/view/42"
    assert sink.requests[0].url.path == "/misp/attributes/restSearch"
    assert sink.requests[0].headers["host"] == "misp.acme-corp.net:8443"


@pytest.mark.parametrize(
    ("data", "status"),
    [
        ({"response": {"Attribute": []}}, ResultStatus.NOT_FOUND),
        ({"response": []}, ResultStatus.NOT_FOUND),
        ({"response": {"Attribute": [1, "x", None]}}, ResultStatus.NOT_FOUND),
    ],
)
def test_empty_shapes(data: Any, status: ResultStatus) -> None:
    assert build_result(BASE_URL, data).status is status


@pytest.mark.parametrize(
    "data",
    [None, [], "x", {"response": {"Attribute": "x"}}, {"response": "x"}, {"Attribute": []}],
)
def test_wrong_shapes_are_bad_json(data: Any) -> None:
    with pytest.raises(ProviderError) as caught:
        build_result(BASE_URL, data)
    assert caught.value.kind is ProviderErrorKind.BAD_JSON


@pytest.mark.parametrize(
    ("event_id", "expected"),
    [
        ("42", 42),
        (7, 7),
        ("0", None),
        ("-1", None),
        ("042", None),
        ("4 2", None),
        ("42/../admin", None),
        ("1e3", None),
        (True, None),
        (2**63, None),
        ("9" * 19, None),
    ],
)
def test_event_id_must_be_numeric(event_id: Any, expected: int | None) -> None:
    attribute = {"type": "ip-dst", "event_id": event_id, "value": "8.8.8.8"}
    result = build_result(BASE_URL, {"response": {"Attribute": [attribute]}})
    assert isinstance(result.summary, MispSummary)
    assert result.summary.attributes[0].event_id == expected
    if expected is None:
        assert result.permalink is None
    else:
        assert result.permalink == f"{BASE_URL}/events/view/{expected}"


def test_permalink_is_the_first_valid_event() -> None:
    attributes = [
        {"type": "ip-dst", "event_id": "x"},
        {"type": "ip-dst", "event_id": "77"},
        {"type": "ip-dst", "event_id": "78"},
    ]
    result = build_result(BASE_URL, {"response": {"Attribute": attributes}})
    assert result.permalink == f"{BASE_URL}/events/view/77"


def test_tlp_and_attack_helpers() -> None:
    names = [
        "TLP:GREEN",
        "tlp:amber+strict",
        "tlp:clear",
        "tlp:white",
        "tlp:red",
        "tlp:amber",
        "tlp:bogus",
    ]
    assert tlp_labels(names) == [
        "tlp:red",
        "tlp:amber+strict",
        "tlp:amber",
        "tlp:green",
        "tlp:clear",
        "tlp:white",
    ]
    assert attack_ids(
        [
            'misp-galaxy:mitre-attack-pattern="Process Injection - T1055"',
            'misp-galaxy:mitre-enterprise-attack-attack-pattern="PowerShell - T1059.001"',
            'misp-galaxy:mitre-attack-pattern="Dup - T1055"',
            'misp-galaxy:mitre-attack-pattern="Bad - T99999"',
            'misp-galaxy:mitre-attack-pattern="Bad - T1055.1"',
            'misp-galaxy:malpedia="T1003"',  # not an attack-pattern galaxy
            "T1003",  # a plain tag is not a galaxy tag
        ]
    ) == ["T1055", "T1059.001"]


def test_tlp_cap_never_hides_red() -> None:
    attributes = [
        {"type": "ip-dst", "Tag": [{"name": f"tlp:{level}"}]}
        for level in ("white", "clear", "green", "amber", "amber+strict")
    ] + [{"type": "ip-dst", "Tag": [{"name": "tlp:red"}]}]
    result = build_result(BASE_URL, {"response": {"Attribute": attributes}})
    assert isinstance(result.summary, MispSummary)
    assert result.summary.tlp == ["tlp:red", "tlp:amber+strict", "tlp:amber", "tlp:green"]


def test_event_tags_count_too() -> None:
    attribute = {"type": "ip-dst", "Event": {"id": "5", "Tag": [{"name": "tlp:amber"}]}}
    result = build_result(BASE_URL, {"response": {"Attribute": [attribute]}})
    assert isinstance(result.summary, MispSummary)
    assert result.summary.tlp == ["tlp:amber"]
    assert result.permalink == f"{BASE_URL}/events/view/5"  # Event.id when event_id is absent


@pytest.mark.parametrize("ioc_type", list(IocType))
def test_every_supported_type_has_misp_types(ioc_type: IocType) -> None:
    provider = _provider()
    assert ioc_type in provider.supported_types
    body = search_body(IocRef.of(ioc_type, "x"))
    assert body["type"] and body["limit"] == 50 and body["enforceWarninglist"] is True
    assert body["includeEventTags"] is True and body["deleted"] is False


# --- verify --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "status", "code"),
    [
        ("verify_get_version", VerifyStatus.VALID, None),
        ("verify_unauthorized", VerifyStatus.INVALID, "auth"),
    ],
)
async def test_verify_fixture(name: str, status: VerifyStatus, code: str | None) -> None:
    case = CASES[name]
    sink = Sink(case)
    provider = _provider()
    async with _client(provider, sink) as client:
        outcome = await provider.verify(client)
    assert (outcome.status, outcome.error_code) == (status, code)
    _check_wire(sink, case)


@pytest.mark.parametrize(
    ("response", "status", "code"),
    [
        (httpx.Response(403, json={"message": SENTINEL}), VerifyStatus.INVALID, "auth"),
        (httpx.Response(500, json={}), VerifyStatus.ERROR, "http_5xx"),
        (httpx.Response(200, json={}), VerifyStatus.ERROR, "bad_json"),
        (httpx.Response(200, content=b"<html>login</html>"), VerifyStatus.ERROR, "bad_json"),
    ],
)
async def test_verify_errors(response: httpx.Response, status: VerifyStatus, code: str) -> None:
    provider = _provider()
    async with _client(provider, lambda request: response) as client:
        outcome = await provider.verify(client)
    assert (outcome.status, outcome.error_code) == (status, code)


# --- allowlist -----------------------------------------------------------------------------


def test_allowlist_is_restsearch_post_and_getversion_get_only() -> None:
    provider = _provider("https://misp.acme-corp.net/misp")
    shapes = {(p.method, p.host, p.path.pattern) for p in provider.allowed_paths}
    assert shapes == {
        ("POST", None, "/misp/attributes/restSearch"),
        ("GET", None, "/misp/servers/getVersion"),
    }


@pytest.mark.parametrize(
    ("method", "url", "allowed"),
    [
        ("POST", "https://misp.acme-corp.net/misp/attributes/restSearch", True),
        ("GET", "https://misp.acme-corp.net/misp/servers/getVersion", True),
        ("GET", "https://misp.acme-corp.net/misp/attributes/restSearch", False),
        ("POST", "https://misp.acme-corp.net/misp/servers/getVersion", False),
        ("POST", "https://misp.acme-corp.net/attributes/restSearch", False),  # no prefix
        ("POST", "https://misp.acme-corp.net/misp/events/restSearch", False),
        ("GET", "https://misp.acme-corp.net/misp/events/view/42", False),
        ("POST", "https://misp.acme-corp.net/misp/attributes/add/1", False),
        ("POST", "https://misp.acme-corp.net/misp/attributes/restSearch/x", False),
        ("POST", "https://misp.acme-corp.net/misp/../attributes/restSearch", False),
        ("POST", "https://misp.acme-corp.net/misp/attributes%2frestSearch", False),
        ("POST", "https://evil.example.net/misp/attributes/restSearch", False),
    ],
)
async def test_allowlist_enforced_before_sending(method: str, url: str, allowed: bool) -> None:
    provider = _provider("https://misp.acme-corp.net/misp")
    request = httpx.Request(method, url)
    assert path_allowed(request, provider.allowed_paths, org_host=provider.org_host) is allowed
    sink = Sink({"expect": "x", "file": "get_version.json", "http_status": 200, "headers": {}})
    if not allowed:
        async with _client(provider, sink) as client:
            with pytest.raises(PathNotAllowed):
                await client.request(method, url)
        assert sink.requests == []


# --- factory and TLS settings --------------------------------------------------------------


def test_create_requires_a_normalized_valid_url() -> None:
    settings = get_settings()
    provider = create(ProviderContext(settings, "https://misp.acme-corp.net/misp"))
    assert provider.name is ProviderName.MISP
    assert provider.base.base_url_norm == "https://misp.acme-corp.net/misp"
    with pytest.raises(ValueError, match="normalized"):
        create(ProviderContext(settings, "https://MISP.acme-corp.net/misp/"))
    for bad in ("", "http://misp.acme-corp.net", "https://10.0.0.5", "https://misp.local"):
        with pytest.raises(MispUrlInvalid):
            create(ProviderContext(settings, bad))


def test_tls_verify_settings(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    settings = get_settings()
    dev = settings.model_copy(update={"env": "dev", "ti_misp_insecure_tls": False})
    assert tls_verify(dev.model_copy(update={"ti_misp_ca_file": None})) is True
    ca = Path(ssl.get_default_verify_paths().cafile or "")
    if ca.is_file():
        context = tls_verify(dev.model_copy(update={"ti_misp_ca_file": str(ca)}))
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname and context.verify_mode is ssl.CERT_REQUIRED
    with caplog.at_level(logging.WARNING, logger=misp_module.__name__):
        assert tls_verify(dev.model_copy(update={"ti_misp_insecure_tls": True})) is False
    assert "NOT verified" in caplog.text
    # Belt and braces: even a prod Settings object that slipped past _prod_guards verifies.
    prod = dev.model_copy(update={"env": "prod", "ti_misp_insecure_tls": True})
    assert tls_verify(prod) is True
