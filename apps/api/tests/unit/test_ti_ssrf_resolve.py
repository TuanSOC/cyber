"""MISP SSRF hardening, worker half (M4 phase 4, RT1, RT5): resolution, pinning, SNI/Host.

A fake resolver stands in for DNS; the TLS test runs a local HTTPS server whose certificate
(from a throwaway CA) names a fake hostname, reached through the pinned loopback address.
"""

import asyncio
import ipaddress
import json
import socket
import ssl
import threading
import uuid
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import SecretStr, ValidationError

from app.core.config import Settings, get_settings
from app.modules.threat_intel import ssrf
from app.modules.threat_intel.http import KeyAuth, ti_client
from app.modules.threat_intel.providers import registry
from app.modules.threat_intel.providers.base import (
    IocRef,
    IocType,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    VerifyStatus,
)
from app.modules.threat_intel.providers.misp import MispProvider
from app.modules.threat_intel.seal import seal
from app.modules.threat_intel.ssrf import (
    MispUrlNotPublic,
    PinnedTransport,
    ValidatedBase,
    resolve_pinned,
    system_resolver,
    validate_base_url,
)
from app.modules.threat_intel.unseal import UnsealError
from app.workers import enrich
from tests.ti_helpers import SENTINEL_KEY
from tests.unit.test_config import BASE, PROD_TI
from tests.unit.test_ti_misp import Streamed

HOST = "misp.acme-corp.net"
PORTS = (443, 8443)
PUBLIC_V4 = "8.8.8.8"
PUBLIC_V6 = "2606:4700::1111"
LOOKUP = IocRef.of(IocType.DOMAIN, "malicious.acme-corp.net")


def _base(url: str = f"https://{HOST}", *, allow_private: bool = False) -> ValidatedBase:
    return validate_base_url(url, allowed_ports=PORTS, allow_private=allow_private)


class FakeResolver:
    """Answers each call with the next answer set (the last one repeats)."""

    def __init__(self, *answers: Sequence[str] | BaseException) -> None:
        self._answers = list(answers)
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, host: str, port: int) -> Sequence[str]:
        self.calls.append((host, port))
        answer = self._answers[min(len(self.calls), len(self._answers)) - 1]
        if isinstance(answer, BaseException):
            raise answer
        return answer


async def _resolve(*answers: str, allow_private: bool = False) -> list[Any]:
    return await resolve_pinned(
        _base(), resolver=FakeResolver(list(answers)), allow_private=allow_private
    )


# --- resolution ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "answers",
    [
        ["10.0.0.5"],
        ["172.16.3.4"],
        ["192.168.1.10"],
        ["127.0.0.1"],
        ["127.8.9.10"],
        ["169.254.169.254"],  # cloud metadata
        ["0.0.0.0"],  # noqa: S104
        ["100.64.0.1"],  # CGNAT
        ["192.0.2.10"],  # documentation
        ["224.0.0.1"],
        ["::1"],
        ["::"],
        ["fe80::1"],
        ["fe80::1%eth0"],
        ["fd00::1"],
        ["fd00:ec2::254"],  # AWS IPv6 metadata
        ["::ffff:10.0.0.1"],  # IPv4-mapped IPv6
        ["::ffff:127.0.0.1"],
        ["::ffff:169.254.169.254"],
        ["2002:7f00:1::"],  # 6to4 loopback
        ["64:ff9b::a9fe:a9fe"],  # NAT64 metadata
        [PUBLIC_V4, "10.0.0.5"],  # mixed: the OS could pick either
        ["10.0.0.5", PUBLIC_V4],
        [PUBLIC_V6, "::ffff:127.0.0.1"],
        ["not-an-ip"],
    ],
)
async def test_non_public_answers_are_refused(answers: list[str]) -> None:
    with pytest.raises(MispUrlNotPublic) as caught:
        await _resolve(*answers)
    assert caught.value.kind is ProviderErrorKind.MISP_URL_NOT_PUBLIC
    assert MispUrlNotPublic.code == "misp_url_not_public"


async def test_public_answers_keep_order_and_dedupe() -> None:
    got = await _resolve(PUBLIC_V4, PUBLIC_V6, PUBLIC_V4, "64:ff9b::808:808")
    assert [ip.compressed for ip in got] == [PUBLIC_V4, PUBLIC_V6, "64:ff9b::808:808"]


@pytest.mark.parametrize("answer", ["10.0.0.5", "fd00::1", "::ffff:192.168.1.1"])
async def test_dev_allow_private_accepts_private_ranges(answer: str) -> None:
    got = await _resolve(answer, allow_private=True)
    assert got[0] == ipaddress.ip_address(answer)


@pytest.mark.parametrize(
    "answer",
    [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104
        "::1",
        "::",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::",
        "224.0.0.1",
    ],
)
async def test_dev_allow_private_never_allows_loopback_metadata_unspecified(answer: str) -> None:
    with pytest.raises(MispUrlNotPublic):
        await _resolve(answer, allow_private=True)


async def test_ip_literal_is_rechecked_without_dns() -> None:
    resolver = FakeResolver(["10.0.0.5"])
    got = await resolve_pinned(_base("https://8.8.8.8"), resolver=resolver, allow_private=False)
    assert got == [ipaddress.ip_address("8.8.8.8")] and resolver.calls == []
    # Saved while the dev flag was on, used after it was turned off: refused.
    private = _base("https://10.0.0.5", allow_private=True)
    with pytest.raises(MispUrlNotPublic):
        await resolve_pinned(private, resolver=resolver, allow_private=False)


async def test_resolver_timeout_failure_and_empty_answer() -> None:
    async def slow(host: str, port: int) -> list[str]:
        await asyncio.sleep(5)
        return [PUBLIC_V4]

    with pytest.raises(ProviderError) as caught:
        await resolve_pinned(_base(), resolver=slow, allow_private=False, timeout_s=0.05)
    assert caught.value.kind is ProviderErrorKind.TIMEOUT
    for answer in (socket.gaierror(socket.EAI_NONAME, "nope"), []):
        with pytest.raises(ProviderError) as caught:
            await resolve_pinned(_base(), resolver=FakeResolver(answer), allow_private=False)
        assert caught.value.kind is ProviderErrorKind.TRANSPORT
    with pytest.raises(MispUrlNotPublic):  # too many answers to check: refused
        await _resolve(*[PUBLIC_V4] * (ssrf.MAX_ADDRESSES + 1))


async def test_system_resolver_uses_getaddrinfo_in_a_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[Any, ...]] = []
    main = threading.get_ident()

    def fake_getaddrinfo(host: str, port: int, **kwargs: Any) -> list[Any]:
        seen.append((host, port, kwargs, threading.get_ident() != main))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_V4, port)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (PUBLIC_V6, port, 0, 0)),
        ]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)
    got = await resolve_pinned(_base("https://misp.acme-corp.net:8443"), allow_private=False)
    assert [ip.compressed for ip in got] == [PUBLIC_V4, PUBLIC_V6]
    assert await system_resolver(HOST, 443) == [PUBLIC_V4, PUBLIC_V6]
    assert seen[0][:2] == (HOST, 8443) and seen[0][3] is True


async def test_system_resolver_fails_fast_when_every_dns_thread_is_stuck(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timed-out `getaddrinfo` keeps its thread; once all DNS threads are held, callers get
    `DnsBusy` at once instead of queueing behind them (and the threads are bounded)."""
    release = threading.Event()

    def stuck(host: str, port: int, **kwargs: Any) -> list[Any]:
        release.wait(10)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_V4, port))]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", stuck)
    loop = asyncio.get_running_loop()
    try:
        for _ in range(ssrf.DNS_WORKERS):
            with pytest.raises(ProviderError) as caught:
                await resolve_pinned(_base(), allow_private=False, timeout_s=0.05)
            assert caught.value.kind is ProviderErrorKind.TIMEOUT
            assert not isinstance(caught.value, ssrf.DnsBusy)
        started = loop.time()
        with pytest.raises(ssrf.DnsBusy) as busy:
            await resolve_pinned(_base(), allow_private=False, timeout_s=5)
        assert loop.time() - started < 1.0  # failed fast, did not wait for a thread
        assert busy.value.kind is ProviderErrorKind.TIMEOUT
        assert ssrf.DnsBusy.code == "dns_busy"
    finally:
        release.set()
    # The slots come back as soon as the stuck calls really return.
    for _ in range(100):
        try:
            assert await system_resolver(HOST, 443) == [PUBLIC_V4]
            break
        except ssrf.DnsBusy:
            await asyncio.sleep(0.02)
    else:
        pytest.fail("DNS slots were never released")


# --- pinning, SNI and Host -----------------------------------------------------------------


class Recorder:
    def __init__(self, response: httpx.Response | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._response = response

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._response is not None:
            return self._response
        if request.url.path.endswith("/servers/getVersion"):
            return httpx.Response(200, json={"version": "2.5.2"})
        return httpx.Response(200, json={"response": {"Attribute": []}})


def _misp(
    resolver: FakeResolver, recorder: Recorder, url: str = f"https://{HOST}"
) -> tuple[MispProvider, httpx.AsyncClient]:
    provider = MispProvider(_base(url), resolver=resolver, allow_private=False)
    client = ti_client(
        provider,
        auth=KeyAuth("Authorization", SecretStr(SENTINEL_KEY)),
        transport=provider.pinned_transport(Streamed(recorder)),
        org_host=provider.org_host,
    )
    return provider, client


async def test_request_goes_to_the_pinned_ip_with_host_and_sni_of_the_hostname() -> None:
    recorder = Recorder()
    provider, client = _misp(
        FakeResolver([PUBLIC_V4, "1.1.1.1"]), recorder, f"https://{HOST}:8443/misp"
    )
    async with client:
        assert (await provider.verify(client)).status is VerifyStatus.VALID
        await provider.lookup(client, LOOKUP)
    first, second = recorder.requests
    assert first.url.host == PUBLIC_V4 and first.url.port == 8443  # the first address
    assert first.url.path == "/misp/servers/getVersion"
    assert first.headers["host"] == f"{HOST}:8443"
    assert first.extensions["sni_hostname"] == HOST
    assert first.headers["authorization"] == SENTINEL_KEY  # raw key, no "Bearer"
    assert second.method == "POST" and second.url.path == "/misp/attributes/restSearch"
    assert second.url.host == PUBLIC_V4 and second.extensions["sni_hostname"] == HOST


async def test_idn_host_is_pinned_and_allowed_in_punycode() -> None:
    """`httpx.URL.host` is Unicode for an IDN; the checks compare the punycode form."""
    url = "https://bücher-acme.net/misp"
    host = _base(url).host
    assert host.isascii() and host.startswith("xn--")  # httpx decodes this one to Unicode
    recorder, resolver = Recorder(), FakeResolver([PUBLIC_V4])
    provider, client = _misp(resolver, recorder, url)
    async with client:
        assert (await provider.verify(client)).status is VerifyStatus.VALID
        await provider.lookup(client, LOOKUP)
    first, second = recorder.requests
    assert first.url.host == PUBLIC_V4 and first.headers["host"] == host
    assert first.extensions["sni_hostname"] == host
    assert second.url.path == "/misp/attributes/restSearch"
    assert resolver.calls == [(host, 443), (host, 443)]


async def test_ipv6_pin_is_bracketed() -> None:
    recorder = Recorder()
    resolver = FakeResolver([PUBLIC_V6])
    provider, client = _misp(resolver, recorder)
    async with client:
        await provider.verify(client)
    request = recorder.requests[0]
    assert str(request.url).startswith(f"https://[{PUBLIC_V6}]/")
    assert request.headers["host"] == HOST and resolver.calls == [(HOST, 443)]


async def test_ip_literal_base_sends_no_sni() -> None:
    recorder = Recorder()
    provider, client = _misp(FakeResolver([]), recorder, f"https://[{PUBLIC_V6}]:8443")
    async with client:
        await provider.verify(client)
    request = recorder.requests[0]
    assert request.headers["host"] == f"[{PUBLIC_V6}]:8443"
    assert "sni_hostname" not in request.extensions


async def test_dns_rebinding_public_on_verify_private_on_request() -> None:
    recorder = Recorder()
    resolver = FakeResolver([PUBLIC_V4], ["10.0.0.5"])
    provider, client = _misp(resolver, recorder)
    async with client:
        assert (await provider.verify(client)).status is VerifyStatus.VALID
        with pytest.raises(ProviderError) as caught:
            await provider.lookup(client, LOOKUP)
    assert caught.value.kind is ProviderErrorKind.MISP_URL_NOT_PUBLIC
    assert len(recorder.requests) == 1  # the lookup never left the host
    assert len(resolver.calls) == 2  # resolved again before the second request


@pytest.mark.parametrize("answer", ["169.254.169.254", "::ffff:127.0.0.1", "10.0.0.5"])
async def test_verify_marks_a_non_public_host_invalid(answer: str) -> None:
    recorder = Recorder()
    provider, client = _misp(FakeResolver([answer]), recorder)
    async with client:
        outcome = await provider.verify(client)
    assert (outcome.status, outcome.error_code) == (VerifyStatus.INVALID, "misp_url_not_public")
    assert recorder.requests == []


async def test_redirect_is_refused_and_not_followed() -> None:
    recorder = Recorder(
        httpx.Response(302, headers={"Location": "https://169.254.169.254/latest/meta-data/"})
    )
    provider, client = _misp(FakeResolver([PUBLIC_V4]), recorder)
    async with client:
        with pytest.raises(ProviderError) as caught:
            await provider.lookup(client, LOOKUP)
        outcome = await provider.verify(client)
    assert caught.value.kind is ProviderErrorKind.REDIRECT
    assert (outcome.status, outcome.error_code) == (VerifyStatus.ERROR, "redirect")
    assert len(recorder.requests) == 2  # one per call: nothing followed


async def test_oversize_body_is_refused_at_the_misp_cap() -> None:
    pad = b"x" * (2 * 1024 * 1024)
    over = httpx.Response(200, content=b'{"response":{"Attribute":[]},"p":"' + pad + b'"}')
    provider, client = _misp(FakeResolver([PUBLIC_V4]), Recorder(over))
    async with client:
        with pytest.raises(ProviderError) as caught:
            await provider.lookup(client, LOOKUP)
    assert caught.value.kind is ProviderErrorKind.OVERSIZE
    # 1.5 MiB is above the generic 1 MiB cap but within MISP's 2 MiB.
    under = b'{"response":{"Attribute":[]},"p":"' + b"x" * (1536 * 1024) + b'"}'
    provider, client = _misp(
        FakeResolver([PUBLIC_V4]), Recorder(httpx.Response(200, content=under))
    )
    async with client:
        assert (await provider.lookup(client, LOOKUP)).status == "not_found"


async def test_transport_refuses_any_other_origin_before_resolving() -> None:
    resolver = FakeResolver([PUBLIC_V4])
    recorder = Recorder()
    transport = PinnedTransport(Streamed(recorder), _base(), resolver=resolver)
    for url in (
        "https://evil.example.net/attributes/restSearch",
        f"http://{HOST}/attributes/restSearch",
        f"https://{HOST}:8443/attributes/restSearch",
        f"https://{PUBLIC_V4}/attributes/restSearch",
    ):
        with pytest.raises(ProviderError) as caught:
            await transport.handle_async_request(httpx.Request("POST", url))
        assert caught.value.kind is ProviderErrorKind.PATH_NOT_ALLOWED
    assert resolver.calls == [] and recorder.requests == []


# --- TLS: the certificate is verified against the hostname, not the pinned IP --------------


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _tls_files(tmp: Path, cert_host: str) -> tuple[Path, Path, Path]:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("CyberLab test CA"))
        .issuer_name(_name("CyberLab test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(cert_host))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cert_host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_file, cert_file, key_file = tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_file, cert_file, key_file


class _Server(ThreadingHTTPServer):
    seen: list[tuple[str, str | None, str | None]]


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.server.seen.append(
            (self.path, self.headers.get("Host"), self.headers.get("Authorization"))
        )
        body = json.dumps({"version": "2.5.2"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def tls_server(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[tuple[Any, ...]]:
    cert_host = getattr(request, "param", HOST)
    ca_file, cert_file, key_file = _tls_files(tmp_path, cert_host)
    server = _Server(("127.0.0.1", 0), _Handler)
    server.seen = []
    sni: list[str | None] = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.sni_callback = lambda _sock, name, _ctx: sni.append(name)  # type: ignore[assignment,misc,return-value]
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, server.server_address[1], ca_file, sni
    finally:
        server.shutdown()
        server.server_close()


async def _verify_over_tls(
    monkeypatch: pytest.MonkeyPatch, port: int, ca_file: Path
) -> tuple[Any, list[Any]]:
    pinned: list[Any] = []

    async def loopback(validated: ValidatedBase, **_: Any) -> list[Any]:
        # Loopback is never allowed for real: the TLS test pins it by hand.
        pinned.append(validated.host)
        return [ipaddress.ip_address("127.0.0.1")]

    monkeypatch.setattr(ssrf, "resolve_pinned", loopback)
    settings = get_settings().model_copy(
        update={"ti_misp_ca_file": str(ca_file), "ti_misp_insecure_tls": False}
    )
    base = validate_base_url(f"https://{HOST}:{port}", allowed_ports=[port], allow_private=False)
    provider = MispProvider(base, settings=settings)
    client = ti_client(
        provider,
        auth=KeyAuth("Authorization", SecretStr(SENTINEL_KEY)),
        transport=provider.pinned_transport(),
        org_host=provider.org_host,
    )
    async with client:
        return await provider.verify(client), pinned


async def test_tls_verifies_the_hostname_while_connecting_to_the_pinned_ip(
    tls_server: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    server, port, ca_file, sni = tls_server
    outcome, pinned = await _verify_over_tls(monkeypatch, port, ca_file)
    assert outcome.status is VerifyStatus.VALID, outcome
    assert pinned == [HOST] and sni == [HOST]
    assert server.seen == [("/servers/getVersion", f"{HOST}:{port}", SENTINEL_KEY)]


@pytest.mark.parametrize("tls_server", ["other.acme-corp.net"], indirect=True)
async def test_tls_refuses_a_certificate_for_another_name(
    tls_server: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    server, port, ca_file, _ = tls_server
    outcome, _ = await _verify_over_tls(monkeypatch, port, ca_file)
    assert (outcome.status, outcome.error_code) == (VerifyStatus.ERROR, "transport")
    assert server.seen == []


# --- prod flags and the URL-bound key (RT1) ------------------------------------------------


@pytest.mark.parametrize("flag", ["ti_misp_allow_private", "ti_misp_insecure_tls"])
def test_prod_refuses_allow_private_and_insecure_tls(flag: str) -> None:
    with pytest.raises(ValidationError, match=flag.upper()):
        Settings(**BASE, **{**PROD_TI, flag: True}, env="prod", cookie_secure=True)


def _deps(private: X25519PrivateKey, resolver: FakeResolver, recorder: Recorder) -> enrich.Deps:
    settings = get_settings().model_copy(update={"ti_seal_active_kid": "k1"})

    def create(name: ProviderName, ctx: registry.ProviderContext) -> Any:
        assert name is ProviderName.MISP
        base = validate_base_url(ctx.base_url_norm, allowed_ports=PORTS, allow_private=False)
        return MispProvider(base, resolver=resolver, allow_private=False)

    return enrich.Deps(
        settings=settings,
        limiter=None,  # type: ignore[arg-type]  # not used by _open_provider
        private_keys={"k1": private},
        create_provider=create,
        transport=Streamed(recorder),
    )


def _config(org: uuid.UUID, private: X25519PrivateKey, sealed_for: str, stored: str) -> Any:
    sealed = seal(SecretStr(SENTINEL_KEY), org, "misp", "k1", 1, sealed_for, private.public_key())
    return enrich._Config(
        id=uuid.uuid4(),
        provider=ProviderName.MISP,
        enabled=True,
        base_url=stored,
        sealed=sealed,
        limits={},
    )


async def test_worker_opens_misp_through_the_pinned_transport() -> None:
    org, private = uuid.uuid4(), X25519PrivateKey.generate()
    recorder, resolver = Recorder(), FakeResolver([PUBLIC_V4])
    deps = _deps(private, resolver, recorder)
    url = f"https://{HOST}/misp"
    adapter, client = await enrich._open_provider(deps, org, _config(org, private, url, url))
    async with client:
        assert (await adapter.verify(client)).status is VerifyStatus.VALID
    request = recorder.requests[0]
    assert request.url.host == PUBLIC_V4 and request.headers["host"] == HOST
    assert request.extensions["sni_hostname"] == HOST
    assert request.headers["authorization"] == SENTINEL_KEY
    assert resolver.calls == [(HOST, 443)]


async def test_misp_key_sealed_for_url_a_does_not_open_for_url_b() -> None:
    org, private = uuid.uuid4(), X25519PrivateKey.generate()
    recorder = Recorder()
    deps = _deps(private, FakeResolver([PUBLIC_V4]), recorder)
    url_a, url_b = "https://misp.acme-corp.net", "https://evil.example-attacker.net"
    with pytest.raises(UnsealError):
        await enrich._open_provider(deps, org, _config(org, private, url_a, url_b))
    assert recorder.requests == []


# --- syntactic: IPv4 written as a name (phase-2 review) -----------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://10.0.0.0x1/",
        "https://0x7f.1/",
        "https://127.1/",
        "https://10.1/",
        "https://misp.0x0/",
        "https://misp.acme-corp.123/",
        "https://0x7f000001/",
        "https://017700000001/",
    ],
)
def test_ipv4_like_names_are_refused(url: str) -> None:
    with pytest.raises(ssrf.MispUrlInvalid) as caught:
        validate_base_url(url, allowed_ports=PORTS, allow_private=True)
    assert caught.value.reason == "host"


def test_names_with_digits_are_still_fine() -> None:
    for url in ("https://misp1.acme-corp.net", "https://123.acme-corp.net", "https://0x.acme.io"):
        assert validate_base_url(url, allowed_ports=PORTS, allow_private=False).host
