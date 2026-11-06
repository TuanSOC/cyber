"""`fetch-windows` network rules (M8 phase 5, RT11), against `httpx.MockTransport` only: no
test ever opens a socket to Microsoft (parent decision). HTTPS only, at most 3 redirects,
allow-listed hosts, no IP literals / userinfo / other ports, a size cap, a GUID / age check of
the converted ISF, and the URL built from validated parts only."""

import hashlib
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from cyberlab_jobs.memory import WindowsPdb

from memory_worker.symbols import fetch_windows as fw
from memory_worker.symbols.manifest import read_manifest
from memory_worker.symbols.store import SymbolStore
from tests.symbols_helpers import GUID, new_store, schema_dir

PDB = WindowsPdb(name="ntkrnlmp.pdb", guid=GUID, age=26)
ORIGIN = f"https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/{GUID}1A/ntkrnlmp.pdb"
CDN = "https://vsblobprodscussu5shard30.blob.core.windows.net/b-1/x.pdb?sv=1&sig=SECRET"
SMALL = fw.FetchPolicy(max_bytes=1024)


def test_the_url_is_built_from_validated_parts_with_a_hex_age() -> None:
    assert fw.symbol_url(PDB) == ORIGIN
    assert fw.symbol_url(PDB.model_copy(update={"age": 1})).endswith(f"/{GUID}1/ntkrnlmp.pdb")
    forged = PDB.model_copy(update={"name": "../../x"})  # model_copy skips validation
    with pytest.raises(ValueError):
        fw.symbol_url(forged)


@pytest.mark.parametrize(
    "url",
    [
        ORIGIN,
        CDN,
        "https://MSDL.Microsoft.COM/download/symbols/x",
        "https://a.vsblob.vsassets.io/x",
        "https://msdl.microsoft.com:443/x",
    ],
)
def test_allowed_hops(url: str) -> None:
    fw.check_url(url)


@pytest.mark.parametrize(
    ("url", "match"),
    [
        ("http://msdl.microsoft.com/download/symbols/x", "non-HTTPS"),
        ("ftp://msdl.microsoft.com/x", "non-HTTPS"),
        ("https://127.0.0.1/x", "IP-literal"),
        ("https://[::1]/x", "IP-literal"),
        ("https://[2001:db8::1]:443/x", "IP-literal"),
        ("https://127.1/x", "invalid host"),
        ("https://0x7f.0.0.1/x", "invalid host"),
        ("https://user@msdl.microsoft.com/x", "userinfo"),
        ("https://user:pw@msdl.microsoft.com/x", "userinfo"),
        ("https://msdl.microsoft.com:8443/x", "port 8443"),
        ("https://msdl.microsoft.com:0/x", "port 0"),
        ("https://msdl.microsoft.com:99999/x", "invalid port"),
        ("https://evil.example/x", "SYMBOL_REDIRECT_SUFFIXES"),
        ("https://evilblob.core.windows.net/x", "SYMBOL_REDIRECT_SUFFIXES"),
        ("https://blob.core.windows.net/x", "SYMBOL_REDIRECT_SUFFIXES"),
        ("https://x.blob.core.windows.net.evil.example/x", "SYMBOL_REDIRECT_SUFFIXES"),
        ("https://msdl.microsoft.com.evil.example/x", "SYMBOL_REDIRECT_SUFFIXES"),
        ("https://msdl.microsoft.com./x", "invalid host"),
        ("https://msdl.microsoft.com\\@evil.example/x", "spaces, control"),
        ("https://msdl.microsoft.com/x y", "spaces, control"),
        ("https://msdl.microsoft.com/\x00", "spaces, control"),
        ("https://xn--msdl-.microsoft.com/x", "invalid host"),
        ("https://msdl.mícrosoft.com/x", "non-ASCII"),
        ("https:///x", "IP-literal or empty"),
    ],
)
def test_refused_hops(url: str, match: str) -> None:
    with pytest.raises(fw.FetchRefused, match=match):
        fw.check_url(url)


def test_a_refused_redirect_names_the_host() -> None:
    with pytest.raises(fw.FetchRefused) as info:
        fw.check_url("https://cdn.unknown-microsoft.example/x")
    assert info.value.host == "cdn.unknown-microsoft.example"
    assert "cdn.unknown-microsoft.example" in str(info.value)


def _transport(
    routes: dict[str, Callable[[httpx.Request], httpx.Response]], seen: list[str]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        assert request.headers["accept-encoding"] == "identity"
        return routes[url](request)

    return httpx.MockTransport(handler)


def _redirect(to: str, status: int = 302) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _r: httpx.Response(status, headers={"Location": to})


def _body(data: bytes, **headers: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _r: httpx.Response(200, content=data, headers=headers)


def _cdn(n: int) -> str:
    return f"https://shard{n}.blob.core.windows.net/b/x.pdb?sig=S{n}"


def test_three_redirects_are_followed(tmp_path: Path) -> None:
    seen: list[str] = []
    routes = {
        ORIGIN: _redirect(_cdn(1), 301),
        _cdn(1): _redirect(_cdn(2), 307),
        _cdn(2): _redirect("/b/final.pdb?sig=S3", 308),  # relative Location
        "https://shard2.blob.core.windows.net/b/final.pdb?sig=S3": _body(b"PDB"),
    }
    logged: list[dict[str, Any]] = []
    got = fw.download(
        PDB,
        tmp_path / "p.pdb",
        transport=_transport(routes, seen),
        log=lambda event, **f: logged.append({"event": event, **f}),
    )
    assert got.size == 3 and (tmp_path / "p.pdb").read_bytes() == b"PDB"
    assert len(seen) == 4
    assert all("sig=" not in u for u in got.urls)  # signatures never reach the log
    assert [e["hop"] for e in logged if e["event"] == "fetch"] == [0, 1, 2, 3]


def test_a_fourth_redirect_is_refused(tmp_path: Path) -> None:
    seen: list[str] = []
    routes = {
        ORIGIN: _redirect(_cdn(1)),
        _cdn(1): _redirect(_cdn(2)),
        _cdn(2): _redirect(_cdn(3)),
        _cdn(3): _redirect(_cdn(4)),
        _cdn(4): _body(b"never"),
    }
    with pytest.raises(fw.FetchRefused, match="more than 3 redirects"):
        fw.download(PDB, tmp_path / "p.pdb", transport=_transport(routes, seen))
    assert _cdn(4) not in seen


@pytest.mark.parametrize(
    ("location", "match"),
    [
        ("http://shard1.blob.core.windows.net/x", "non-HTTPS"),
        ("https://10.0.0.5/x", "IP-literal"),
        ("//evil.example/x", "evil.example"),
        ("https://evil.example/x", "evil.example"),
        ("https://u:p@shard1.blob.core.windows.net/x", "userinfo"),
        ("https://shard1.blob.core.windows.net:444/x", "port 444"),
    ],
)
def test_a_redirect_to_a_refused_hop_is_never_requested(
    tmp_path: Path, location: str, match: str
) -> None:
    seen: list[str] = []
    routes = {ORIGIN: _redirect(location)}
    with pytest.raises(fw.FetchRefused, match=match):
        fw.download(PDB, tmp_path / "p.pdb", transport=_transport(routes, seen))
    assert seen == [ORIGIN]


def test_oversize_bodies_are_refused(tmp_path: Path) -> None:
    declared = {ORIGIN: _body(b"x" * 2048)}
    with pytest.raises(fw.FetchRefused, match="larger than"):
        fw.download(PDB, tmp_path / "a", policy=SMALL, transport=_transport(declared, []))

    def streamed(_r: httpx.Request) -> httpx.Response:  # no Content-Length
        return httpx.Response(200, content=iter([b"x" * 600, b"x" * 600]))

    with pytest.raises(fw.FetchRefused, match="larger than"):
        fw.download(PDB, tmp_path / "b", policy=SMALL, transport=_transport({ORIGIN: streamed}, []))


@pytest.mark.parametrize("status", [404, 500, 403])
def test_http_errors_fail(tmp_path: Path, status: int) -> None:
    routes = {ORIGIN: lambda _r: httpx.Response(status)}
    with pytest.raises(fw.FetchFailed, match=f"HTTP {status}"):
        fw.download(PDB, tmp_path / "p", transport=_transport(routes, []))


def test_a_redirect_without_location_fails(tmp_path: Path) -> None:
    routes = {ORIGIN: lambda _r: httpx.Response(302)}
    with pytest.raises(fw.FetchFailed, match="Location"):
        fw.download(PDB, tmp_path / "p", transport=_transport(routes, []))


def test_transport_errors_fail_cleanly(tmp_path: Path) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("certificate verify failed", request=request)

    with pytest.raises(fw.FetchFailed, match="ConnectError"):
        fw.download(PDB, tmp_path / "p", transport=httpx.MockTransport(boom))


def test_the_default_transport_verifies_tls() -> None:
    transport = fw.default_transport()
    context = transport._pool._ssl_context
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def _fake_convert(identity: dict[str, Any] | None) -> fw.Converter:
    def convert(pdb: Path, out: Path, work: Path, schemas: Path) -> dict[str, Any]:
        assert pdb.read_bytes() == b"PDB" and out.parent == work
        out.write_bytes(b"converted isf")
        digest = hashlib.sha256(b"converted isf").hexdigest()
        return {"identity": identity, "file": out.name, "sha256": digest}

    return convert


def test_fetch_windows_places_a_matching_isf_as_msdl(tmp_path: Path) -> None:
    root = new_store(tmp_path)
    routes = {ORIGIN: _body(b"PDB")}
    ident = {"os": "windows", "name": PDB.name, "guid": PDB.guid, "age": PDB.age}
    change = fw.fetch_windows(
        root,
        PDB,
        transport=_transport(routes, []),
        convert=_fake_convert(ident),
        schema_dir=schema_dir(tmp_path),
    )
    assert change.action == "added" and change.source == "msdl"
    assert read_manifest(root).files[0].source == "msdl"
    assert SymbolStore(root).lookup(PDB) is not None


@pytest.mark.parametrize(
    "identity",
    [
        {"os": "windows", "name": "ntkrnlmp.pdb", "guid": GUID, "age": 27},
        {"os": "windows", "name": "ntkrnlmp.pdb", "guid": "F" * 32, "age": 26},
        {"os": "windows", "name": "ntoskrnl.pdb", "guid": GUID, "age": 26},
        {"os": "linux", "banner": "Linux version 6.1"},
        None,
    ],
)
def test_a_converted_isf_that_does_not_match_is_refused(
    tmp_path: Path, identity: dict[str, Any] | None
) -> None:
    root = new_store(tmp_path)
    with pytest.raises(fw.FetchFailed, match="do not match"):
        fw.fetch_windows(
            root,
            PDB,
            transport=_transport({ORIGIN: _body(b"PDB")}, []),
            convert=_fake_convert(identity),
            schema_dir=schema_dir(tmp_path),
        )
    assert read_manifest(root).files == []
    assert not (root / ".staging").exists()
