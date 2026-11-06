"""`fetch-windows` over real TLS against a local HTTPS mock (M8 phase 5, RT11).

Never the internet (parent decision): the mock listens on 127.0.0.1 with a certificate from a
throw-away CA made for this test and trusted only by this test's client; the policy uses
reserved `.test` names (RFC 6761, never resolvable publicly) and a loopback network backend
connects every `.test` name to the mock, so even a bug here cannot reach a real host.

Covers: verified TLS through a redirect chain to an allow-listed suffix, an untrusted
certificate, a certificate for the wrong name, a redirect to a non-allow-listed host (named
in the refusal), HTTP, an oversize body, and the whole `fetch_windows` path with the real
isolated ISF child (schema validation, identity check, atomic placement as `source: msdl`).
"""

from __future__ import annotations

import hashlib
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpcore
import httpx
import pytest
from cyberlab_jobs.memory import WindowsPdb

from memory_worker.symbols import fetch_windows as fw
from memory_worker.symbols import isolate
from memory_worker.symbols.manifest import read_manifest
from memory_worker.symbols.store import SymbolStore
from tests.symbols_helpers import GUID, dumps, new_store, schema_dir, windows_isf

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")

PDB = WindowsPdb(name="ntkrnlmp.pdb", guid=GUID, age=1)
POLICY = fw.FetchPolicy(origin_host="msdl.test", suffixes=(".cdn.test",), max_bytes=1 << 20)
ORIGIN_PATH = f"/download/symbols/ntkrnlmp.pdb/{GUID}1/ntkrnlmp.pdb"
NAMES = ("msdl.test", "a.cdn.test", "b.cdn.test", "evil.test")
ISF = dumps(windows_isf())  # what the mock serves as the "PDB"; the fake converter reads it


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True, timeout=60)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("pki")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out",
             "ca.pem", "-days", "2", "-subj", "/CN=cyberlab test CA", "-config", _cnf(d),
             "-extensions", "v3", cwd=d)
    sans = ",".join(f"DNS:{n}" for n in NAMES)
    leaf_ext = d / "leaf.ext"
    leaf_ext.write_text(
        f"subjectAltName={sans}\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    )
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
             "-subj", "/CN=msdl.test", "-config", _cnf(d), cwd=d)
    _openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
             "-CAcreateserial", "-out", "leaf.pem", "-days", "2", "-extfile", "leaf.ext", cwd=d)
    # A second, unrelated CA's leaf: valid names, untrusted issuer.
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue.key", "-out",
             "rogue.pem", "-days", "2", "-subj", "/CN=msdl.test", "-config", _cnf(d),
             "-addext", f"subjectAltName={sans}", cwd=d)
    return {"ca": d / "ca.pem", "cert": d / "leaf.pem", "key": d / "leaf.key",
            "rogue_cert": d / "rogue.pem", "rogue_key": d / "rogue.key"}


def _cnf(d: Path) -> str:
    cnf = d / "openssl.cnf"
    if not cnf.exists():
        cnf.write_text(
            "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=x\n[v3]\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\n"
        )
    return str(cnf)


Routes = dict[tuple[str, str], tuple[int, dict[str, str], bytes]]


class _Handler(BaseHTTPRequestHandler):
    routes: Routes = {}
    seen: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        host = (self.headers.get("Host") or "").split(":")[0]
        self.seen.append(f"{host}{self.path}")
        status, headers, body = self.routes.get((host, self.path), (404, {}, b""))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: Any) -> None:
        return None


@pytest.fixture
def mock(pki: dict[str, Path]) -> Iterator[dict[str, Any]]:
    yield from _serve(pki["cert"], pki["key"])


@pytest.fixture
def rogue_mock(pki: dict[str, Path]) -> Iterator[dict[str, Any]]:
    yield from _serve(pki["rogue_cert"], pki["rogue_key"])


def _serve(cert: Path, key: Path) -> Iterator[dict[str, Any]]:
    routes: Routes = {}
    seen: list[str] = []
    handler = type("H", (_Handler,), {"routes": routes, "seen": seen})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"port": server.server_address[1], "routes": routes, "seen": seen}
    finally:
        server.shutdown()
        server.server_close()


class _Loopback(httpcore.SyncBackend):
    """Connects every `.test` name to the local mock; anything else is a test bug."""

    def __init__(self, port: int) -> None:
        self.port = port

    def connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any) -> Any:
        assert host.endswith(".test") and port == 443, f"refusing to connect to {host}:{port}"
        return super().connect_tcp("127.0.0.1", self.port, *args, **kwargs)


def _transport(port: int, ca: Path | None) -> httpx.HTTPTransport:
    """The production TLS settings (`default_transport`) plus the test CA, over loopback."""
    # Without `ca`: the system store only, as in production (the test CA is unknown there).
    context = ssl.create_default_context(cafile=str(ca) if ca else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    transport = httpx.HTTPTransport(verify=context, retries=0)
    transport._pool = httpcore.ConnectionPool(
        ssl_context=context, network_backend=_Loopback(port), retries=0
    )
    return transport


def _tls(mock: dict[str, Any], pki: dict[str, Path]) -> httpx.HTTPTransport:
    return _transport(mock["port"], pki["ca"])


def test_a_verified_redirect_chain_to_an_allowed_suffix(
    mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path
) -> None:
    mock["routes"].update(
        {
            ("msdl.test", ORIGIN_PATH): (302, {"Location": "https://a.cdn.test/b/1?sig=x"}, b""),
            ("a.cdn.test", "/b/1?sig=x"): (307, {"Location": "https://b.cdn.test/b/2"}, b""),
            ("b.cdn.test", "/b/2"): (200, {}, b"PDB BYTES"),
        }
    )
    got = fw.download(
        PDB, tmp_path / "p.pdb", policy=POLICY, transport=_transport(mock["port"], pki["ca"])
    )
    assert (tmp_path / "p.pdb").read_bytes() == b"PDB BYTES"
    assert got.sha256 == hashlib.sha256(b"PDB BYTES").hexdigest()
    assert mock["seen"] == [f"msdl.test{ORIGIN_PATH}", "a.cdn.test/b/1?sig=x", "b.cdn.test/b/2"]


def test_an_untrusted_certificate_fails(
    rogue_mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path
) -> None:
    rogue_mock["routes"][("msdl.test", ORIGIN_PATH)] = (200, {}, b"PDB")
    with pytest.raises(fw.FetchFailed, match="ConnectError"):
        fw.download(
            PDB, tmp_path / "p", policy=POLICY, transport=_transport(rogue_mock["port"], pki["ca"])
        )
    assert rogue_mock["seen"] == []


def test_the_system_store_does_not_trust_the_test_ca(mock: dict[str, Any], tmp_path: Path) -> None:
    mock["routes"][("msdl.test", ORIGIN_PATH)] = (200, {}, b"PDB")
    with pytest.raises(fw.FetchFailed, match="ConnectError"):
        fw.download(PDB, tmp_path / "p", policy=POLICY, transport=_transport(mock["port"], None))
    assert mock["seen"] == []


def test_a_certificate_for_another_name_fails(
    mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path
) -> None:
    policy = fw.FetchPolicy(origin_host="other.test", suffixes=(".cdn.test",))
    with pytest.raises(fw.FetchFailed, match="ConnectError"):
        fw.download(PDB, tmp_path / "p", policy=policy, transport=_tls(mock, pki))


@pytest.mark.parametrize(
    ("location", "match"),
    [
        ("https://evil.test/x", "evil.test"),
        ("http://a.cdn.test/x", "non-HTTPS"),
        ("https://127.0.0.1/x", "IP-literal"),
    ],
)
def test_a_refused_redirect_is_never_followed(
    mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path, location: str, match: str
) -> None:
    mock["routes"][("msdl.test", ORIGIN_PATH)] = (302, {"Location": location}, b"")
    mock["routes"][("evil.test", "/x")] = (200, {}, b"EVIL")
    with pytest.raises(fw.FetchRefused, match=match):
        fw.download(PDB, tmp_path / "p", policy=POLICY, transport=_tls(mock, pki))
    assert mock["seen"] == [f"msdl.test{ORIGIN_PATH}"]


def test_an_oversize_body_is_refused(
    mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path
) -> None:
    mock["routes"][("msdl.test", ORIGIN_PATH)] = (200, {}, b"x" * 2048)
    small = fw.FetchPolicy(origin_host="msdl.test", suffixes=(".cdn.test",), max_bytes=1024)
    with pytest.raises(fw.FetchRefused, match="larger than"):
        fw.download(PDB, tmp_path / "p", policy=small, transport=_tls(mock, pki))


def _isf_child_converter(pdb: Path, out: Path, work: Path, schemas: Path) -> dict[str, Any]:
    """Stands in for pdbconv (no real PDB exists here): the mock served an ISF, which the
    real isolated `isf` child validates and identifies."""
    return isolate.run_child(
        "isf", {"src": str(pdb), "out": str(out), "schema_dir": str(schemas)}, work, timeout_s=120
    )


def test_fetch_windows_end_to_end(
    mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path
) -> None:
    mock["routes"].update(
        {
            ("msdl.test", ORIGIN_PATH): (302, {"Location": "https://a.cdn.test/isf"}, b""),
            ("a.cdn.test", "/isf"): (200, {}, ISF),
        }
    )
    root = new_store(tmp_path)
    logged: list[dict[str, Any]] = []
    change = fw.fetch_windows(
        root,
        PDB,
        policy=POLICY,
        transport=_transport(mock["port"], pki["ca"]),
        convert=_isf_child_converter,
        schema_dir=schema_dir(tmp_path),
        log=lambda event, **f: logged.append({"event": event, **f}),
    )
    assert change.action == "added" and change.source == "msdl"
    hit = SymbolStore(root).lookup(PDB)
    assert hit is not None and hit.sha256 == read_manifest(root).files[0].sha256
    fetched = [e["url"] for e in logged if e["event"] == "fetch"]
    assert fetched == [f"https://msdl.test{ORIGIN_PATH}", "https://a.cdn.test/isf"]
    assert any(e["event"] == "manifest_change" for e in logged)


def test_fetch_windows_refuses_a_guid_mismatch(
    mock: dict[str, Any], pki: dict[str, Path], tmp_path: Path
) -> None:
    mock["routes"][("msdl.test", ORIGIN_PATH)] = (200, {}, dumps(windows_isf(guid="F" * 32)))
    root = new_store(tmp_path)
    with pytest.raises(fw.FetchFailed, match="do not match"):
        fw.fetch_windows(
            root,
            PDB,
            policy=POLICY,
            transport=_transport(mock["port"], pki["ca"]),
            convert=_isf_child_converter,
            schema_dir=schema_dir(tmp_path),
        )
    assert read_manifest(root).files == []
