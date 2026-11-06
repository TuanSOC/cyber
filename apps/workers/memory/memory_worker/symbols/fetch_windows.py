"""`memory-symbols fetch-windows --pdb --guid --age`: one Windows kernel PDB from Microsoft's
public symbol server, converted to ISF (M8 phase 5).

Operator-only. **Never run by a test, a gate or the worker** (parent decision): the tests use a
local HTTPS mock with a test-only CA and test-only `.test` host names; nothing in this repo
ever contacts `msdl.microsoft.com`. Volatility's own downloader is never used (plain HTTP,
verification off on an SSL error; research §3).

Network rules (RT11):
- the URL is built from the validated `WindowsPdb` fields only (kernel PDB allow-list, 32 hex
  GUID, age 0..65535): `https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><AGE:X>/<pdb>`
  (symstore convention: the age in hex, no padding);
- TLS verification on (the system CA store, TLS >= 1.2), no proxy or netrc from the env;
- redirects followed manually, at most `MAX_HOPS` = 3; every hop HTTPS on port 443, no
  userinfo, never an IP literal, to a host equal to `msdl.microsoft.com` or ending with one
  of `SYMBOL_REDIRECT_SUFFIXES`; a refused hop names the host so the operator can report it;
- at most 128 MiB, streamed to a file in the store's staging dir, `Accept-Encoding: identity`.

`SYMBOL_REDIRECT_SUFFIXES` was **not observed** (no live fetch exists, by decision). It is the
recorded list of the hosts Microsoft documents for its symbol / artifact CDN (see the phase-5
notes); it is changed deliberately when Microsoft changes its CDN.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import ssl
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from cyberlab_jobs.memory import WindowsPdb
from pydantic import ValidationError

from memory_worker.symbols import isolate
from memory_worker.symbols.import_isf import to_identity, volatility_schema_dir
from memory_worker.symbols.manifest import Change, Logger, StoreError, StoreWriter, no_log

MSDL_HOST = "msdl.microsoft.com"
MSDL_PATH = "/download/symbols"
# Microsoft's symbol server answers with a redirect to Azure blob storage of its artifact
# service. Sources (recorded, not observed): Microsoft Learn "Allowed IP addresses and domain
# URLs" for Azure DevOps (Artifacts / symbol server: `*.blob.core.windows.net`,
# `*.vsblob.vsassets.io`, `*.vsblob.visualstudio.com`). Every entry starts with "." and
# matches whole labels only.
SYMBOL_REDIRECT_SUFFIXES: tuple[str, ...] = (
    ".blob.core.windows.net",
    ".vsblob.vsassets.io",
    ".vsblob.visualstudio.com",
)
MAX_HOPS = 3
MAX_PDB_BYTES = 128 * 1024**2
CONVERT_TIMEOUT_S = 1800.0
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "cyberlab-memory-symbols/0.1.0"
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
_URL_CHARS = frozenset(chr(c) for c in range(0x21, 0x7F)) - frozenset('\\"<>^`{|}')

if not all(s.startswith(".") and _HOST_RE.fullmatch(s[1:]) for s in SYMBOL_REDIRECT_SUFFIXES):
    raise RuntimeError('every SYMBOL_REDIRECT_SUFFIXES entry is ".<host name>"')


class FetchRefused(RuntimeError):
    """A hop or a response broke the network rules (the message names the host)."""

    def __init__(self, message: str, host: str | None = None) -> None:
        super().__init__(message)
        self.host = host


class FetchFailed(RuntimeError):
    """The server did not deliver the PDB (HTTP error, TLS failure, timeout)."""


@dataclass(frozen=True)
class FetchPolicy:
    origin_host: str = MSDL_HOST
    base_path: str = MSDL_PATH
    suffixes: tuple[str, ...] = SYMBOL_REDIRECT_SUFFIXES
    max_hops: int = MAX_HOPS
    max_bytes: int = MAX_PDB_BYTES
    timeout_s: float = 60.0


DEFAULT_POLICY = FetchPolicy()


@dataclass
class Download:
    path: Path
    size: int
    sha256: str
    urls: list[str] = field(default_factory=list)


def symbol_url(pdb: WindowsPdb, policy: FetchPolicy = DEFAULT_POLICY) -> str:
    """Built from validated parts only (the model re-validates whatever it is given)."""
    pdb = WindowsPdb.model_validate(pdb.model_dump())
    return (
        f"https://{policy.origin_host}{policy.base_path}/"
        f"{pdb.name}/{pdb.guid}{pdb.age:X}/{pdb.name}"
    )


def redact(url: str) -> str:
    """A URL for the log: scheme, host and path (CDN query strings carry signatures)."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}{parts.path}"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def check_url(url: str, policy: FetchPolicy = DEFAULT_POLICY) -> str:
    """Validate one hop; returns its host. Raises `FetchRefused`."""
    if not url or len(url) > 4096 or any(ch not in _URL_CHARS for ch in url):
        raise FetchRefused("a URL with spaces, control or non-ASCII characters")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise FetchRefused(f"a non-HTTPS URL ({isolate.safe_text(parts.scheme, 16)})")
    if "@" in parts.netloc:
        raise FetchRefused("a URL with userinfo")
    try:
        port = parts.port
    except ValueError as exc:
        raise FetchRefused("a URL with an invalid port") from exc
    host = (parts.hostname or "").lower()
    if port not in (None, 443):
        raise FetchRefused(f"port {port} (only 443)", host)
    if not host or "[" in parts.netloc or _is_ip_literal(host):
        raise FetchRefused(f"an IP-literal or empty host {isolate.safe_text(host, 64)}", host)
    if not _HOST_RE.fullmatch(host) or host.rsplit(".", 1)[-1].isdigit():
        raise FetchRefused(f"an invalid host name {isolate.safe_text(host, 64)}", host)
    if host != policy.origin_host and not any(
        host.endswith(suffix) and len(host) > len(suffix) for suffix in policy.suffixes
    ):
        raise FetchRefused(
            f"redirect to host {host}, which is not {policy.origin_host} and matches no "
            "SYMBOL_REDIRECT_SUFFIXES entry; report it if Microsoft changed its CDN",
            host,
        )
    return host


def default_transport() -> httpx.HTTPTransport:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return httpx.HTTPTransport(verify=context, retries=0)


def download(
    pdb: WindowsPdb,
    dest: Path,
    *,
    policy: FetchPolicy = DEFAULT_POLICY,
    transport: httpx.BaseTransport | None = None,
    log: Logger = no_log,
) -> Download:
    """GET the PDB into `dest` following the rules above."""
    url = symbol_url(pdb, policy)
    result = Download(path=dest, size=0, sha256="")
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    with httpx.Client(
        transport=transport or default_transport(),
        follow_redirects=False,
        trust_env=False,
        timeout=policy.timeout_s,
        headers=headers,
    ) as client:
        for hop in range(policy.max_hops + 1):
            check_url(url, policy)
            log("fetch", url=redact(url), hop=hop)
            result.urls.append(redact(url))
            try:
                with client.stream("GET", url) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchFailed(f"HTTP {response.status_code} without Location")
                        if hop == policy.max_hops:
                            raise FetchRefused(f"more than {policy.max_hops} redirects")
                        url = urljoin(url, location)
                        continue
                    if response.status_code != 200:
                        raise FetchFailed(
                            f"HTTP {response.status_code} from {urlsplit(url).hostname}"
                        )
                    _save(response, dest, policy.max_bytes, result)
                    return result
            except httpx.HTTPError as exc:
                raise FetchFailed(f"{type(exc).__name__} talking to {redact(url)}") from exc
    raise FetchRefused(f"more than {policy.max_hops} redirects")  # pragma: no cover


def _save(response: httpx.Response, dest: Path, cap: int, result: Download) -> None:
    declared = response.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise FetchFailed("an invalid Content-Length")
        if int(declared) > cap:
            raise FetchRefused(f"the PDB is larger than {cap // 1024**2} MiB")
    digest = hashlib.sha256()
    size = 0
    with dest.open("xb") as fh:
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > cap:
                raise FetchRefused(f"the PDB is larger than {cap // 1024**2} MiB")
            digest.update(chunk)
            fh.write(chunk)
    if size == 0:
        raise FetchFailed("an empty response body")
    result.size, result.sha256 = size, digest.hexdigest()


# (downloaded pdb, produced .json.xz, work dir, schema dir) -> child result
Converter = Callable[[Path, Path, Path, Path], dict[str, Any]]


def pdbconv_converter(pdb: Path, out: Path, work: Path, schema_dir: Path) -> dict[str, Any]:
    return isolate.run_child(
        "pdbconv",
        {"pdb": str(pdb), "out": str(out), "schema_dir": str(schema_dir)},
        work,
        timeout_s=CONVERT_TIMEOUT_S,
    )


def fetch_windows(
    root: Path,
    pdb: WindowsPdb,
    *,
    policy: FetchPolicy = DEFAULT_POLICY,
    transport: httpx.BaseTransport | None = None,
    convert: Converter = pdbconv_converter,
    schema_dir: Path | None = None,
    replace: bool = False,
    log: Logger = no_log,
) -> Change:
    """Download, convert in a child, check GUID / age / name against the request, place."""
    schemas = schema_dir or volatility_schema_dir()
    # The download and the child's conversion happen in a temp dir outside the store (review
    # fix); `adopt` copies the produced ISF into the staging dir, `stage` re-hashes it.
    with (
        StoreWriter(root, log=log) as writer,
        tempfile.TemporaryDirectory(prefix="memory-symbols-") as tmp,
    ):
        work = Path(tmp)
        got = download(pdb, work / "download.pdb", policy=policy, transport=transport, log=log)
        log("downloaded", bytes=got.size, sha256=got.sha256, hops=len(got.urls) - 1)
        produced = work / "isf.json.xz"
        try:
            out = convert(got.path, produced, work, schemas)
        except isolate.ChildFailed as exc:
            raise FetchFailed(f"conversion failed: {exc}") from exc
        try:
            identity = to_identity(out.get("identity"))
        except (ValidationError, KeyError, TypeError) as exc:
            raise FetchFailed("the converted ISF carries an invalid PDB identity") from exc
        if identity != pdb:
            raise FetchFailed(
                "the converted ISF's PDB name / GUID / age do not match the request: refusing"
            )
        try:
            staged = writer.adopt(produced, work, "fetch")
            change = writer.stage(staged, pdb, out["sha256"], "msdl", replace=replace)
        except StoreError as exc:
            hint = "" if replace else " (re-run with --replace to replace it)"
            raise FetchFailed(f"{exc}{hint}") from exc
        writer.commit()
    return change
