"""`--inject` twins through the real engines: the planted payloads survive into the analyzer's
records (Zeek) and TShark's dissection, so the AI evaluation actually sees them.

Heavy (Zeek, Suricata, TShark): worker image only, like the rest of `tests/integration`. The
light checks of the generator itself live in `tests/unit/test_inject.py`.
"""

import os
import re
import shutil
import subprocess
import unicodedata
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

import pytest
from cyberlab_worker import sandbox

from dataset import inject
from dataset.generate import TWIN_SUFFIX, generate
from pcap_worker import analyzer
from tests.integration.test_engines import LIMITS, TEST_RULES, parse

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="runs inside the pcap-worker image")


@pytest.fixture(scope="module")
def twin() -> Path:
    out = Path("/tmp/dataset-inject")  # root-only scratch, as in test_engines
    shutil.rmtree(out, ignore_errors=True)
    paths = generate(out, inject=True)
    return paths["suspicious_http" + TWIN_SUFFIX]


@pytest.fixture
def analyzed(dirs: sandbox.JobDirs, twin: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("SURICATA_RULES", TEST_RULES)
    dirs.capture.chmod(0o644)
    shutil.copyfile(twin, dirs.capture)
    dirs.capture.chmod(0o444)
    result = analyzer.analyze_file(dirs, uuid.uuid4(), LIMITS, analyzer.Budget(LIMITS))
    return parse(result)


# A byte escape as the engines write it: Zeek `\xNN`, OpenSSL's RFC 2253 subject `\NN`.
_BYTE_ESCAPE = re.compile(rb"\\x?([0-9A-Fa-f]{2})")


def _canonical(text: str) -> str:
    """The instruction text a reader of the field gets, whatever the engine did to the bytes.

    The point is that the payload's words reach what the AI context builder reads, not byte
    identity: the engines escape non-ASCII bytes (Zeek, OpenSSL), lowercase DNS names and
    percent-decode URIs (Zeek), and replace bytes they will not render with U+FFFD (TShark).
    So, on both sides: undo the byte and percent escapes (the planted URI is percent-encoded,
    the DNS label dots sit where `inject.qname` put them on both sides), read Unicode tag
    characters as the ASCII they encode (P4's hidden text, so not just its visible "ok"),
    drop the remaining format characters (P5's bidi controls) and U+FFFD, and case-fold.
    """
    raw = unquote_to_bytes(_BYTE_ESCAPE.sub(lambda m: bytes([int(m[1], 16)]), text.encode()))
    out = []
    for ch in raw.decode(errors="replace"):
        if 0xE0020 <= ord(ch) <= 0xE007E:
            out.append(chr(ord(ch) - 0xE0000))
        elif ch != "�" and unicodedata.category(ch) != "Cf":
            out.append(ch)
    return "".join(out).casefold()


def _survives(values: list[str], planted: str) -> bool:
    wanted = _canonical(planted)
    assert len(wanted) >= 16, (planted, wanted)  # the instruction text itself, never just "ok"
    return any(wanted in _canonical(v) for v in values)


def _plants() -> Iterator[tuple[str, str, str]]:
    for carrier, pairs in inject.planted_values().items():
        for pid, value in pairs:
            yield carrier, pid, value


def test_payloads_survive_into_the_zeek_records(analyzed: dict[str, Any]) -> None:
    dns, http, tls = analyzed.get("dns", []), analyzed.get("http", []), analyzed.get("tls", [])
    fields: dict[str, list[str]] = {
        "dns.query": [r.query for r in dns if r.query],
        "dns.txt": [a for r in dns for a in r.answers],
        "http.user_agent": [r.user_agent for r in http if r.user_agent],
        "http.uri": [r.uri for r in http if r.uri],
        "http.host": [r.host for r in http if r.host],
        "tls.server_name": [r.server_name for r in tls if r.server_name],
        "tls.cert_subject_cn": [r.cert_subject for r in tls if r.cert_subject],
    }
    missing = [
        (pid, carrier) for carrier, pid, value in _plants() if not _survives(fields[carrier], value)
    ]
    assert missing == [], {carrier: [ascii(v) for v in fields[carrier]] for _, carrier in missing}


def test_payloads_survive_into_tshark_fields(twin: Path) -> None:
    columns = {
        "dns.query": "dns.qry.name",
        "dns.txt": "dns.txt",
        "http.user_agent": "http.user_agent",
        "http.uri": "http.request.uri",
        "http.host": "http.host",
        "tls.server_name": "tls.handshake.extensions_server_name",
        "tls.cert_subject_cn": "x509sat.uTF8String",
    }
    argv = ["tshark", "-r", str(twin), "-n", "-T", "fields", "-E", "separator=/t"]
    for column in columns.values():
        argv += ["-e", column]
    lines = subprocess.run(argv, check=True, capture_output=True, text=True).stdout.splitlines()
    rows = [line.split("\t") for line in lines]
    for carrier, pid, value in _plants():
        index = list(columns).index(carrier)
        values = [row[index] for row in rows if len(row) > index and row[index]]
        assert _survives(values, value), (pid, carrier, [ascii(v) for v in values])
