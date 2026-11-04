"""Suricata: signature alerts and TLS fingerprints (JA3/JA3S) from eve.json."""

import os
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberlab_jobs.results import AlertRecord

from pcap_worker import sandbox
from pcap_worker.engines.common import clip, ip, iso, port

DEFAULT_RULES = "/var/lib/suricata/rules/suricata.rules"
OVERRIDES = Path(__file__).with_name("suricata-cyberlab.yaml")
MD5 = re.compile(r"^[0-9a-f]{32}$")

FlowLink = Callable[[str | None, datetime], str | None]


def rules_file() -> str:
    """ET Open snapshot baked into the image; tests may point at a small local rule file."""
    return os.environ.get("SURICATA_RULES", DEFAULT_RULES)


def run(capture: Path, dirs: sandbox.JobDirs, timeout_s: float, rules: str | None = None) -> None:
    sandbox.run_tool(
        [
            "suricata",
            "-r", str(capture),
            "-l", str(dirs.out),
            "-k", "none",
            "--runmode", "single",
            "-S", rules or rules_file(),
            "--include", str(OVERRIDES),
            "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
        ],
        dirs,
        timeout_s=timeout_s,
    )  # fmt: skip


def _md5(value: object) -> str | None:
    text = clip(value, 64)
    return text if text and MD5.match(text) else None


def alert(item: dict[str, Any], link: FlowLink) -> AlertRecord | None:
    """One eve `alert` event; None if it is not usable. May raise on hostile values."""
    body = item.get("alert")
    ts = iso(item.get("timestamp"))
    if not isinstance(body, dict) or ts is None:
        return None
    sid, severity, rev = body.get("signature_id"), body.get("severity"), body.get("rev")
    if not isinstance(sid, int) or not 0 <= sid < 2**63:
        return None
    community = clip(item.get("community_id"), 64)
    return AlertRecord(
        ts=ts,
        src_ip=ip(item.get("src_ip")),
        src_port=port(item.get("src_port")),
        dst_ip=ip(item.get("dest_ip")),
        dst_port=port(item.get("dest_port")),
        flow_ref=link(community, ts),
        proto=clip(item.get("proto"), 16),
        signature_id=sid,
        rev=rev if isinstance(rev, int) and 0 <= rev < 2**31 else 0,
        signature=clip(body.get("signature"), 512) or f"sid {sid}",
        category=clip(body.get("category"), 255),
        severity=severity if isinstance(severity, int) and 1 <= severity <= 4 else 3,
        community_id=community,
    )


def tls_fingerprints(
    item: dict[str, Any],
) -> tuple[str, datetime, tuple[str | None, str | None]] | None:
    """(community id, ts, (ja3, ja3s)) from one eve `tls` event."""
    tls = item.get("tls")
    community = clip(item.get("community_id"), 64)
    ts = iso(item.get("timestamp"))
    if not isinstance(tls, dict) or not community or ts is None:
        return None
    ja3, ja3s = tls.get("ja3"), tls.get("ja3s")
    return (
        community,
        ts,
        (
            _md5(ja3.get("hash")) if isinstance(ja3, dict) else None,
            _md5(ja3s.get("hash")) if isinstance(ja3s, dict) else None,
        ),
    )
