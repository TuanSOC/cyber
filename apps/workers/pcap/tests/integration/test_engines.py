"""Real engines (capinfos, tshark, Zeek, Suricata) over the synthetic dataset, in-container."""

import gzip
import hashlib
import os
import shutil
import subprocess
import uuid
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import JobLimits
from cyberlab_jobs.results import LINE_ADAPTER, ResultHeader, ResultTrailer
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from dataset.generate import generate
from pcap_worker import analyzer
from pcap_worker.engines.zeek import community_id

TEST_RULES = str(Path(__file__).parents[1] / "rules" / "local-test.rules")
LIMITS = JobLimits(
    max_bytes=64 * 1024**2,
    timeout_s=600,
    tool_timeout_s=300,
    max_flows=10_000,
    max_records_per_kind=10_000,
    max_findings=1_000,
    max_result_bytes=64 * 1024**2,
)

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="runs inside the pcap-worker image")


@pytest.fixture(scope="session")
def dataset() -> dict[str, Path]:
    # Root-only scratch (/tmp is 1700): the job's input copy is what tools get to read.
    out = Path("/tmp/dataset")
    shutil.rmtree(out, ignore_errors=True)
    return generate(out)


@pytest.fixture(autouse=True)
def _local_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SURICATA_RULES", TEST_RULES)


@pytest.fixture
def run(dirs: sandbox.JobDirs) -> Iterator[Any]:
    def analyze(source: Path | bytes, limits: JobLimits = LIMITS) -> dict[str, Any]:
        dirs.capture.chmod(0o644)
        if isinstance(source, bytes):
            dirs.capture.write_bytes(source)
        else:
            shutil.copyfile(source, dirs.capture)
        dirs.capture.chmod(0o444)
        for leftover in dirs.out.iterdir():  # several analyses may share one job directory
            leftover.unlink()
        for spool in dirs.root.glob("*.spool"):
            spool.unlink()
        (dirs.root / "result.ndjson.gz").unlink(missing_ok=True)
        result = analyzer.analyze_file(dirs, uuid.uuid4(), limits, analyzer.Budget(limits))
        return parse(result)

    yield analyze


def parse(path: Path) -> dict[str, Any]:
    """Validate the stream exactly as ingest will: header first, trailer last and correct."""
    lines = gzip.decompress(path.read_bytes()).splitlines(keepends=True)
    header = ResultHeader.model_validate_json(lines[0])
    trailer = ResultTrailer.model_validate_json(lines[-1])
    assert trailer.line_count == len(lines) - 1
    assert trailer.sha256 == hashlib.sha256(b"".join(lines[:-1])).hexdigest()
    by_kind: dict[str, list[Any]] = {}
    for line in lines[1:-1]:
        record = LINE_ADAPTER.validate_json(line)
        assert record.kind not in {"header", "trailer"}
        by_kind.setdefault(record.kind, []).append(record)
    return {"header": header, **by_kind}


def test_normal_web_is_parsed_completely(run: Any, dataset: dict[str, Path]) -> None:
    out = run(dataset["normal_web"])
    assert out["header"].engine_errors == [] and out["header"].truncated == {}
    [stats] = out["stats"]
    assert stats.packets > 50 and stats.first_ts and stats.last_ts
    assert {p.path for p in stats.protocol_hierarchy} >= {"eth:ip:tcp:http", "eth:ip:tcp:tls"}
    assert len(out["http"]) == 3 and {h.uri for h in out["http"]} == {"/", "/about", "/news?id=7"}
    assert {d.query for d in out["dns"]} == {"www.example.com", "cdn.example.net"}
    tls = out["tls"]
    assert len(tls) == 2 and all(t.established and t.server_name == "cdn.example.net" for t in tls)
    issuer = "CN=CyberLab Synthetic Test CA"
    assert all(t.self_signed is False and t.cert_issuer == issuer for t in tls)
    assert all(t.ja3 and len(t.ja3) == 32 and t.ja3s and len(t.ja3s) == 32 for t in tls)
    assert all(t.validation_status for t in tls)  # untrusted test CA: Zeek says why
    flows = out["flow"]
    assert all(f.flow_ref and f.community_id for f in flows)
    assert str(stats.top_sources[0].ip) == "10.0.1.10"
    assert {str(h.ip) for h in stats.top_destinations} >= {"198.51.100.10", "198.51.100.20"}
    assert [f.orig_bytes + f.resp_bytes for f in flows] == sorted(
        (f.orig_bytes + f.resp_bytes for f in flows), reverse=True
    )


def test_our_community_id_matches_zeek(run: Any, dataset: dict[str, Path]) -> None:
    flows = [f for f in run(dataset["normal_web"])["flow"] if f.proto == "tcp"]
    assert flows
    for f in flows:
        computed = community_id(str(f.src_ip), f.src_port, str(f.dst_ip), f.dst_port, 6)
        assert computed == f.community_id


def test_tls_certificate_facts(run: Any, dataset: dict[str, Path]) -> None:
    tls = {t.server_name: t for t in run(dataset["tls_sessions"])["tls"]}
    assert tls["selfsigned.example.org"].self_signed is True
    expired = tls["expired.example.org"]
    assert expired.cert_not_after and expired.cert_not_after < expired.ts
    assert tls["legacy.example.org"].version == "TLSv10"
    assert all(t.cert_sha256 and len(t.cert_sha256) == 64 for t in tls.values())


def test_port_scan_flows_and_states(run: Any, dataset: dict[str, Path]) -> None:
    flows = run(dataset["port_scan"])["flow"]
    states = Counter(f.conn_state for f in flows if str(f.src_ip) == "10.0.4.40")
    assert sum(states.values()) == 145
    assert states["REJ"] >= 100 and states["S0"] >= 25


def test_dns_anomaly_records(run: Any, dataset: dict[str, Path]) -> None:
    dns = run(dataset["dns_anomalies"])["dns"]
    assert len(dns) == 30 and {d.qtype for d in dns} == {"TXT"}
    assert sum(d.rcode == "NXDOMAIN" for d in dns) == 20


def test_suricata_alerts_link_to_zeek_flows(run: Any, dataset: dict[str, Path]) -> None:
    out = run(dataset["suspicious_http"])
    [alert] = out["alert"]
    assert alert.signature_id == 9000001 and alert.signature.startswith("CYBERLAB TEST")
    assert alert.flow_ref in {f.flow_ref for f in out["flow"]} and alert.community_id
    [http] = out["http"]
    assert http.host == "203.0.113.70" and "application/x-dosexec" in http.resp_mime_types


def test_pcapng_is_analyzed_like_pcap(run: Any, dataset: dict[str, Path], tmp_path: Path) -> None:
    pcapng = tmp_path / "web.pcapng"
    subprocess.run(["editcap", "-F", "pcapng", str(dataset["normal_web"]), str(pcapng)], check=True)
    out = run(pcapng)
    assert out["header"].capture_format == "pcapng" and out["header"].engine_errors == []
    assert len(out["http"]) == 3 and len(out["tls"]) == 2


def test_shipped_et_open_ruleset_loads_and_fires(
    run: Any, dataset: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sanity of the image's rule snapshot (asserts only that some ET rule fires)."""
    monkeypatch.delenv("SURICATA_RULES")
    out = run(dataset["beacon"])
    assert "suricata_failed" not in out["header"].engine_errors
    assert out["header"].tool_versions["rules_sha256"]
    assert any(a.signature.startswith("ET ") for a in out.get("alert", []))


def test_caps_truncate_and_flag(run: Any, dataset: dict[str, Path]) -> None:
    limits = LIMITS.model_copy(update={"max_flows": 5, "max_records_per_kind": 1})
    out = run(dataset["mixed"], limits)
    assert len(out["flow"]) == 5 and len(out["dns"]) == 1 and len(out["tls"]) == 1
    assert len(out["alert"]) == 1
    flags = out["header"].truncated
    assert flags["flows"] and flags["dns"] and flags["tls"] and flags["alert"]
    [stats] = out["stats"]
    assert stats.counts["flows"] > 5  # statistics cover every flow read
    sizes = [f.orig_bytes + f.resp_bytes for f in out["flow"]]
    assert sizes == sorted(sizes, reverse=True)  # the largest flows are the ones kept


def test_header_only_capture_yields_an_empty_result(run: Any, dataset: dict[str, Path]) -> None:
    out = run(dataset["dns_traffic"].read_bytes()[:24])
    [stats] = out["stats"]
    assert stats.packets == 0 and "flow" not in out


def test_truncated_capture_is_still_analyzed(run: Any, dataset: dict[str, Path]) -> None:
    data = dataset["normal_web"].read_bytes()
    out = run(data[: len(data) // 2 + 7])  # cut mid-packet
    assert "capture_cut_short" in out["header"].engine_errors
    assert out["stats"][0].packets > 0 and out["flow"]


def test_garbage_after_a_valid_magic_is_unparseable(run: Any) -> None:
    with pytest.raises(JobFailed) as exc:
        run(bytes.fromhex("d4c3b2a1") + os.urandom(4000))
    assert exc.value.code == "unparseable_capture"


def test_dataset_is_deterministic(tmp_path: Path) -> None:
    first, second = generate(tmp_path / "a"), generate(tmp_path / "b")
    for name in first:
        assert first[name].read_bytes() == second[name].read_bytes(), name
