"""The internet-facing enrich worker reaches only Postgres, the broker and `egress` (review M2).

Runs INSIDE the enrich worker's container (the `enrich` + `egress` networks), without the
suite's conftest (no app Redis, no MinIO there):

    docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 \\
        enrich-worker-test python -m pytest --noconftest -q -p no:cacheprovider \\
        tests/container/test_enrich_network.py

Skipped anywhere else (api-test collects it too).
"""

import os
import socket
from pathlib import Path

import pytest

ROUTES = Path("/proc/net/route")
# Process secrets the enrich worker must never hold (RT2): settings refuse them too.
FORBIDDEN_ENV = ("JWT_SECRET", "REDIS_URL", "TEST_REDIS_URL", "COOKIE_SECURE")
FORBIDDEN_PREFIXES = ("MINIO_", "TEST_MINIO_", "POSTGRES_", "BROKER_API", "BROKER_INGEST")

pytestmark = pytest.mark.skipif(
    os.environ.get("PROCESS_ROLE") != "enrich", reason="enrich worker container only"
)


def _reachable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError:
        return False
    return True


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("redis", 6379),  # the app Redis: token denylist, rate limits (no password)
        ("minio", 9000),
        ("api", 8000),
        ("gateway", 8080),
        ("web", 3000),
    ],
)
def test_backend_services_are_out_of_reach(host: str, port: int) -> None:
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        return  # not even resolvable: not on any shared network
    assert not _reachable(host, port), f"{host}:{port} is reachable from the enrich worker"


@pytest.mark.parametrize(
    "host", ["pcap-worker", "pcap-worker-test", "static-worker", "static-worker-test"]
)
def test_not_on_the_analysis_network(host: str) -> None:
    """The analyzers parse hostile files: the internet-facing worker never shares a network
    with them (no pivot from a compromised parser to the internet)."""
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


@pytest.mark.parametrize(("host", "port"), [("postgres", 5432), ("redis-broker", 6379)])
def test_its_data_services_are_reachable(host: str, port: int) -> None:
    assert _reachable(host, port)


def test_the_mock_sink_is_reachable_through_egress() -> None:
    assert _reachable("ti-mock", 8080)


@pytest.mark.skipif(not ROUTES.exists(), reason="Linux container only")
def test_it_has_a_default_route() -> None:
    """Its egress (through the `egress` network) is what the other containers lack."""
    lines = ROUTES.read_text().splitlines()[1:]
    assert any(line.split()[1] == "00000000" and line.split()[7] == "00000000" for line in lines)


def test_its_environment_holds_no_api_secrets() -> None:
    names = set(os.environ)
    leaked = sorted(n for n in names if n in FORBIDDEN_ENV or n.startswith(FORBIDDEN_PREFIXES))
    assert leaked == []
    # Its broker user is `enrich` (confined to enrich* keys), never api/ingest.
    assert os.environ["BROKER_URL"].startswith("redis://enrich:")
