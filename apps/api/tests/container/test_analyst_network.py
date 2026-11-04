"""The AI analyst worker reaches only Postgres, the broker and `egress` (M5, the M4 enrich
isolation cloned).

Runs INSIDE the analyst worker's container (the `enrich` + `egress` networks), without the
suite's conftest (no app Redis, no MinIO there):

    docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 \\
        analyst-worker-test python -m pytest --noconftest -q -p no:cacheprovider \\
        tests/container/test_analyst_network.py

Skipped anywhere else (api-test collects it too). Phase 11 adds the egress checks.
"""

import os
import socket
from pathlib import Path

import pytest

ROUTES = Path("/proc/net/route")
# Process secrets the analyst worker must never hold: settings refuse them too.
FORBIDDEN_ENV = (
    "JWT_SECRET",
    "REDIS_URL",
    "TEST_REDIS_URL",
    "COOKIE_SECURE",
    "TI_SEAL_PRIVATE_KEYS_FILE",
    "TI_SEAL_PUBLIC_KEYS",
    "AI_PLATFORM_KEY_FILE",
)
FORBIDDEN_PREFIXES = (
    "MINIO_",
    "TEST_MINIO_",
    "POSTGRES_",
    "BROKER_API",
    "BROKER_INGEST",
    "BROKER_ENRICH",
    "TI_",
)

pytestmark = pytest.mark.skipif(
    os.environ.get("PROCESS_ROLE") != "analyst", reason="analyst worker container only"
)


def _reachable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError:
        return False
    return True


@pytest.mark.parametrize(
    ("host", "port"),
    [("redis", 6379), ("minio", 9000), ("api", 8000), ("gateway", 8080), ("web", 3000)],
)
def test_backend_services_are_out_of_reach(host: str, port: int) -> None:
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        return  # not even resolvable: not on any shared network
    assert not _reachable(host, port), f"{host}:{port} is reachable from the analyst worker"


@pytest.mark.parametrize("host", ["api", "redis", "minio"])
def test_backend_names_do_not_resolve(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


@pytest.mark.parametrize(
    "host",
    [
        "pcap-worker",
        "pcap-worker-test",
        "static-worker",
        "static-worker-test",
        "enrich-worker",
        "enrich-worker-test",
    ],
)
def test_not_on_the_analysis_network_and_no_enrich_worker(host: str) -> None:
    """The analyzers parse hostile files; the other internet-facing worker holds TI keys.
    Neither is resolvable (the enrich worker shares `enrich`/`egress` but exposes no port:
    resolvable at most, never reachable)."""
    try:
        socket.getaddrinfo(host, 80)
    except socket.gaierror:
        return
    assert host.startswith("enrich"), f"{host} resolves from the analyst worker"


@pytest.mark.parametrize(("host", "port"), [("postgres", 5432), ("redis-broker", 6379)])
def test_its_data_services_are_reachable(host: str, port: int) -> None:
    assert _reachable(host, port)


def test_the_mock_sink_is_reachable_through_egress() -> None:
    assert _reachable("ai-mock", 8080)


@pytest.mark.skipif(not ROUTES.exists(), reason="Linux container only")
def test_it_has_a_default_route() -> None:
    lines = ROUTES.read_text().splitlines()[1:]
    assert any(line.split()[1] == "00000000" and line.split()[7] == "00000000" for line in lines)


def test_its_environment_holds_no_api_secrets_or_ti_keys() -> None:
    names = set(os.environ)
    leaked = sorted(n for n in names if n in FORBIDDEN_ENV or n.startswith(FORBIDDEN_PREFIXES))
    assert leaked == []
    assert os.environ["BROKER_URL"].startswith("redis://analyst:")
    assert os.environ["AI_SEAL_PRIVATE_KEYS_FILE"] == "/run/secrets/ai_seal_private"
    assert Path("/run/secrets/ai_seal_private").is_file()
    assert not Path("/run/secrets/ti_seal_private").exists()
