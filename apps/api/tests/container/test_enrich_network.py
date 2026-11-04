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

import pytest

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


@pytest.mark.parametrize(("host", "port"), [("postgres", 5432), ("redis-broker", 6379)])
def test_its_data_services_are_reachable(host: str, port: int) -> None:
    assert _reachable(host, port)


def test_the_mock_sink_is_reachable_through_egress() -> None:
    assert _reachable("ti-mock", 8080)
