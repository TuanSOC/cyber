"""No internet from the `backend` network (internal since M4): api-test, and the ingest worker
which shares its network, have no route out and cannot see the provider sink.

Runs in api-test with the suite, and on its own (no conftest: no app settings needed) inside
the ingest worker, from `scripts/verify.mjs`:

    docker compose exec -T -e PYTHONDONTWRITEBYTECODE=1 ingest-worker python -m pytest \\
        --noconftest -q -p no:cacheprovider tests/container/test_egress.py

The enrich and analyst workers are the processes WITH egress: `test_enrich_network.py` and
`test_analyst_network.py` cover them.
"""

import os
import socket
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest

ROUTES = Path("/proc/net/route")
PUBLIC_NAME = "example.org"

pytestmark = pytest.mark.skipif(
    os.environ.get("PROCESS_ROLE") in ("enrich", "analyst"), reason="this worker has egress"
)


def _default_routes() -> list[str]:
    lines = ROUTES.read_text().splitlines()[1:]
    # Destination 00000000 with mask 00000000 is the default route.
    return [
        line for line in lines if line.split()[1] == "00000000" and line.split()[7] == "00000000"
    ]


def _connects(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError:
        return False
    return True


@pytest.mark.skipif(not ROUTES.exists(), reason="Linux container only")
def test_no_default_route() -> None:
    assert _default_routes() == []


def test_no_internet_connection() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()


@pytest.mark.parametrize("host", ["postgres", "redis", "redis-broker", "minio"])
def test_backend_services_still_resolve(host: str) -> None:
    assert socket.getaddrinfo(host, 80)


@pytest.mark.parametrize(
    "host",
    [
        "ti-mock",
        "enrich-worker",
        "enrich-worker-test",
        "ai-mock",
        "analyst-worker",
        "analyst-worker-test",
    ],
)
def test_the_provider_sinks_and_the_internet_facing_workers_are_out_of_reach(host: str) -> None:
    """`ti-mock` / `ai-mock` sit on `egress` only and the enrich / analyst workers on
    `enrich` + `egress`: nothing on `backend` resolves or reaches them (M4, M5)."""
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 8080)
    assert not _connects(host, 8080)


def test_public_names_do_not_resolve(record_property: Callable[[str, object], None]) -> None:
    """Docker's embedded DNS answers internal networks from the engine's resolver, so a
    public name MAY resolve even without a route (a DNS channel: THREAT_MODEL residual,
    RT22). The test records that instead of failing on it; a connection never succeeds."""
    try:
        infos = socket.getaddrinfo(PUBLIC_NAME, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        record_property("dns_channel", "closed")
        return
    addresses = sorted({str(info[4][0]) for info in infos})
    record_property("dns_channel", f"open: {PUBLIC_NAME} -> {addresses}")
    warnings.warn(
        f"RT22 residual: {PUBLIC_NAME} resolves from an internal network ({addresses})",
        stacklevel=1,
    )
    for address in addresses:
        assert not _connects(address, 443), address
