"""api-test runs on `backend` only, which is `internal` since M4: no route out (phase 1).

Phase 7 extends this file (DNS for public names, ti-mock unreachable, the enrich worker's
egress); this phase pins the network change itself.
"""

import socket
from pathlib import Path

import pytest

ROUTES = Path("/proc/net/route")


def _default_routes() -> list[str]:
    lines = ROUTES.read_text().splitlines()[1:]
    # Destination 00000000 with mask 00000000 is the default route.
    return [
        line for line in lines if line.split()[1] == "00000000" and line.split()[7] == "00000000"
    ]


@pytest.mark.skipif(not ROUTES.exists(), reason="Linux container only")
def test_no_default_route() -> None:
    assert _default_routes() == []


def test_no_internet_connection() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()


@pytest.mark.parametrize("host", ["postgres", "redis", "redis-broker", "minio"])
def test_backend_services_still_resolve(host: str) -> None:
    assert socket.getaddrinfo(host, 80)
