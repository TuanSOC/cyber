"""Container isolation of the untrusted report renderer (M6 phase 1, RT21): the worker-kit
analyzer checks for the report hosts. Run inside `report-worker-test`:

  scripts/lane-test.sh <lane> --service report-worker-test pytest -q tests/test_isolation.py

The env holds only BROKER_URL (plus the image's non-secret variables); there is no default
route, no egress, no name resolution of postgres / redis / api / web / gateway or the TI and
AI hosts; it reaches only the broker and MinIO; and its broker user is confined to `report*`.
"""

import os
import socket
from pathlib import Path

import pytest
import redis

SECRET_HINTS = (
    "DATABASE",
    "MINIO",
    "JWT",
    "POSTGRES",
    "SECRET",
    "PASSWORD",
    "ACCESS_KEY",
    "SIGNING",
    "SEAL",
    "REDIS_URL",
)
ROUTES = Path("/proc/net/route")

pytestmark = pytest.mark.skipif(
    "BROKER_URL" not in os.environ, reason="runs inside the report-worker container"
)


def test_environment_holds_only_the_broker_url() -> None:
    leaked = [name for name in os.environ if any(h in name.upper() for h in SECRET_HINTS)]
    assert leaked == []
    assert os.environ["BROKER_URL"].startswith("redis://report:")


@pytest.mark.parametrize("host", ["postgres", "redis", "api", "web", "gateway", "ingest-worker"])
def test_app_services_are_not_reachable(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


@pytest.mark.parametrize(
    "host",
    ["ti-mock", "ai-mock", "enrich-worker", "analyst-worker", "analyst-worker-test"],
)
def test_ti_and_ai_hosts_are_not_reachable(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 8080)


def test_no_internet_egress() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()


@pytest.mark.skipif(not ROUTES.exists(), reason="Linux container only")
def test_no_default_route() -> None:
    lines = ROUTES.read_text().splitlines()[1:]
    default = [ln for ln in lines if ln.split()[1] == "00000000" and ln.split()[7] == "00000000"]
    assert default == []


@pytest.mark.parametrize(("host", "port"), [("redis-broker", 6379), ("minio", 9000)])
def test_only_the_broker_and_minio_are_reachable(host: str, port: int) -> None:
    socket.create_connection((host, port), timeout=3).close()


def _broker() -> redis.Redis:
    return redis.Redis.from_url(os.environ["BROKER_URL"], socket_timeout=3)


def _denied(client: redis.Redis, *command: str) -> None:
    with pytest.raises(redis.exceptions.ResponseError):
        client.execute_command(*command)  # type: ignore[no-untyped-call]


def test_broker_acl_confines_the_renderer() -> None:
    prefix = os.environ.get("QUEUE_PREFIX", "")
    client = _broker()
    ingest = f"{prefix}ingest"
    for command in (
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("CONFIG", "GET", "*"),
        ("FLUSHALL",),
        ("CLIENT", "LIST"),
        ("LRANGE", ingest, "0", "-1"),
        ("LPOP", ingest),
        ("SADD", f"_kombu.binding.{ingest}", "x"),
        ("HGET", f"{prefix}trusted.unacked", "x"),
        ("LPUSH", f"{prefix}enrich", "x"),
        ("LPUSH", f"{prefix}analyst", "x"),
        ("LPUSH", f"{prefix}pcap", "x"),
        ("SET", "arbitrary-key", "x"),
    ):
        _denied(client, *command)
    assert client.smembers(f"_kombu.binding.{ingest}") is not None
    assert client.llen(f"{prefix}{os.environ.get('WORKER_QUEUE', 'report')}") >= 0
