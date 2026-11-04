"""Container isolation of the untrusted analyzer (run inside the pcap-worker container)."""

import os
import socket

import pytest
import redis

SECRET_HINTS = ("DATABASE", "MINIO", "JWT", "POSTGRES", "SECRET", "PASSWORD", "ACCESS_KEY")

pytestmark = pytest.mark.skipif(
    "BROKER_URL" not in os.environ, reason="runs inside the pcap-worker container"
)


def test_environment_holds_only_the_broker_url() -> None:
    leaked = [name for name in os.environ if any(h in name.upper() for h in SECRET_HINTS)]
    assert leaked == []


@pytest.mark.parametrize("host", ["postgres", "redis", "api", "web", "gateway"])
def test_app_services_are_not_reachable(host: str) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(host, 80)


def test_no_internet_egress() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()


def _broker() -> redis.Redis:
    return redis.Redis.from_url(os.environ["BROKER_URL"], socket_timeout=3)


def _denied(client: redis.Redis, *command: str) -> None:
    # NoPermissionError (ACL) or, for DEBUG, the server-level refusal: both are errors.
    with pytest.raises(redis.exceptions.ResponseError):
        client.execute_command(*command)  # type: ignore[no-untyped-call]


def test_broker_acl_blocks_inspection_and_admin_commands() -> None:
    client = _broker()
    assert client.ping()
    for command in (
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("CONFIG", "GET", "*"),
        ("FLUSHALL",),
        ("CLIENT", "LIST"),
        ("MONITOR",),
        ("DEBUG", "SLEEP", "0"),
    ):
        _denied(client, *command)


def test_broker_acl_confines_the_analyzer_to_its_keys() -> None:
    prefix = os.environ.get("QUEUE_PREFIX", "")
    client = _broker()
    ingest = f"{prefix}ingest"
    # Reports may be added to the ingest queue, never read, trimmed back or rerouted.
    for command in (
        ("LRANGE", ingest, "0", "-1"),
        ("LPOP", ingest),
        ("BRPOP", ingest, "1"),
        # (LLEN stays possible: Redis treats it as metadata, it reveals no report content.)
        ("SADD", f"_kombu.binding.{ingest}", "x"),
        ("DEL", f"_kombu.binding.{ingest}"),
        ("HGET", f"{prefix}trusted.unacked", "x"),
        ("HRANDFIELD", f"{prefix}trusted.unacked", "1"),
        ("ZRANGE", f"{prefix}trusted.unacked_index", "0", "-1"),
        ("SET", "arbitrary-key", "x"),
        ("GET", "rl:anything"),
    ):
        _denied(client, *command)
    # What it legitimately needs still works.
    assert client.smembers(f"_kombu.binding.{ingest}") is not None
    assert client.llen(f"{prefix}{os.environ.get('WORKER_QUEUE', 'pcap')}") >= 0
