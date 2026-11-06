"""Broker ACL of the disk analyzer (M9 phase 1): the `disk` user is analyzer-class, confined
to its `disk*` queue, unacked and binding keys and write-only to ingest (it can add reports,
never read, trim or reroute them); no other worker can touch `disk*`; the api publishes
`disk.analyze` there."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def disk() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_DISK_URL")
    yield client
    client.close()


def _denied(client: redis.Redis, *command: str) -> None:
    with pytest.raises(redis.exceptions.ResponseError):
        client.execute_command(*command)  # type: ignore[no-untyped-call]


@pytest.mark.parametrize(
    "command",
    [
        ("LRANGE", f"{PREFIX}ingest", "0", "-1"),
        ("LPOP", f"{PREFIX}ingest"),
        ("BRPOP", f"{PREFIX}ingest", "1"),
        ("SADD", f"_kombu.binding.{PREFIX}ingest", "x"),
        ("DEL", f"_kombu.binding.{PREFIX}ingest"),
        ("LPUSH", f"{PREFIX}pcap", "x"),
        ("LPUSH", f"{PREFIX}static", "x"),
        ("LPUSH", f"{PREFIX}enrich", "x"),
        ("LPUSH", f"{PREFIX}analyst", "x"),
        ("LPUSH", f"{PREFIX}report", "x"),
        ("LPUSH", f"{PREFIX}retention", "x"),
        ("HGET", f"{PREFIX}trusted.unacked", "x"),
        ("ZRANGE", f"{PREFIX}trusted.unacked_index", "0", "-1"),
        ("SET", "rl:anything", "x"),
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("FLUSHDB",),
        ("CONFIG", "GET", "*"),
        ("CLIENT", "LIST"),
        ("LRANGE", f"{PREFIX}disk", "0", "-1"),
        ("HGETALL", f"{PREFIX}disk.unacked"),
        # The disk ingest queue is read by the trusted side only (RT9). Like every analyzer,
        # `disk` may write `ingest*` (so also `ingest_disk`): a `disk.ingest` message is
        # re-authenticated by its per-job token, exactly like `ingest.event`.
        ("BRPOP", f"{PREFIX}ingest_disk", "1"),
        ("LRANGE", f"{PREFIX}memory", "0", "-1"),
    ],
)
def test_disk_user_is_confined(disk: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(disk, *command)


def test_disk_user_has_what_it_needs(disk: redis.Redis) -> None:
    queue = f"{PREFIX}disk"
    probe = f"{PREFIX}disk.acl-probe"
    try:
        assert disk.ping()
        disk.sadd(f"_kombu.binding.{queue}", "probe")
        assert disk.smembers(f"_kombu.binding.{queue}")
        disk.lpush(probe, "x")
        assert disk.rpop(probe) == b"x"
        disk.hset(f"{queue}.unacked", "probe", "x")
        disk.hdel(f"{queue}.unacked", "probe")
        # Reports may be added to the ingest queue (write-only).
        assert disk.smembers(f"_kombu.binding.{PREFIX}ingest") is not None
    finally:
        disk.srem(f"_kombu.binding.{queue}", "probe")
        disk.delete(probe)


@pytest.mark.parametrize(
    "env",
    [
        "TEST_BROKER_PCAP_URL",
        "TEST_BROKER_STATIC_URL",
        "TEST_BROKER_ENRICH_URL",
        "TEST_BROKER_ANALYST_URL",
        "TEST_BROKER_REPORT_URL",
        "TEST_BROKER_RETENTION_URL",
        "TEST_BROKER_MEMORY_URL",
    ],
)
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}disk", "x"),
        ("LLEN", f"{PREFIX}disk"),
        ("BRPOP", f"{PREFIX}disk", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}disk"),
        ("HGET", f"{PREFIX}disk.unacked", "x"),
        ("LPUSH", "disk", "x"),
    ],
)
def test_other_workers_cannot_touch_disk(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


def test_the_api_user_can_publish_to_disk() -> None:
    client = _client("TEST_BROKER_API_URL")
    probe = f"{PREFIX}disk.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}disk", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}disk", "probe")
        client.close()


def test_the_ingest_user_owns_the_disk_ingest_queue() -> None:
    """RT9: the trusted ingest user hands disk results to `ingest_disk` and the disk ingest
    worker (same user) consumes it."""
    client = _client("TEST_BROKER_INGEST_URL")
    probe = f"{PREFIX}ingest_disk"
    try:
        client.sadd(f"_kombu.binding.{probe}", "probe")
        client.lpush(f"{probe}.acl-probe", "x")
        assert client.rpop(f"{probe}.acl-probe") == b"x"
    finally:
        client.srem(f"_kombu.binding.{probe}", "probe")
        client.delete(f"{probe}.acl-probe")
        client.close()
