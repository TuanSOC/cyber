"""Broker ACL of the reverse-engineering analyzer (M10 phase 1): the `reverse` user is
analyzer-class, confined to its `reverse*` queue, unacked and binding keys and write-only to
ingest (it can add reports, never read, trim or reroute them); no other worker (the memory and
disk analyzers included) can touch `reverse*`; the api publishes `reverse.analyze` there."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def reverse() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_REVERSE_URL")
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
        ("LPUSH", f"{PREFIX}memory", "x"),
        ("LPUSH", f"{PREFIX}disk", "x"),
        ("HGET", f"{PREFIX}trusted.unacked", "x"),
        ("ZRANGE", f"{PREFIX}trusted.unacked_index", "0", "-1"),
        ("SET", "rl:anything", "x"),
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("FLUSHDB",),
        ("CONFIG", "GET", "*"),
        ("CLIENT", "LIST"),
        ("LRANGE", f"{PREFIX}reverse", "0", "-1"),
        ("HGETALL", f"{PREFIX}reverse.unacked"),
    ],
)
def test_reverse_user_is_confined(reverse: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(reverse, *command)


def test_reverse_user_has_what_it_needs(reverse: redis.Redis) -> None:
    queue = f"{PREFIX}reverse"
    probe = f"{PREFIX}reverse.acl-probe"
    try:
        assert reverse.ping()
        reverse.sadd(f"_kombu.binding.{queue}", "probe")
        assert reverse.smembers(f"_kombu.binding.{queue}")
        reverse.lpush(probe, "x")
        assert reverse.rpop(probe) == b"x"
        reverse.hset(f"{queue}.unacked", "probe", "x")
        reverse.hdel(f"{queue}.unacked", "probe")
        # Reports may be added to the ingest queue (write-only).
        assert reverse.smembers(f"_kombu.binding.{PREFIX}ingest") is not None
    finally:
        reverse.srem(f"_kombu.binding.{queue}", "probe")
        reverse.delete(probe)


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
        "TEST_BROKER_DISK_URL",
    ],
)
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}reverse", "x"),
        ("LLEN", f"{PREFIX}reverse"),
        ("BRPOP", f"{PREFIX}reverse", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}reverse"),
        ("HGET", f"{PREFIX}reverse.unacked", "x"),
        ("LPUSH", "reverse", "x"),
    ],
)
def test_other_workers_cannot_touch_reverse(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


def test_the_api_user_can_publish_to_reverse() -> None:
    client = _client("TEST_BROKER_API_URL")
    probe = f"{PREFIX}reverse.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}reverse", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}reverse", "probe")
        client.close()
