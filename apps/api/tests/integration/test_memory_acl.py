"""Broker ACL of the memory analyzer (M8 phase 1): the `memory` user is analyzer-class, confined
to its `memory*` queue, unacked and binding keys and write-only to ingest (it can add reports,
never read, trim or reroute them); no other worker can touch `memory*`; the api publishes
`memory.analyze` there."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def memory() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_MEMORY_URL")
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
        ("LRANGE", f"{PREFIX}memory", "0", "-1"),
        ("HGETALL", f"{PREFIX}memory.unacked"),
    ],
)
def test_memory_user_is_confined(memory: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(memory, *command)


def test_memory_user_has_what_it_needs(memory: redis.Redis) -> None:
    queue = f"{PREFIX}memory"
    probe = f"{PREFIX}memory.acl-probe"
    try:
        assert memory.ping()
        memory.sadd(f"_kombu.binding.{queue}", "probe")
        assert memory.smembers(f"_kombu.binding.{queue}")
        memory.lpush(probe, "x")
        assert memory.rpop(probe) == b"x"
        memory.hset(f"{queue}.unacked", "probe", "x")
        memory.hdel(f"{queue}.unacked", "probe")
        # Reports may be added to the ingest queue (write-only).
        assert memory.smembers(f"_kombu.binding.{PREFIX}ingest") is not None
    finally:
        memory.srem(f"_kombu.binding.{queue}", "probe")
        memory.delete(probe)


@pytest.mark.parametrize(
    "env",
    [
        "TEST_BROKER_PCAP_URL",
        "TEST_BROKER_STATIC_URL",
        "TEST_BROKER_ENRICH_URL",
        "TEST_BROKER_ANALYST_URL",
        "TEST_BROKER_REPORT_URL",
        "TEST_BROKER_RETENTION_URL",
    ],
)
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}memory", "x"),
        ("LLEN", f"{PREFIX}memory"),
        ("BRPOP", f"{PREFIX}memory", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}memory"),
        ("HGET", f"{PREFIX}memory.unacked", "x"),
        ("LPUSH", "memory", "x"),
    ],
)
def test_other_workers_cannot_touch_memory(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


def test_the_api_user_can_publish_to_memory() -> None:
    client = _client("TEST_BROKER_API_URL")
    probe = f"{PREFIX}memory.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}memory", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}memory", "probe")
        client.close()
