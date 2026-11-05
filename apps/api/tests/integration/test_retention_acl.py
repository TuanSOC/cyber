"""Broker ACL of the retention worker (M7 phase 1): the `retention` user is confined to its
`retention*` queue, unacked and binding keys (like enrich: no ingest*, trusted.*, other queues,
app keys or admin commands); the analyzers, the renderer, enrich and analyst cannot touch
`retention*`; the api and ingest users (the beat) can publish to it."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def retention() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_RETENTION_URL")
    yield client
    client.close()


def _denied(client: redis.Redis, *command: str) -> None:
    with pytest.raises(redis.exceptions.ResponseError):
        client.execute_command(*command)  # type: ignore[no-untyped-call]


@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}ingest", "x"),
        ("LRANGE", f"{PREFIX}ingest", "0", "-1"),
        ("BRPOP", f"{PREFIX}ingest", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}ingest"),
        ("LPUSH", f"{PREFIX}pcap", "x"),
        ("LPUSH", f"{PREFIX}static", "x"),
        ("LPUSH", f"{PREFIX}enrich", "x"),
        ("LPUSH", f"{PREFIX}analyst", "x"),
        ("LPUSH", f"{PREFIX}report", "x"),
        ("GET", f"{PREFIX}enrich.ti:rl:mock:org"),
        ("GET", f"{PREFIX}analyst.ai:day:org:20261106"),
        ("HGET", f"{PREFIX}trusted.unacked", "x"),
        ("ZRANGE", f"{PREFIX}trusted.unacked_index", "0", "-1"),
        ("SET", "rl:anything", "x"),
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("FLUSHDB",),
        ("CONFIG", "GET", "*"),
        ("CLIENT", "LIST"),
        ("LRANGE", f"{PREFIX}retention", "0", "-1"),
        ("HGETALL", f"{PREFIX}retention.unacked"),
    ],
)
def test_retention_user_is_confined(retention: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(retention, *command)


def test_retention_user_has_what_it_needs(retention: redis.Redis) -> None:
    queue = f"{PREFIX}retention"
    probe = f"{PREFIX}retention.acl-probe"
    try:
        assert retention.ping()
        retention.sadd(f"_kombu.binding.{queue}", "probe")
        assert retention.smembers(f"_kombu.binding.{queue}")
        retention.lpush(probe, "x")
        assert retention.rpop(probe) == b"x"
        retention.hset(f"{queue}.unacked", "probe", "x")
        retention.hdel(f"{queue}.unacked", "probe")
    finally:
        retention.srem(f"_kombu.binding.{queue}", "probe")
        retention.delete(probe)


@pytest.mark.parametrize(
    "env",
    [
        "TEST_BROKER_PCAP_URL",
        "TEST_BROKER_STATIC_URL",
        "TEST_BROKER_ENRICH_URL",
        "TEST_BROKER_ANALYST_URL",
        "TEST_BROKER_REPORT_URL",
    ],
)
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}retention", "x"),
        ("LLEN", f"{PREFIX}retention"),
        ("BRPOP", f"{PREFIX}retention", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}retention"),
        ("HGET", f"{PREFIX}retention.unacked", "x"),
        ("LPUSH", "retention", "x"),
    ],
)
def test_other_workers_cannot_touch_retention(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


@pytest.mark.parametrize("env", ["TEST_BROKER_API_URL", "BROKER_URL"])  # api-test: ingest user
def test_api_and_ingest_users_can_publish_to_retention(env: str) -> None:
    client = _client(env)
    probe = f"{PREFIX}retention.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}retention", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}retention", "probe")
        client.close()


def test_the_retention_user_uses_the_lane_broker_db() -> None:
    dbs = {
        os.environ[name].rsplit("/", 1)[-1] for name in ("BROKER_URL", "TEST_BROKER_RETENTION_URL")
    }
    assert len(dbs) == 1 and dbs != {"0"}
