"""Broker ACL of the internet-facing AI analyst worker (M5): confined to `analyst*` keys
(queue, unacked bookkeeping, `analyst.ai:*` limiter/budget keys); the analyzer users and the
enrich worker cannot touch `analyst*`; the api and ingest users can publish to it."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."
SCRIPT = "redis.call('SET', KEYS[1], ARGV[1], 'EX', 60) return redis.call('GET', KEYS[1])"


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def analyst() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_ANALYST_URL")
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
        ("LPUSH", f"{PREFIX}pcap", "x"),
        ("LPUSH", f"{PREFIX}static", "x"),
        ("LPUSH", f"{PREFIX}enrich", "x"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}enrich"),
        ("GET", f"{PREFIX}enrich.ti:rl:mock:org"),
        ("HGET", f"{PREFIX}enrich.unacked", "x"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}ingest"),
        ("HGET", f"{PREFIX}trusted.unacked", "x"),
        ("ZRANGE", f"{PREFIX}trusted.unacked_index", "0", "-1"),
        ("SET", "rl:anything", "x"),
        ("GET", "ingest"),
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("FLUSHDB",),
        ("CONFIG", "GET", "*"),
        ("CLIENT", "LIST"),
        ("PUBLISH", "chan", "x"),
        # Inspection of its own queue's content is denied too (no LRANGE/HGETALL).
        ("LRANGE", f"{PREFIX}analyst", "0", "-1"),
        ("HGETALL", f"{PREFIX}analyst.unacked"),
    ],
)
def test_analyst_user_is_confined(analyst: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(analyst, *command)


def test_analyst_user_has_what_it_needs(analyst: redis.Redis) -> None:
    queue = f"{PREFIX}analyst"
    probe = f"{PREFIX}analyst.acl-probe"
    bucket = f"{PREFIX}analyst.ai:rl:mock:org"
    budget = f"{PREFIX}analyst.ai:day:org:20261105"
    try:
        assert analyst.ping()
        analyst.sadd(f"_kombu.binding.{queue}", "probe")
        assert analyst.smembers(f"_kombu.binding.{queue}")
        analyst.lpush(probe, "x")
        assert analyst.rpop(probe) == b"x"
        analyst.hset(f"{queue}.unacked", "probe", "x")
        analyst.hdel(f"{queue}.unacked", "probe")
        # Limiter / budget scripts (phase 2) run with declared keys under analyst.ai:*.
        assert analyst.eval(SCRIPT, 1, bucket, "5") == b"5"
        assert analyst.incrby(budget, 100) == 100
        # ...but never with keys outside its pattern.
        _denied(analyst, "EVAL", SCRIPT, "1", f"{PREFIX}enrich.ti:rl", "5")
        _denied(analyst, "EVAL", "return redis.call('GET', 'ingest')", "0")
    finally:
        analyst.srem(f"_kombu.binding.{queue}", "probe")
        analyst.delete(probe, bucket, budget)


@pytest.mark.parametrize(
    "env", ["TEST_BROKER_PCAP_URL", "TEST_BROKER_STATIC_URL", "TEST_BROKER_ENRICH_URL"]
)
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}analyst", "x"),
        ("LLEN", f"{PREFIX}analyst"),
        ("BRPOP", f"{PREFIX}analyst", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}analyst"),
        ("GET", f"{PREFIX}analyst.ai:day:org:20261105"),
        ("INCRBY", f"{PREFIX}analyst.ai:day:org:20261105", "1"),
        ("LPUSH", "analyst", "x"),
        ("HGET", "analyst.unacked", "x"),
    ],
)
def test_analyzers_and_enrich_cannot_touch_analyst(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


@pytest.mark.parametrize("env", ["TEST_BROKER_API_URL", "BROKER_URL"])  # api-test: ingest user
def test_api_and_ingest_users_can_publish_to_analyst(env: str) -> None:
    client = _client(env)
    probe = f"{PREFIX}analyst.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}analyst", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}analyst", "probe")
        client.close()


def test_the_test_profile_uses_the_lane_broker_db() -> None:
    """RT3: every test broker URL points at the same db (`TEST_BROKER_DB`, default 1)."""
    dbs = {
        os.environ[name].rsplit("/", 1)[-1]
        for name in (
            "BROKER_URL",
            "TEST_BROKER_API_URL",
            "TEST_BROKER_PCAP_URL",
            "TEST_BROKER_STATIC_URL",
            "TEST_BROKER_ENRICH_URL",
            "TEST_BROKER_ANALYST_URL",
        )
    }
    assert len(dbs) == 1 and dbs != {"0"}
