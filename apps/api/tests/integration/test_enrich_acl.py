"""Broker ACL of the internet-facing enrich worker (M4): confined to `enrich*` keys; the
analyzer users cannot touch `enrich*`; the api user can publish to it."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def enrich() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_ENRICH_URL")
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
        ("SMEMBERS", f"_kombu.binding.{PREFIX}ingest"),
        ("HGET", f"{PREFIX}trusted.unacked", "x"),
        ("ZRANGE", f"{PREFIX}trusted.unacked_index", "0", "-1"),
        ("GET", f"{PREFIX}pcap.unacked"),
        ("SET", "rl:anything", "x"),
        ("GET", "ingest"),
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("FLUSHDB",),
        ("CONFIG", "GET", "*"),
        ("CLIENT", "LIST"),
        # Inspection of its own queue's content is denied too (no LRANGE/HGETALL).
        ("LRANGE", f"{PREFIX}enrich", "0", "-1"),
        ("HGETALL", f"{PREFIX}enrich.unacked"),
    ],
)
def test_enrich_user_is_confined(enrich: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(enrich, *command)


def test_enrich_user_has_what_it_needs(enrich: redis.Redis) -> None:
    queue = f"{PREFIX}enrich"
    probe = f"{PREFIX}enrich.acl-probe"
    try:
        assert enrich.ping()
        enrich.sadd(f"_kombu.binding.{queue}", "probe")
        assert enrich.smembers(f"_kombu.binding.{queue}")
        enrich.lpush(probe, "x")
        assert enrich.rpop(probe) == b"x"
        enrich.hset(f"{queue}.unacked", "probe", "x")
        enrich.hdel(f"{queue}.unacked", "probe")
        # Limiter scripts (phase 2) run with declared keys under enrich.ti:*.
        script = "redis.call('SET', KEYS[1], ARGV[1], 'EX', 60) return redis.call('GET', KEYS[1])"
        bucket = f"{PREFIX}enrich.ti:rl:mock:org"
        assert enrich.eval(script, 1, bucket, "5") == b"5"
        # ...but never with keys outside its pattern.
        _denied(enrich, "EVAL", script, "1", f"{PREFIX}ingest.ti:rl", "5")
        _denied(enrich, "EVAL", "return redis.call('GET', 'ingest')", "0")
    finally:
        enrich.srem(f"_kombu.binding.{queue}", "probe")
        enrich.delete(probe, f"{PREFIX}enrich.ti:rl:mock:org")


@pytest.mark.parametrize("env", ["TEST_BROKER_PCAP_URL", "TEST_BROKER_STATIC_URL"])
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}enrich", "x"),
        ("LLEN", f"{PREFIX}enrich"),
        ("BRPOP", f"{PREFIX}enrich", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}enrich"),
        ("GET", f"{PREFIX}enrich.ti:rl:mock:org"),
        ("LPUSH", "enrich", "x"),
        ("HGET", "enrich.unacked", "x"),
    ],
)
def test_analyzers_cannot_touch_enrich(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


def test_api_user_can_publish_to_enrich() -> None:
    client = _client("TEST_BROKER_API_URL")
    probe = f"{PREFIX}enrich.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}enrich", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}enrich", "probe")
        client.close()
