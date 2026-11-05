"""Broker ACL of the untrusted report renderer (M6 phase 1): the `report` user is confined
like an analyzer (its `report*` queue and unacked keys, write-only to `ingest`, read-only on
ingest's bindings); the analyzers, the enrich and the analyst workers cannot touch `report*`;
the api and ingest users can publish to it."""

import os
from collections.abc import Iterator

import pytest
import redis

PREFIX = "test."


def _client(env: str) -> redis.Redis:
    return redis.Redis.from_url(os.environ[env], socket_timeout=3)


@pytest.fixture
def report() -> Iterator[redis.Redis]:
    client = _client("TEST_BROKER_REPORT_URL")
    yield client
    client.close()


def _denied(client: redis.Redis, *command: str) -> None:
    with pytest.raises(redis.exceptions.ResponseError):
        client.execute_command(*command)  # type: ignore[no-untyped-call]


@pytest.mark.parametrize(
    "command",
    [
        ("LRANGE", f"{PREFIX}ingest", "0", "-1"),
        ("BRPOP", f"{PREFIX}ingest", "1"),
        ("LPOP", f"{PREFIX}ingest"),
        ("SADD", f"_kombu.binding.{PREFIX}ingest", "x"),
        ("DEL", f"_kombu.binding.{PREFIX}ingest"),
        ("LPUSH", f"{PREFIX}pcap", "x"),
        ("LPUSH", f"{PREFIX}static", "x"),
        ("LPUSH", f"{PREFIX}enrich", "x"),
        ("LPUSH", f"{PREFIX}analyst", "x"),
        ("GET", f"{PREFIX}analyst.ai:day:org:20261106"),
        ("GET", f"{PREFIX}enrich.ti:rl:mock:org"),
        ("HGET", f"{PREFIX}trusted.unacked", "x"),
        ("ZRANGE", f"{PREFIX}trusted.unacked_index", "0", "-1"),
        ("SET", "rl:anything", "x"),
        ("KEYS", "*"),
        ("SCAN", "0"),
        ("FLUSHDB",),
        ("CONFIG", "GET", "*"),
        ("CLIENT", "LIST"),
        ("LRANGE", f"{PREFIX}report", "0", "-1"),
        ("HGETALL", f"{PREFIX}report.unacked"),
    ],
)
def test_report_user_is_confined(report: redis.Redis, command: tuple[str, ...]) -> None:
    _denied(report, *command)


def test_report_user_has_what_it_needs(report: redis.Redis) -> None:
    queue = f"{PREFIX}report"
    probe = f"{PREFIX}report.acl-probe"
    try:
        assert report.ping()
        report.sadd(f"_kombu.binding.{queue}", "probe")
        assert report.smembers(f"_kombu.binding.{queue}")
        report.lpush(probe, "x")
        assert report.rpop(probe) == b"x"
        report.hset(f"{queue}.unacked", "probe", "x")
        report.hdel(f"{queue}.unacked", "probe")
        # It may add its answer to the ingest queue and read ingest's bindings (kombu).
        assert report.smembers(f"_kombu.binding.{PREFIX}ingest") is not None
    finally:
        report.srem(f"_kombu.binding.{queue}", "probe")
        report.delete(probe)


@pytest.mark.parametrize(
    "env",
    [
        "TEST_BROKER_PCAP_URL",
        "TEST_BROKER_STATIC_URL",
        "TEST_BROKER_ENRICH_URL",
        "TEST_BROKER_ANALYST_URL",
    ],
)
@pytest.mark.parametrize(
    "command",
    [
        ("LPUSH", f"{PREFIX}report", "x"),
        ("LLEN", f"{PREFIX}report"),
        ("BRPOP", f"{PREFIX}report", "1"),
        ("SMEMBERS", f"_kombu.binding.{PREFIX}report"),
        ("HGET", f"{PREFIX}report.unacked", "x"),
        ("LPUSH", "report", "x"),
    ],
)
def test_other_workers_cannot_touch_report(env: str, command: tuple[str, ...]) -> None:
    client = _client(env)
    try:
        _denied(client, *command)
    finally:
        client.close()


@pytest.mark.parametrize("env", ["TEST_BROKER_API_URL", "BROKER_URL"])  # api-test: ingest user
def test_api_and_ingest_users_can_publish_to_report(env: str) -> None:
    client = _client(env)
    probe = f"{PREFIX}report.publish-probe"
    try:
        client.lpush(probe, "x")
        client.sadd(f"_kombu.binding.{PREFIX}report", "probe")
    finally:
        client.delete(probe)
        client.srem(f"_kombu.binding.{PREFIX}report", "probe")
        client.close()


def test_the_report_user_uses_the_lane_broker_db() -> None:
    dbs = {os.environ[name].rsplit("/", 1)[-1] for name in ("BROKER_URL", "TEST_BROKER_REPORT_URL")}
    assert len(dbs) == 1 and dbs != {"0"}
