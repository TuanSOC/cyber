"""drill_seed refuses to run outside the restore drill (M7 phase 2): without CYBERLAB_DRILL=1,
the drill project name and the drill overlay's EVIDENCE_LOCK_DAYS=1, `seed` and `check` exit 1
before any request, any owner write or any governance-bypass delete."""

import io
import json
from types import SimpleNamespace
from typing import Any

import pytest
from minio import Minio
from minio.error import S3Error

from app.scripts import drill_seed

DRILL_ENV = {
    "CYBERLAB_DRILL": "1",
    "CYBERLAB_DRILL_PROJECT": "cyberlab-drill",
    "EVIDENCE_LOCK_DAYS": "1",
}


def test_require_drill_accepts_only_the_drill() -> None:
    drill_seed.require_drill(DRILL_ENV)
    for name, bad in (
        ("CYBERLAB_DRILL", None),
        ("CYBERLAB_DRILL", "true"),
        ("CYBERLAB_DRILL_PROJECT", None),
        ("CYBERLAB_DRILL_PROJECT", "cyberlab"),
        ("CYBERLAB_DRILL_PROJECT", "cyberlab-drill-x"),
        ("EVIDENCE_LOCK_DAYS", None),
        ("EVIDENCE_LOCK_DAYS", "30"),
    ):
        env = {k: v for k, v in DRILL_ENV.items() if k != name}
        if bad is not None:
            env[name] = bad
        with pytest.raises(drill_seed.DrillError, match="refusing"):
            drill_seed.require_drill(env)


@pytest.fixture
def no_side_effects(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    called: list[str] = []

    def boom(name: str) -> Any:
        def inner(*_: Any, **__: Any) -> Any:
            called.append(name)
            raise AssertionError(f"{name} ran outside the drill")

        return inner

    monkeypatch.setattr(drill_seed, "_seed_api", boom("_seed_api"))
    monkeypatch.setattr(drill_seed, "_client", boom("_client"))
    monkeypatch.setattr(drill_seed, "_delete_locked_version", boom("_delete_locked_version"))
    return called


@pytest.mark.parametrize("mode", ["seed", "check"])
def test_main_refuses_outside_the_drill(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    no_side_effects: list[str],
) -> None:
    for name in DRILL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert drill_seed.main([mode]) == 1
    assert "refusing" in json.loads(capsys.readouterr().out)["error"]
    # The main project's api env (EVIDENCE_LOCK_DAYS=30) with a forged marker: still refused.
    monkeypatch.setenv("CYBERLAB_DRILL", "1")
    monkeypatch.setenv("CYBERLAB_DRILL_PROJECT", "cyberlab-drill")
    monkeypatch.setenv("EVIDENCE_LOCK_DAYS", "30")
    assert drill_seed.main([mode]) == 1
    assert "EVIDENCE_LOCK_DAYS" in json.loads(capsys.readouterr().out)["error"]
    assert no_side_effects == []


async def test_owner_rows_refuse_outside_the_drill(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in DRILL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DRILL_OWNER_DATABASE_URL", "postgresql+asyncpg://x:y@nowhere:1/z")
    with pytest.raises(drill_seed.DrillError, match="CYBERLAB_DRILL"):
        await drill_seed._seed_owner_rows({})


class FakeStore:
    """A root client stand-in: `deny_create` answers make_bucket as the 1001:1001 Silo wrapper
    did on the original bitnami volume root (root:root 0775), 2026-11-06."""

    def __init__(self, deny_create: bool = False, fail_put: bool = False) -> None:
        self.deny_create = deny_create
        self.fail_put = fail_put
        self.buckets: dict[str, dict[str, bytes]] = {}
        self.calls: list[str] = []

    @staticmethod
    def _error(code: str) -> S3Error:
        return S3Error(code, code, "/", "req", "host", None)  # type: ignore[arg-type]

    def make_bucket(self, bucket: str) -> None:
        self.calls.append("make_bucket")
        if self.deny_create:
            raise self._error("AccessDenied")
        self.buckets[bucket] = {}

    def put_object(self, bucket: str, key: str, data: io.BytesIO, length: int) -> None:
        self.calls.append("put_object")
        if self.fail_put:
            raise self._error("AccessDenied")
        self.buckets[bucket][key] = data.read(length)

    def get_object(self, bucket: str, key: str) -> Any:
        body = self.buckets[bucket][key]

        class Response:
            def read(self) -> bytes:
                return body

            def close(self) -> None: ...

            def release_conn(self) -> None: ...

        return Response()

    def remove_object(self, bucket: str, key: str, version_id: str | None = None) -> None:
        self.calls.append("remove_object")
        self.buckets[bucket].pop(key, None)

    def list_objects(self, bucket: str, include_version: bool = False) -> list[Any]:
        return [SimpleNamespace(object_name=k, version_id=None) for k in self.buckets[bucket]]

    def remove_bucket(self, bucket: str) -> None:
        self.calls.append("remove_bucket")
        self.buckets.pop(bucket)


def test_bucket_probe_creates_writes_reads_and_removes() -> None:
    store = FakeStore()
    record = drill_seed.bucket_probe(store, "abcd")  # type: ignore[arg-type]
    assert record == {"check": "bucket_create", "ok": True, "bucket": "drill-probe-abcd"}
    assert store.calls == [
        "make_bucket",
        "put_object",
        "remove_object",
        "remove_bucket",
    ]
    assert store.buckets == {}


def test_bucket_probe_reports_access_denied_on_the_original_layout() -> None:
    store = FakeStore(deny_create=True)
    record = drill_seed.bucket_probe(store, "abcd")  # type: ignore[arg-type]
    assert record["ok"] is False and record["code"] == "AccessDenied"
    assert store.buckets == {}


def test_bucket_probe_removes_the_bucket_after_a_failed_write() -> None:
    store = FakeStore(fail_put=True)
    record = drill_seed.bucket_probe(store, "abcd")  # type: ignore[arg-type]
    assert record["ok"] is False and record["code"] == "AccessDenied"
    assert store.buckets == {}, "the probe bucket must not be left behind"


def test_root_client_needs_the_drill_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DRILL_MINIO_ROOT_USER", "root")
    monkeypatch.setenv("DRILL_MINIO_ROOT_PASSWORD", "pw")
    monkeypatch.setenv("MINIO_ENDPOINT", "minio:9000")
    assert isinstance(drill_seed._root_client(), Minio)
    for name in ("DRILL_MINIO_ROOT_USER", "DRILL_MINIO_ROOT_PASSWORD"):
        monkeypatch.delenv(name)
    with pytest.raises(drill_seed.DrillError, match="DRILL_MINIO_ROOT_USER"):
        drill_seed._root_client()
