"""The phase-1 report renderer skeleton: Celery settings (prefork, one task per child, time
limits, no remote control), the `report.render` answer (`failed / not_implemented`), invalid
messages dropped, and the image facts (no Ghostscript, only the bundled fonts)."""

import base64
import json
import shutil
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import REPORT_RENDER, REPORT_RENDERED
from cyberlab_jobs.report import (
    TLP,
    Manifest,
    Profile,
    ReportRenderedV1,
    ReportSnapshot,
    manifest_bytes,
)

from report_worker import app as worker_app
from report_worker import config, tasks

FIXTURES = Path(__file__).parent / "fixtures"


def _message(**over: Any) -> dict[str, Any]:
    manifest = Manifest(
        report_id=uuid.uuid4(),
        version=1,
        org_id=uuid.uuid4(),
        snapshot_sha256="a" * 64,
        snapshot_bytes=10,
        tlp=TLP.AMBER,
        profile=Profile.INTERNAL,
        finalized_at=datetime(2026, 11, 6, 9, 0, tzinfo=UTC),
        finalized_by=uuid.uuid4(),
        kid="dev-report-1",
    )
    values: dict[str, Any] = {
        "render_id": str(uuid.uuid4()),
        "org_id": str(manifest.org_id),
        "format": "pdf",
        "snapshot_url": "http://minio:9000/reports-test/x?X-Amz-Signature=1",
        "snapshot_sha256": "a" * 64,
        "snapshot_bytes": 10,
        "manifest_b64": base64.b64encode(manifest_bytes(manifest)).decode(),
        "signature": base64.b64encode(bytes(64)).decode(),
        "kid": "dev-report-1",
        "finalized_at": "2026-11-06T09:00:00Z",
        "upload": {"url": "http://minio:9000/reports-test", "fields": {"key": "k"}},
        "token": "t" * 43,
        "deadline": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    }
    values.update(over)
    return values


def test_celery_runs_prefork_one_task_per_child_with_limits() -> None:
    conf = worker_app.celery_app.conf
    assert conf.worker_concurrency == 1
    assert conf.worker_max_tasks_per_child == 1
    assert (conf.task_soft_time_limit, conf.task_time_limit) == (90, 120)
    assert conf.worker_enable_remote_control is False
    assert conf.worker_send_task_events is False
    assert conf.task_acks_late is False
    assert conf.task_default_queue.endswith("report")
    assert conf.broker_transport_options["unacked_key"].endswith("report.unacked")
    assert REPORT_RENDER in worker_app.celery_app.tasks


def test_a_render_is_answered_not_implemented() -> None:
    sent: list[ReportRenderedV1] = []
    message = _message()
    result = tasks.handle_render(message, sent.append)
    assert result is not None and sent == [result]
    assert (result.status, result.error_code) == ("failed", "not_implemented")
    assert str(result.render_id) == message["render_id"] and result.token == message["token"]
    assert result.renderer_version == config.RENDERER_VERSION


@pytest.mark.parametrize(
    "bad",
    [
        {"format": "docx"},
        {"token": "short"},
        {"snapshot_url": "file:///etc/passwd"},
        {"render_id": "not-a-uuid"},
        {"surprise": 1},
    ],
)
def test_invalid_messages_are_dropped(
    bad: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    sent: list[ReportRenderedV1] = []
    assert tasks.handle_render(_message(**bad), sent.append) is None
    assert sent == []
    assert "X-Amz-Signature" not in caplog.text  # presigned URLs are never logged


def test_the_answer_goes_to_the_ingest_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any], Any]] = []

    def send_task(name: str, kwargs: dict[str, Any], queue: Any) -> None:
        calls.append((name, kwargs, queue))

    monkeypatch.setattr(worker_app.celery_app, "send_task", send_task)
    result = tasks.handle_render(_message(), tasks.send_rendered)
    assert result is not None
    [(name, kwargs, queue)] = calls
    assert name == REPORT_RENDERED and queue is worker_app.INGEST_QUEUE
    assert ReportRenderedV1.model_validate(kwargs["message"]) == result


@pytest.mark.parametrize("name", ["golden_snapshot.json", "hostile_snapshot.json"])
def test_the_fixtures_are_valid_snapshots(name: str) -> None:
    snapshot = ReportSnapshot.model_validate_json((FIXTURES / name).read_bytes())
    assert json.loads((FIXTURES / name).read_text("utf-8"))["schema_version"] == (
        snapshot.schema_version
    )


def test_the_image_has_no_ghostscript() -> None:
    if not Path("/app/assets/fonts.conf").exists():
        pytest.skip("runs inside the report-worker image")
    assert shutil.which("gs") is None
    for path in ("/usr/bin/gs", "/usr/local/bin/gs"):
        assert not Path(path).exists()


def test_fontconfig_lists_only_the_bundled_fonts() -> None:
    conf = Path("/app/assets/fonts.conf")
    if not conf.exists():
        pytest.skip("runs inside the report-worker image")
    dirs = [line.strip() for line in conf.read_text().splitlines() if "<dir>" in line]
    assert dirs == ["<dir>/usr/share/fonts/truetype/noto</dir>"]
    assert Path("/usr/share/fonts/truetype/noto").is_dir()
