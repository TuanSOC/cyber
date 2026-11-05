"""The `report.render` flow: download and verify, sandboxed render, output checks, upload,
typed answers. The snapshot is served and the artifact received by a local HTTP server
(the real `transfer.download` / `transfer.upload` run against it); the render subprocess is
the real one, or a stand-in script run through the same sandbox."""

import base64
import hashlib
import json
import logging
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.report import (
    TLP,
    Manifest,
    Profile,
    ReportRenderedV1,
    ReportSnapshot,
    canonical_json,
    manifest_bytes,
)
from cyberlab_worker import sandbox

from report_worker import config, tasks
from report_worker import sandbox as render_sandbox
from tests.conftest import WORK, in_container, load_snapshot

pytestmark = in_container


@dataclass
class Server:
    url: str
    body: bytes = b""
    get_status: int = 200
    post_status: int = 204
    posts: list[dict[str, Any]] = field(default_factory=list)
    gets: int = 0


@pytest.fixture
def server() -> Iterator[Server]:
    state = Server(url="")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            state.gets += 1
            self.send_response(state.get_status)
            self.send_header("Content-Length", str(len(state.body)))
            self.end_headers()
            self.wfile.write(state.body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"])
            raw = self.rfile.read(length)
            message = BytesParser(policy=HTTP).parsebytes(
                b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + raw
            )
            parts: dict[str, Any] = {}
            for part in message.iter_parts():
                name = str(part.get_param("name", header="content-disposition"))
                parts[name] = {
                    "filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "data": part.get_payload(decode=True),
                }
            state.posts.append(parts)
            self.send_response(state.post_status)
            if state.post_status < 300:
                self.send_header("x-amz-version-id", "version-1")
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield state
    httpd.shutdown()
    httpd.server_close()


def message(
    server: Server, snapshot: ReportSnapshot, fmt: str = "pdf", **over: Any
) -> dict[str, Any]:
    data = canonical_json(snapshot)
    server.body = data
    sha = hashlib.sha256(data).hexdigest()
    org = uuid.uuid4()
    manifest = Manifest(
        report_id=snapshot.report.report_id,
        version=snapshot.report.version,
        org_id=org,
        snapshot_sha256=sha,
        snapshot_bytes=len(data),
        tlp=TLP.AMBER,
        profile=Profile.INTERNAL,
        finalized_at=snapshot.report.finalized_at,
        finalized_by=uuid.uuid4(),
        kid="dev-report-1",
    )
    values: dict[str, Any] = {
        "render_id": str(uuid.uuid4()),
        "org_id": str(org),
        "format": fmt,
        "snapshot_url": f"{server.url}/reports-test/snapshot.json?X-Amz-Signature=secret",
        "snapshot_sha256": sha,
        "snapshot_bytes": len(data),
        "manifest_b64": base64.b64encode(manifest_bytes(manifest)).decode(),
        "signature": base64.b64encode(bytes(range(64))).decode(),
        "kid": "dev-report-1",
        "finalized_at": "2026-11-06T09:00:00Z",
        "upload": {"url": f"{server.url}/reports-test", "fields": {"key": "k", "policy": "p"}},
        "token": "t" * 43,
        "deadline": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    }
    values.update(over)
    return values


def run(msg: dict[str, Any]) -> ReportRenderedV1:
    sent: list[ReportRenderedV1] = []
    result = tasks.handle_render(msg, sent.append)
    assert result is not None and sent == [result]
    return result


REAL_ARGV = render_sandbox.render_argv


def fake_renderer(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    """Replace the render subprocess by a script, run through the same sandbox. The script
    gets `fmt, in_dir, out_file` as `sys.argv[1:]`."""

    def argv(fmt: str, dirs: sandbox.JobDirs) -> list[str]:
        real = REAL_ARGV(fmt, dirs)
        return [real[0], "-I", "-B", "-c", code, *real[-3:]]

    monkeypatch.setattr(render_sandbox, "render_argv", argv)


WRITE = """
import json, sys
from pathlib import Path
out = Path(sys.argv[3])
out.write_bytes({data!r})
(out.parent / "render.json").write_text(json.dumps({{"pages": {pages!r}}}))
"""


# --- success -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fmt", "data", "content_type"),
    [
        ("pdf", b"%PDF-1.7 fake", "application/pdf"),
        ("html", b"<!DOCTYPE html><p>x</p>", "text/html"),
        ("md", "TLP\\:AMBER ⏎".encode(), "text/markdown"),
    ],
)
def test_a_render_is_checked_uploaded_and_answered(
    server: Server, monkeypatch: pytest.MonkeyPatch, fmt: str, data: bytes, content_type: str
) -> None:
    pages = 3 if fmt == "pdf" else None
    fake_renderer(monkeypatch, WRITE.format(data=data, pages=pages))
    result = run(message(server, load_snapshot("golden_snapshot.json"), fmt))
    assert result.status == "succeeded", result.error_code
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert (result.bytes, result.pages, result.object_version_id) == (len(data), pages, "version-1")
    assert result.renderer_version == config.RENDERER_VERSION
    [post] = server.posts
    assert post["key"]["data"] == b"k" and post["policy"]["data"] == b"p"
    assert post["file"]["data"] == data
    assert post["file"]["content_type"] == content_type
    assert post["file"]["filename"] == f"report.{fmt}"


@pytest.mark.parametrize("fmt", ["pdf", "html", "md"])
def test_the_real_renderer_renders_the_golden_snapshot(server: Server, fmt: str) -> None:
    result = run(message(server, load_snapshot("golden_snapshot.json"), fmt))
    assert result.status == "succeeded", result.error_code
    [post] = server.posts
    artifact = post["file"]["data"]
    assert hashlib.sha256(artifact).hexdigest() == result.sha256
    if fmt == "pdf":
        assert artifact.startswith(b"%PDF-") and result.pages is not None and result.pages >= 1
    else:
        assert "TLP:AMBER" in artifact.decode().replace("\\", "") and result.pages is None


def test_every_render_cleans_up_its_job_and_processes(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_renderer(
        monkeypatch,
        "import os, sys, time\n"
        "if os.fork() == 0:\n    os.setsid(); time.sleep(60)\n"
        + WRITE.format(data=b"%PDF-1.7", pages=1),
    )
    result = run(message(server, load_snapshot("golden_snapshot.json")))
    assert result.status == "succeeded"
    assert sandbox.tool_pids() == []
    assert list(WORK.iterdir()) == []


def test_reset_kills_leftovers_before_a_render(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process left by an earlier render whose cleanup never ran (hard time limit)."""
    leftover = sandbox.prepare(WORK, "leftover")
    sandbox.run_tool(
        ["sh", "-c", "(setsid sleep 60 </dev/null >/dev/null 2>&1 &); sleep 0.2"],
        leftover,
        timeout_s=5,
    )
    assert sandbox.tool_pids() != []
    seen: list[list[int]] = []
    original = render_sandbox.render

    def render(fmt: str, dirs: sandbox.JobDirs) -> render_sandbox.RenderRun:
        seen.append(sandbox.tool_pids())
        assert not (WORK / "leftover").exists()
        return original(fmt, dirs)

    monkeypatch.setattr(render_sandbox, "render", render)
    fake_renderer(monkeypatch, WRITE.format(data=b"%PDF-1.7", pages=1))
    assert run(message(server, load_snapshot("golden_snapshot.json"))).status == "succeeded"
    assert seen == [[]]


# --- snapshot checks -----------------------------------------------------------------------


def test_a_snapshot_with_other_bytes_is_refused_before_rendering(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_renderer(monkeypatch, "raise SystemExit('must not run')")
    msg = message(server, load_snapshot("golden_snapshot.json"))
    server.body = server.body.replace(b"Beaconing", b"Beaconinh")
    result = run(msg)
    assert (result.status, result.error_code) == ("failed", "snapshot_mismatch")
    assert server.posts == []


def test_an_unreachable_snapshot_is_a_mismatch(server: Server) -> None:
    msg = message(server, load_snapshot("golden_snapshot.json"))
    server.get_status = 403
    result = run(msg)
    assert (result.status, result.error_code) == ("failed", "snapshot_mismatch")


def test_a_manifest_for_another_snapshot_is_refused_without_download(server: Server) -> None:
    msg = message(server, load_snapshot("golden_snapshot.json"))
    other = message(server, load_snapshot("hostile_snapshot.json"))
    msg["manifest_b64"] = other["manifest_b64"]
    result = run(msg)
    assert (result.status, result.error_code) == ("failed", "snapshot_mismatch")
    assert server.gets == 0


def test_bytes_that_are_not_a_snapshot_are_refused(server: Server) -> None:
    msg = message(server, load_snapshot("golden_snapshot.json"))
    bogus = json.dumps({"schema_version": "cyberlab.report.v1"}).encode()
    server.body = bogus
    sha = hashlib.sha256(bogus).hexdigest()
    manifest = json.loads(base64.b64decode(msg["manifest_b64"]))
    manifest.update(snapshot_sha256=sha, snapshot_bytes=len(bogus))
    msg.update(
        snapshot_sha256=sha,
        snapshot_bytes=len(bogus),
        manifest_b64=base64.b64encode(canonical_json(manifest)).decode(),
    )
    result = run(msg)
    assert (result.status, result.error_code) == ("failed", "snapshot_mismatch")


def test_a_passed_deadline_is_a_timeout(server: Server) -> None:
    msg = message(
        server,
        load_snapshot("golden_snapshot.json"),
        deadline=(datetime.now(UTC) - timedelta(seconds=5)).isoformat(),
    )
    result = run(msg)
    assert (result.status, result.error_code) == ("failed", "timeout")
    assert server.gets == 0


# --- typed failures ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("raise SystemExit(10)", "fetch_blocked"),
        ("raise SystemExit(11)", "too_many_pages"),
        ("raise SystemExit(12)", "too_large"),
        ("raise SystemExit(13)", "oom"),
        ("raise SystemExit(14)", "invalid_output"),
        ("raise SystemExit(99)", "renderer_error"),
        ("import os, signal; os.kill(os.getpid(), signal.SIGKILL)", "oom"),
        ("import os, signal; os.kill(os.getpid(), signal.SIGSEGV)", "renderer_error"),
        (
            "import sys; print('secret-detail', file=sys.stderr); "
            "raise ValueError('secret-detail')",
            "renderer_error",
        ),
    ],
)
def test_render_failures_are_typed_and_carry_no_text(
    server: Server,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    code: str,
    expected: str,
) -> None:
    caplog.set_level(logging.INFO)
    fake_renderer(monkeypatch, code)
    result = run(message(server, load_snapshot("golden_snapshot.json")))
    assert (result.status, result.error_code) == ("failed", expected)
    dumped = result.model_dump(mode="json")
    assert set(dumped) == set(ReportRenderedV1.model_fields)
    assert (dumped["sha256"], dumped["bytes"], dumped["pages"]) == (None, None, None)
    assert "secret-detail" not in json.dumps(dumped) and "secret-detail" not in caplog.text
    assert "X-Amz-Signature" not in caplog.text
    assert server.posts == []


@pytest.mark.parametrize(
    ("fmt", "code"),
    [
        ("pdf", WRITE.format(data=b"<html>not a pdf", pages=1)),
        ("pdf", WRITE.format(data=b"%PDF-1.7", pages=None)),
        ("pdf", WRITE.format(data=b"%PDF-1.7", pages=0)),
        ("html", WRITE.format(data=b"<!DOCTYPE html>\xff\xfe", pages=None)),
        ("md", WRITE.format(data=b"", pages=None)),
        ("md", "import sys; open(sys.argv[3], 'w').write('x')"),  # no render.json
        (
            "pdf",
            "import os, sys; from pathlib import Path\n"
            "os.symlink('/etc/passwd', sys.argv[3])\n"
            "(Path(sys.argv[3]).parent / 'render.json').write_text('{\"pages\": 1}')",
        ),
    ],
)
def test_invalid_outputs_are_refused(
    server: Server, monkeypatch: pytest.MonkeyPatch, fmt: str, code: str
) -> None:
    fake_renderer(monkeypatch, code)
    result = run(message(server, load_snapshot("golden_snapshot.json"), fmt))
    assert (result.status, result.error_code) == ("failed", "invalid_output")
    assert server.posts == []


def test_too_many_reported_pages_are_refused(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_renderer(monkeypatch, WRITE.format(data=b"%PDF-1.7", pages=301))
    result = run(message(server, load_snapshot("golden_snapshot.json")))
    assert (result.status, result.error_code) == ("failed", "too_many_pages")


def test_a_failed_upload_is_a_renderer_error(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_renderer(monkeypatch, WRITE.format(data=b"%PDF-1.7", pages=1))
    server.post_status = 403
    result = run(message(server, load_snapshot("golden_snapshot.json")))
    assert (result.status, result.error_code) == ("failed", "renderer_error")


def test_an_unexpected_exception_is_a_renderer_error_logged_by_type_only(
    server: Server, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("secret-detail /work/abc")

    monkeypatch.setattr(render_sandbox, "render", boom)
    result = run(message(server, load_snapshot("golden_snapshot.json")))
    assert (result.status, result.error_code) == ("failed", "renderer_error")
    assert "RuntimeError" in caplog.text and "secret-detail" not in caplog.text


def test_inputs_are_root_owned_and_read_only(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_renderer(
        monkeypatch,
        "import os, sys, json\nfrom pathlib import Path\n"
        "d = Path(sys.argv[2])\n"
        "st = {p.name: (p.stat().st_uid, oct(p.stat().st_mode & 0o777)) for p in d.iterdir()}\n"
        "ok = all(v == (0, '0o444') for v in st.values()) and os.getcwd() == str(d)\n"
        "try:\n    (d / 'x').write_text('x'); ok = False\nexcept OSError:\n    pass\n"
        "out = Path(sys.argv[3]); out.write_bytes(b'%PDF-1.7' if ok else b'bad')\n"
        "(out.parent / 'render.json').write_text(json.dumps({'pages': 1}))\n",
    )
    result = run(message(server, load_snapshot("golden_snapshot.json")))
    assert result.status == "succeeded", result.error_code


def test_the_embedded_inputs_are_the_signed_bytes(server: Server) -> None:
    """manifest.json is the manifest exactly as signed; manifest.sig.json names it."""
    seen: dict[str, bytes] = {}
    original = render_sandbox.render

    def capture(fmt: str, dirs: sandbox.JobDirs) -> render_sandbox.RenderRun:
        for name in ("snapshot.json", "manifest.json", "manifest.sig.json", "job.json"):
            seen[name] = (dirs.input / name).read_bytes()
        return original(fmt, dirs)

    msg = message(server, load_snapshot("golden_snapshot.json"), "md")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(render_sandbox, "render", capture)
        assert run(msg).status == "succeeded"
    assert seen["snapshot.json"] == server.body
    assert seen["manifest.json"] == base64.b64decode(msg["manifest_b64"])
    signature = json.loads(seen["manifest.sig.json"])
    assert signature["signature"] == msg["signature"] and signature["kid"] == "dev-report-1"
    assert signature["manifest"] == json.loads(seen["manifest.json"])
    assert json.loads(seen["job.json"]) == {
        "format": "md",
        "sha256": msg["snapshot_sha256"],
        "finalized_at": "2026-11-06T09:00:00.000000Z",
    }
    assert Path(WORK).exists()
