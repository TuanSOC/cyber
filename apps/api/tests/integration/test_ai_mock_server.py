"""The `ai-mock` stdlib server (M5 phase 2): the frozen wire protocol, a deterministic and
schema-valid default answer that cites the evidence with exact quotes, every behaviour
marker, and the test-only `/_last`.

The server is spawned in-process on a free port. `infra/` is not mounted in `api-test`, so
the module is found through `AI_MOCK_SERVER`, `/srv/ai-mock/server.py` (mount it with
`-v ./infra/ai-mock:/srv/ai-mock:ro`) or the repo checkout; the tests skip without it.
"""

import importlib.util
import json
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.modules.ai.contracts import AiTask, FieldValue, RefKind
from app.modules.ai.output_schema import AnalysisOutput, provider_json_schema
from app.modules.ai.prompt import render
from tests.ai_doubles import make_context, trivial_render

KEY = "test-ai-mock-key"
CANARY = "Zq3-_x9Kp0LmN4vB7tR2yW8eH5uJ1oA6"  # like secrets.token_urlsafe(24)


def _server_path() -> Path | None:
    candidates = [
        os.environ.get("AI_MOCK_SERVER"),
        "/srv/ai-mock/server.py",
        str(Path(__file__).resolve().parents[4] / "infra" / "ai-mock" / "server.py"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def _load() -> ModuleType:
    path = _server_path()
    if path is None:
        pytest.skip("infra/ai-mock/server.py is not reachable from this container")
    spec = importlib.util.spec_from_file_location("ai_mock_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mock() -> Iterator[ModuleType]:
    yield _load()


@pytest.fixture(scope="module")
def base_url(mock: ModuleType) -> Iterator[str]:
    server = mock.make_server("127.0.0.1", 0, expected_key=KEY, slow_s=0.3)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def client(base_url: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=base_url, timeout=10, headers={"X-Mock-Key": KEY}) as c:
        c.post("/_reset")
        yield c


def _request(
    items: tuple[tuple[RefKind, dict[str, FieldValue]], ...] | None = None,
    task: AiTask = AiTask.SUMMARIZE_PCAP,
) -> dict[str, Any]:
    ctx = make_context(task=task) if items is None else make_context(task=task, items=items)
    parts = trivial_render(ctx, task, delimiter="d" * 32, canary=CANARY)
    return {
        "model": "mock-1",
        "system": parts.system,
        "user": parts.user,
        "schema": provider_json_schema("mock"),
        "max_output_tokens": 1000,
    }


def _marked(marker: str) -> dict[str, Any]:
    return _request(
        (
            (RefKind.FINDING, {"title": f"Beacon to 203.0.113.50 ({marker})", "severity": "high"}),
            (RefKind.IOC, {"type": "ipv4", "value": "203.0.113.50"}),
        )
    )


def test_health_and_key_checks(client: httpx.Client, base_url: str) -> None:
    assert httpx.get(f"{base_url}/health").json() == {"ok": True}
    assert client.get("/v1/verify").json() == {"ok": True}
    for headers in ({}, {"X-Mock-Key": "wrong"}):
        with httpx.Client(base_url=base_url, headers=headers) as anonymous:
            assert anonymous.get("/v1/verify").status_code == 401
            denied = anonymous.post("/v1/analyze", json=_request())
            assert (denied.status_code, denied.json()) == (401, {"error": "auth"})
            assert anonymous.post("/v1/count_tokens", json=_request()).status_code == 401
    assert client.get("/nope").status_code == 404
    assert client.post("/v1/analyze", content=b"not json").status_code == 400


def test_count_tokens_is_chars_over_four(client: httpx.Client) -> None:
    body = _request()
    expected = (len(body["system"]) + len(body["user"])) // 4
    assert client.post("/v1/count_tokens", json=body).json() == {"input_tokens": expected}


def test_default_answer_is_schema_valid_and_cites_exact_quotes(client: httpx.Client) -> None:
    body = _request()
    response = client.post("/v1/analyze", json=body)
    assert response.status_code == 200
    doc = response.json()
    assert doc["stop_reason"] == "end_turn"
    assert doc["model"] == "mock-1"
    assert doc["usage"] == {
        "input_tokens": (len(body["system"]) + len(body["user"])) // 4,
        "output_tokens": len(json.dumps(doc["output"])) // 4,
    }
    output = AnalysisOutput.model_validate(doc["output"])
    ctx = make_context()
    assert output.observed and output.interpretation and output.hypotheses
    assert [t.technique_id for t in output.attack_techniques] == ["T1071.001", "T1573"]
    assert [e.citations[0].ref for e in output.timeline] == ["E1"]
    for claim in output.observed:
        (citation,) = claim.citations
        item = ctx.item(citation.ref)
        assert item is not None and citation.field is not None and citation.quote
        value = item.fields[citation.field]
        assert isinstance(value, str) and citation.quote in value
        assert citation.quote in claim.text
    # Deterministic.
    assert client.post("/v1/analyze", json=body).json() == doc


def test_an_empty_context_still_gets_a_valid_answer(client: httpx.Client) -> None:
    body = _request(())
    output = AnalysisOutput.model_validate(client.post("/v1/analyze", json=body).json()["output"])
    assert output.observed == [] and output.overall_confidence.level == "low"


@pytest.mark.parametrize(
    ("marker", "status", "error", "retry_after"),
    [
        ("429", 429, "rate_limited", "1"),
        ("429-nora", 429, "rate_limited", None),
        ("529", 529, "overloaded", None),
        ("spend", 429, "spend_limit", None),
        ("401", 401, "auth", None),
        ("500", 500, "server", None),
    ],
)
def test_error_markers(
    client: httpx.Client, marker: str, status: int, error: str, retry_after: str | None
) -> None:
    response = client.post("/v1/analyze", json=_marked(f"ai-mock:{marker}"))
    assert response.status_code == status
    assert response.json()["error"] == error
    assert response.headers.get("Retry-After") == retry_after
    if marker == "401":  # hostile on purpose: the key comes back in the body (key-leak suite)
        assert KEY in response.json()["message"]
    else:
        assert response.json() == {"error": error}


def test_body_markers(client: httpx.Client) -> None:
    malformed = client.post("/v1/analyze", json=_marked("ai-mock:malformed"))
    assert malformed.status_code == 200
    with pytest.raises(ValueError):
        json.loads(malformed.content)

    oversize = client.post("/v1/analyze", json=_marked("ai-mock:oversize"))
    assert oversize.status_code == 200 and len(oversize.content) > 2 * 1024 * 1024

    schema = client.post("/v1/analyze", json=_marked("ai-mock:schema")).json()
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate(schema["output"])

    refused = client.post("/v1/analyze", json=_marked("ai-mock:refuse")).json()
    assert (refused["stop_reason"], refused["refusal_category"]) == ("refusal", "cyber")

    truncated = client.post("/v1/analyze", json=_marked("ai-mock:maxtokens")).json()
    assert truncated["stop_reason"] == "max_tokens" and isinstance(truncated["output"], str)


def test_fabricate_echo_and_inject(client: httpx.Client) -> None:
    body = _marked("ai-mock:fabricate")
    fabricated = AnalysisOutput.model_validate(
        client.post("/v1/analyze", json=body).json()["output"]
    )
    refs = [c.ref for claim in fabricated.observed for c in claim.citations]
    assert "F999" in refs  # an invented label
    real = fabricated.observed[1].citations[0]
    assert real.ref == "F1" and real.quote not in body["user"]  # a quote never sent

    echoed = client.post("/v1/analyze", json=_marked("ai-mock:echo")).json()["output"]
    assert CANARY in AnalysisOutput.model_validate(echoed).observed[0].text
    # A long system prompt: the canary deep inside is still echoed whole, within the caps.
    long = _marked("ai-mock:echo")
    long["system"] = "Rules. " * 1500 + f"Secret {CANARY}. " + "More rules. " * 200
    echoed = client.post("/v1/analyze", json=long).json()["output"]
    texts = [c.text for c in AnalysisOutput.model_validate(echoed).observed]
    assert any(CANARY in text for text in texts[1:])
    # The real prompt (`ai.prompt.render`) puts the canary in the user turn, before the
    # evidence block: echoed too; the evidence itself (the marker value) is not.
    ctx = make_context(
        items=((RefKind.FINDING, {"title": "Beacon (ai-mock:echo)", "severity": "high"}),)
    )
    parts = render(ctx, AiTask.SUMMARIZE_PCAP, delimiter="d" * 32, canary=CANARY)
    assert CANARY not in parts.system and CANARY in parts.user
    real = {**_marked("ai-mock:echo"), "system": parts.system, "user": parts.user}
    echoed = client.post("/v1/analyze", json=real).json()["output"]
    texts = [c.text for c in AnalysisOutput.model_validate(echoed).observed]
    assert CANARY in texts[0] and any(CANARY in text for text in texts[1:])
    assert not any("Beacon (ai-mock:echo)" in text for text in texts)

    injected = AnalysisOutput.model_validate(
        client.post("/v1/analyze", json=_marked("ai-mock:inject")).json()["output"]
    )
    assert "clean" in injected.observed[0].text
    assert injected.overall_confidence.level == "high"

    hostile = AnalysisOutput.model_validate(
        client.post("/v1/analyze", json=_marked("ai-mock:hostile")).json()["output"]
    )
    assert "clean" in hostile.observed[0].text
    assert "F999" in [c.ref for claim in hostile.observed for c in claim.citations]
    assert [claim.id for claim in hostile.observed] == ["O1", "O2", "O3"]


def test_the_default_answer_reads_the_real_prompt(client: httpx.Client) -> None:
    """`ai.prompt.render` sends the items array (not a context object) and names the task in
    the user turn: the mock still cites the items, with a timeline for summarize_pcap."""
    ctx = make_context(
        items=(
            (RefKind.FINDING, {"title": "Beacon to 203.0.113.50", "severity": "high"}),
            (RefKind.TIMELINE, {"title": "Beacon from INT_IP_1", "ts": "2026-01-01T00:00:50Z"}),
        )
    )
    parts = render(ctx, AiTask.SUMMARIZE_PCAP, delimiter="e" * 32, canary=CANARY)
    body = {**_request(), "system": parts.system, "user": parts.user}
    output = AnalysisOutput.model_validate(client.post("/v1/analyze", json=body).json()["output"])
    assert [c.citations[0].ref for c in output.observed] == ["F1", "E1"]
    assert [e.citations[0].ref for e in output.timeline] == ["E1"]


def test_rate_limited_once_per_marker(client: httpx.Client) -> None:
    first = client.post("/v1/analyze", json=_marked("ai-mock:429-once-abc1"))
    assert first.status_code == 429 and first.headers["Retry-After"] == "1"
    again = client.post("/v1/analyze", json=_marked("ai-mock:429-once-abc1"))
    assert again.status_code == 200
    AnalysisOutput.model_validate(again.json()["output"])
    other = client.post("/v1/analyze", json=_marked("ai-mock:429-once-abc2"))
    assert other.status_code == 429
    client.post("/_reset")
    assert client.post("/v1/analyze", json=_marked("ai-mock:429-once-abc1")).status_code == 429


def test_slow_markers_answer_late(client: httpx.Client) -> None:
    start = time.monotonic()
    slow = client.post("/v1/analyze", json=_marked("ai-mock:slow"))
    assert time.monotonic() - start >= 0.3  # AI_MOCK_SLOW_S (0.3 s here)
    AnalysisOutput.model_validate(slow.json()["output"])
    start = time.monotonic()
    client.post("/v1/analyze", json=_marked("ai-mock:slow-1"))
    assert time.monotonic() - start >= 1.0


def test_last_request_and_counters(client: httpx.Client) -> None:
    body = _marked("ai-mock:429")
    client.post("/v1/analyze", json=body)
    client.post("/v1/analyze", json=body)
    client.post("/v1/analyze", json=_request())
    last = client.get("/_last").json()
    assert last["path"] == "/v1/analyze"
    assert last["body"] == _request()
    assert last["truncated"] is False
    assert last["counters"] == {"429": 2, "default": 1}
    # Bounded to 1 MiB in memory.
    big = _request()
    big["user"] += "x" * (1024 * 1024)
    client.post("/v1/analyze", json=big)
    last = client.get("/_last").json()
    assert last["truncated"] is True and last["body"] is None
    client.post("/_reset")
    assert client.get("/_last").json() == {
        "path": None,
        "body": None,
        "truncated": False,
        "counters": {},
    }


def test_the_first_known_marker_wins(mock: ModuleType) -> None:
    assert mock.marker("ai-mock:unknown then ai-mock:529 and ai-mock:429") == "529"
    assert mock.marker("ai-mock:429-nora") == "429-nora"
    assert mock.marker("ai-mock:slow-12") == "slow-12"
    assert mock.marker("nothing here") is None
