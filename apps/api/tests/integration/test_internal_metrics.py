"""`GET /internal/metrics` (M7 phase 5): off without a token (404), the bearer token is the
control (401), a proxied request is refused (403, defence in depth only, RT27) before the rate
limit, 60 / min in one global window (never keyed by the spoofable peer), `Cache-Control:
no-store`; valid Prometheus text over `job_outcomes` and the queue
gauges with fixed labels only and no tenant data; and the gateway never routes `/internal/*`.
"""

import os
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import get_settings
from app.main import app
from app.modules.ops import internal
from tests.factories import new_client, register
from tests.integration.seed import seed_tenant
from tests.integration.test_ops_metrics import job, tenant_of
from tests.ops_helpers import seed_job_outcomes
from tests.unit.test_prometheus_render import ALLOWED_VALUES, FAMILIES, parse

URL = "/internal/metrics"


def _use_token_file(path: Path | None) -> None:
    get_settings().metrics_token_file = None if path is None else str(path)
    internal.metrics_token.cache_clear()


@pytest.fixture
def token(tmp_path: Path) -> Iterator[str]:
    value = "test-metrics-token-" + uuid.uuid4().hex
    path = tmp_path / "metrics_token"
    path.write_text(value + "\n", encoding="utf-8")
    previous = get_settings().metrics_token_file
    _use_token_file(path)
    yield value
    get_settings().metrics_token_file = previous
    internal.metrics_token.cache_clear()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_off_without_a_token(tmp_path: Path) -> None:
    previous = get_settings().metrics_token_file
    try:
        _use_token_file(None)
        response = await new_client().get(URL, headers=_auth("anything"))
        assert response.status_code == 404
        assert response.headers["cache-control"] == "no-store"
        empty = tmp_path / "empty"
        empty.write_text("  \n", encoding="utf-8")
        _use_token_file(empty)
        assert (await new_client().get(URL, headers=_auth(""))).status_code == 404
        _use_token_file(tmp_path / "missing")
        assert (await new_client().get(URL, headers=_auth("x"))).status_code == 404
    finally:
        get_settings().metrics_token_file = previous
        internal.metrics_token.cache_clear()


async def test_the_bearer_token_is_required(token: str) -> None:
    client = new_client()
    for headers in (
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": f"Basic {token}"},
        {"Authorization": token},
        {"Authorization": f"Bearer {token}x"},
    ):
        response = await client.get(URL, headers=headers)
        assert response.status_code == 401, headers
        assert response.headers["cache-control"] == "no-store"
        assert token not in response.text
    assert (await client.get(URL, headers=_auth(token))).status_code == 200


@pytest.mark.parametrize(
    "header", [{"X-Forwarded-For": "203.0.113.9"}, {"Forwarded": "for=203.0.113.9"}]
)
async def test_a_proxied_request_is_refused(
    token: str, header: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(internal, "RATE_LIMIT_PER_MIN", 1)
    client = new_client()
    for auth in (_auth(token), {}, {"Authorization": "Bearer wrong"}):
        response = await client.get(URL, headers={**auth, **header})
        # 403 with or without the token: refused before the rate limit and the token check.
        assert response.status_code == 403, auth
        assert response.headers["cache-control"] == "no-store"
        assert "cyberlab_jobs" not in response.text
    # The refused requests took no slot of the window.
    assert (await client.get(URL, headers=_auth(token))).status_code == 200


async def test_rate_limited_in_one_global_window(
    token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert internal.RATE_LIMIT_PER_MIN == 60
    assert internal.RATE_LIMIT_KEY == "metrics:"
    monkeypatch.setattr(internal, "RATE_LIMIT_PER_MIN", 3)
    client = new_client("10.0.0.7")
    for _ in range(3):
        assert (await client.get(URL, headers={"Authorization": "Bearer wrong"})).status_code == 401
    # Wrong guesses count too: the limit comes before the token check.
    limited = await client.get(URL, headers=_auth(token))
    assert limited.status_code == 429
    assert limited.headers.get("retry-after")
    # The window is global: another peer address does not get a fresh one.
    assert (await new_client("10.0.0.8").get(URL, headers=_auth(token))).status_code == 429


async def test_serves_valid_prometheus_text_with_fixed_labels(
    token: str, owner_engine: AsyncEngine
) -> None:
    tenant = await seed_tenant("internal-metrics-secret-org")
    now = datetime.now(UTC)
    await seed_job_outcomes(
        owner_engine,
        [
            {"kind": "pcap", "status": "succeeded", "queue_ms": 100, "run_ms": 1000},
            {"kind": "pcap", "status": "succeeded", "queue_ms": 300, "run_ms": 3000},
            {
                "kind": "pcap",
                "status": "failed",
                "error_code": "unparseable_capture",
                "queue_ms": 200,
                "run_ms": 2000,
            },
            {"kind": "pcap", "status": "failed", "error_code": "never_started"},
            {
                "kind": "static",
                "subkind": "full",
                "status": "failed",
                "error_code": "zeek_failed_but_secret_code_x",
                "queue_ms": 5,
                "run_ms": 50,
            },
            # A subkind / status outside the fixed enums (only an owner can write one): labels
            # stay fixed.
            {"kind": "ai", "subkind": 'evil"\nprovider', "status": "Weird", "run_ms": 1},
            {
                "kind": "report",
                "subkind": "pdf",
                "status": "succeeded",
                "run_ms": 1,
                "finished_at": now - timedelta(hours=3),
            },
            {
                "kind": "ti",
                "subkind": "mock",
                "status": "completed",
                "finished_at": now - timedelta(days=8),
            },
        ],
    )
    response = await new_client().get(URL, headers=_auth(token))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    text = response.text
    families = parse(text)
    assert set(families) == set(FAMILIES)
    for name, samples in families.items():
        for _, labels, _ in samples:
            for label, label_value in labels.items():
                assert label_value in ALLOWED_VALUES[label], (name, label, label_value)

    def value(family: str, suffix: str = "", **labels: str) -> float | None:
        for sample, got, v in families[family]:
            if sample == family + suffix and got == labels:
                return v
        return None

    jobs = "cyberlab_jobs"
    assert value(jobs, kind="pcap", subkind="none", status="succeeded", window="1h") == 2
    assert value(jobs, kind="pcap", subkind="none", status="failed", window="7d") == 2
    assert value(jobs, kind="ai", subkind="other", status="other", window="1h") == 1
    assert value(jobs, kind="report", subkind="pdf", status="succeeded", window="1h") is None
    assert value(jobs, kind="report", subkind="pdf", status="succeeded", window="24h") == 1
    assert not [s for s in families[jobs] if s[1]["kind"] == "ti"]  # 8 days old: no window
    ratio = "cyberlab_job_failure_ratio"
    assert value(ratio, kind="pcap", subkind="none", window="24h") == 0.5
    parse_ok = "cyberlab_parse_success_ratio"
    assert value(parse_ok, kind="pcap", window="1h") == 2 / 3  # 2 / (2 + 1 parse)
    # The unknown code is `other`, not `parse`: no parse denominator, so no static ratio.
    assert value(parse_ok, kind="static", window="1h") is None
    classes = "cyberlab_job_failures_by_class"
    assert value(classes, kind="pcap", subkind="none", window="1h", **{"class": "parse"}) == 1
    assert value(classes, kind="pcap", subkind="none", window="1h", **{"class": "infra"}) == 1
    assert value(classes, kind="static", subkind="full", window="1h", **{"class": "other"}) == 1
    summary = {"kind": "pcap", "subkind": "none", "phase": "run", "window": "1h"}
    duration = "cyberlab_job_duration_seconds"
    assert value(duration, **summary, quantile="0.5") == 2.0
    assert value(duration, **summary, quantile="0.99") == pytest.approx(2.98)
    assert value(duration, "_count", **summary) == 3  # the never-started job has none
    assert value(duration, "_sum", **summary) == 6.0
    # Error codes are classified, never labels; nothing tenant-identifying is served.
    for absent in (
        "zeek_failed_but_secret_code_x",
        "unparseable_capture",
        "evil",
        "Weird",
        str(tenant.org_id),
        "internal-metrics-secret-org",
    ):
        assert absent not in text


async def test_active_gauges_from_the_index_tables(token: str) -> None:
    reg = await register(org_name="Gauge Org")
    t = await tenant_of(reg)
    await job(t, "pcap", "queued")
    await job(t, "pcap", "queued")
    await job(t, "static", "running", run_ms=1)
    families = parse((await new_client().get(URL, headers=_auth(token))).text)
    active = {(lb["kind"], lb["status"]): v for _, lb, v in families["cyberlab_jobs_active"]}
    assert active[("pcap", "queued")] == 2
    assert active[("static", "running")] == 1
    assert active[("ai", "waiting")] == 0 and active[("report", "running")] == 0


def test_not_in_the_api_schema_and_outside_api() -> None:
    paths = app.openapi()["paths"]
    assert URL in paths and set(paths[URL]) == {"get"}
    assert not [p for p in paths if p.startswith("/api") and "internal" in p]


# --- the gateway never routes /internal/* ----------------------------------------------------


def _caddy_dir() -> Path | None:
    candidates = [os.environ.get("CADDY_CONFIG_DIR"), "/srv/infra/caddy"]
    candidates.append(str(Path(__file__).resolve().parents[4] / "infra" / "caddy"))
    for candidate in candidates:
        if candidate and (Path(candidate) / "common.caddy").is_file():
            return Path(candidate)
    return None


def _braced(source: str, i: int) -> tuple[str, int]:
    """The body of the `{...}` block opening at `source[i]`, and the index after it."""
    assert source[i] == "{"
    depth = 0
    for j in range(i, len(source)):
        depth += {"{": 1, "}": -1}.get(source[j], 0)
        if depth == 0:
            return source[i + 1 : j], j + 1
    raise AssertionError("unterminated block")


def _top_level(block: str) -> list[tuple[str, str]]:
    """(directive line head, body) of every top-level directive with a block."""
    out, i = [], 0
    while (j := block.find("{", i)) >= 0:
        head = block[block.rfind("\n", 0, j) + 1 : j].strip()
        body, i = _braced(block, j)
        out.append((head, body))
    return out


def caddy_api_routes(caddy: Path) -> list[str]:
    """The matchers whose `handle` reverse-proxies to the api, from the shared route block;
    also checks that the site files proxy nothing themselves."""
    for site in ("Caddyfile", "Caddyfile.prod"):
        text = (caddy / site).read_text(encoding="utf-8")
        assert "import cyberlab_routes" in text and "reverse_proxy" not in text, site
    common = (caddy / "common.caddy").read_text(encoding="utf-8")
    routes, _ = _braced(common, common.index("{", common.index("(cyberlab_routes)")))
    directives = _top_level(routes)
    matchers = {head: body for head, body in directives if head.startswith("@")}
    to_api = []
    for head, body in directives:
        if not head.startswith("handle"):
            continue
        matcher = head.removeprefix("handle").strip()
        if "reverse_proxy api:" in body:
            to_api.append(matchers.get(matcher, matcher).strip())
        elif "reverse_proxy" in body:
            assert matcher == "", f"only the catch-all may proxy elsewhere: {matcher}"
            assert "reverse_proxy web:3000" in body
    return to_api


def test_the_gateway_never_routes_internal() -> None:
    caddy = _caddy_dir()
    if caddy is None:
        pytest.skip("infra/caddy is not mounted here (set CADDY_CONFIG_DIR)")
    routes = caddy_api_routes(caddy)
    assert routes, "no api route found: the parser no longer matches the Caddy file"
    for route in routes:
        # `/api/*` or a path_regexp anchored under /api/: never /internal.
        assert route == "/api/*" or re.search(r"path_regexp \^/api/", route), route
    for path in caddy.iterdir():
        assert "/internal" not in path.read_text(encoding="utf-8"), path.name
