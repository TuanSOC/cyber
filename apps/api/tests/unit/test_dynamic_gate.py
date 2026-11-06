"""Gate (M7 phase 7): dynamic analysis is designed, NOT wired. docs/SANDBOX_SECURITY.md lists
what must pass before anyone enables it; until then this test fails on any wiring:

- `Analyzer` has no `dynamic` value; no Celery queue, task name, default queue or beat entry
  names `dynamic` / `sandbox`; no API route path contains `dynamic`;
- `DYNAMIC_ENABLED is False`; `cyberlab_jobs` does not export the module, and importing the
  API and every Celery app never imports `cyberlab_jobs.dynamic`;
- the broker entrypoint defines no `dynamic` / `sandbox` ACL user; no compose service is
  named `*sandbox*` / `*dynamic*` in any compose file (every profile) nor, when the docker
  CLI is available, in the rendered dev and prod configs (`check-*-env.mjs`'s parse step).

The broker and compose checks read repository files that api-test does not mount (it mounts
`apps/api`, `packages/py-jobs` and `scripts` only). They look in `CYBERLAB_REPO_ROOT`, then
the test file's parents, then `/srv/repo`, and are skipped when none holds the files. On the
host they run without the app (stdlib, pytest and PyYAML only):

    PYTHONPATH=packages/py-jobs/src python -m pytest --noconftest -q -p no:cacheprovider \\
        apps/api/tests/unit/test_dynamic_gate.py -k "broker or compose or enabled or export"
"""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

WORDS = re.compile(r"dynamic|sandbox", re.IGNORECASE)
API_ROOT = Path(__file__).resolve().parents[2]
CELERY_APPS = (
    "app.workers.celery_app",
    "app.workers.enrich_app",
    "app.workers.analyst_app",
    "app.workers.retention_app",
)


def _repo_root() -> Path | None:
    candidates = [Path(p) for p in [os.environ.get("CYBERLAB_REPO_ROOT", "")] if p]
    candidates += list(Path(__file__).resolve().parents) + [Path("/srv/repo")]
    for root in candidates:
        if (root / "docker-compose.yml").is_file() and (
            root / "infra/redis-broker/entrypoint.sh"
        ).is_file():
            return root
    return None


REPO = _repo_root()
needs_repo = pytest.mark.skipif(
    REPO is None,
    reason="repository files not mounted (set CYBERLAB_REPO_ROOT or mount the repo at /srv/repo)",
)


# --- code: enum, queues, tasks, routes ---------------------------------------------------


def test_analyzer_has_no_dynamic_value() -> None:
    from app.modules.analysis.models import Analyzer

    # M8 adds `memory` (an offline, untrusted analyzer that never executes anything).
    assert {a.value for a in Analyzer} == {"pcap", "static", "memory"}
    assert not [a for a in Analyzer if WORDS.search(a.name) or WORDS.search(a.value)]


def test_no_shared_queue_or_task_name_is_dynamic() -> None:
    from cyberlab_jobs import Queues, tasks

    names = [v for k, v in vars(tasks).items() if k.isupper() and isinstance(v, str)]
    assert len(names) >= 10  # the scan sees the real constants
    queue_props = [k for k, v in vars(Queues).items() if isinstance(v, property)]
    queues = [getattr(Queues(prefix), prop) for prop in queue_props for prefix in ("", "test.")]
    assert "dynamic" not in queue_props and "sandbox" not in queue_props
    assert [n for n in names + queues if WORDS.search(n)] == []


@pytest.mark.parametrize("module", CELERY_APPS)
def test_no_celery_app_routes_or_registers_dynamic(module: str) -> None:
    celery_app = __import__(module, fromlist=["celery_app"]).celery_app
    celery_app.loader.import_default_modules()
    conf = celery_app.conf
    seen = [*celery_app.tasks.keys(), str(conf.task_default_queue)]
    for entry in (conf.beat_schedule or {}).values():
        seen += [str(entry["task"]), str(entry.get("options", {}).get("queue", ""))]
    seen += [str(route) for route in (conf.task_routes or {})]
    seen += [str(getattr(q, "name", q)) for q in (conf.task_queues or [])]
    assert conf.task_default_queue and any(not n.startswith("celery.") for n in celery_app.tasks)
    assert [name for name in seen if WORDS.search(name)] == []


def test_no_route_path_contains_dynamic() -> None:
    from app.main import create_app

    app = create_app()
    paths = [str(getattr(route, "path", "")) for route in app.routes]
    paths += list(app.openapi()["paths"])
    assert any("/analyses" in p for p in paths)
    assert [p for p in paths if "dynamic" in p.lower()] == []


# --- code: the kill switch and the module stays unimported --------------------------------


def _imports_of(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            found += [base] + [f"{base}.{alias.name}" for alias in node.names]
    return found


def test_dynamic_is_not_enabled() -> None:
    from cyberlab_jobs import dynamic

    assert dynamic.DYNAMIC_ENABLED is False
    assert dynamic.DYNAMIC_SCHEMA == "dynamic.v1"


def test_cyberlab_jobs_does_not_export_the_module() -> None:
    import cyberlab_jobs
    from cyberlab_jobs import dynamic

    exported = set(cyberlab_jobs.__all__)
    assert "dynamic" not in exported
    assert exported.isdisjoint(dynamic.__all__)
    imported = _imports_of(Path(cyberlab_jobs.__file__))
    assert [m for m in imported if "dynamic" in m] == []


def test_no_api_or_contract_source_imports_the_module() -> None:
    import cyberlab_jobs

    sources = list((API_ROOT / "app").rglob("*.py"))
    sources += [p for p in Path(cyberlab_jobs.__file__).parent.glob("*.py") if p.stem != "dynamic"]
    if REPO is not None:
        sources += list((REPO / "apps/workers").rglob("*.py"))
        sources += list((REPO / "packages").rglob("src/**/*.py"))
    assert len(sources) > 50
    offenders = [
        str(path)
        for path in sources
        if path.stem != "dynamic"
        and any(name == "cyberlab_jobs.dynamic" for name in _imports_of(path))
    ]
    assert offenders == []


def test_importing_the_api_and_every_worker_app_never_loads_the_module() -> None:
    code = (
        "import sys, importlib\n"
        "import app.main\n"
        f"for m in {list(CELERY_APPS)!r}:\n"
        "    importlib.import_module(m).celery_app.loader.import_default_modules()\n"
        "assert 'cyberlab_jobs.dynamic' not in sys.modules, 'cyberlab_jobs.dynamic was imported'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=API_ROOT, timeout=120)


# --- infrastructure: broker ACL and compose ----------------------------------------------


@needs_repo
def test_broker_defines_no_dynamic_or_sandbox_user() -> None:
    assert REPO is not None
    text = (REPO / "infra/redis-broker/entrypoint.sh").read_text(encoding="utf-8")
    users = re.findall(r"^user\s+(\S+)", text, flags=re.MULTILINE)
    assert {"default", "api", "ingest", "pcap", "static"} <= set(users)  # the parse works
    assert [u for u in users if WORDS.search(u)] == []
    # No key pattern or helper for such a user either.
    assert not WORDS.search(text)


class _ComposeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Compose YAML with its custom tags (`!reset`, `!override`) read as plain values."""


def _any_tag(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _any_tag)


def _compose_files() -> list[Path]:
    assert REPO is not None
    return sorted(REPO.glob("docker-compose*.yml"))


@needs_repo
def test_no_compose_file_defines_a_dynamic_or_sandbox_service() -> None:
    files = _compose_files()
    assert {f.name for f in files} >= {"docker-compose.yml", "docker-compose.prod.yml"}
    services: dict[str, list[str]] = {}
    for path in files:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader)  # noqa: S506
        for name, spec in (doc.get("services") or {}).items():
            services.setdefault(name, []).append(path.name)
            spec = spec or {}
            for key in ("container_name", "hostname"):
                assert not WORDS.search(str(spec.get(key, ""))), f"{path.name} {name}.{key}"
            env = spec.get("environment") or {}
            keys = env if isinstance(env, dict) else [str(e).split("=", 1)[0] for e in env]
            assert [k for k in keys if WORDS.search(str(k))] == [], f"{path.name} {name}"
        assert [n for n in (doc.get("networks") or {}) if WORDS.search(n)] == [], path.name
    assert {"api", "ingest-worker", "static-worker"} <= set(services)  # the parse works
    assert [n for n in services if WORDS.search(n)] == []


def _render(*args: str) -> dict[str, Any]:
    assert REPO is not None
    out = subprocess.run(
        ["docker", "compose", *args, "config", "--format", "json"],
        check=True,
        cwd=REPO,
        capture_output=True,
        timeout=120,
    ).stdout
    rendered: dict[str, Any] = json.loads(out)
    return rendered


@needs_repo
@pytest.mark.skipif(shutil.which("docker") is None, reason="no docker CLI (api-test)")
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(("--profile", "test", "--profile", "e2e"), id="dev-test"),
        pytest.param(("-f", "docker-compose.yml", "-f", "docker-compose.prod.yml"), id="prod"),
    ],
)
def test_rendered_compose_has_no_dynamic_or_sandbox_service(args: tuple[str, ...]) -> None:
    config = _render(*args)
    services = config["services"]
    assert "api" in services
    assert [name for name in services if WORDS.search(name)] == []
    assert [name for name in config.get("networks", {}) if WORDS.search(name)] == []
