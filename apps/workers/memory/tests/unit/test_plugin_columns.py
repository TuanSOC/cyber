"""Column drift (RT4): the `TreeGrid` columns of every allow-listed plugin, read from the
INSTALLED volatility3 source (AST of `run()`, never imported or executed), equal our row
model's columns and the replay fixtures' keys. This is the only guard for the Windows
plugins, which no test executes. Skipped where volatility3 is not installed (host)."""

import ast
import importlib.util
import json
from pathlib import Path

import pytest
from cyberlab_jobs.memory import MemoryPlugin

from memory_worker.normalize.models import COLUMNS, RESERVED
from memory_worker.probe.plugins import PLUGINS
from tests.replay_helpers import VOL_ROWS

# f-string columns, rendered with our fixed options (`physical` false).
FSTRING_COLUMNS = {"Offset{offsettype}": "Offset(V)"}
# Columns defined as a class attribute of another module: (file, class, attribute).
EXTERNAL = {
    "ModuleDisplayPlugin.columns_results": (
        "framework/symbols/linux/utilities/modules.py",
        "ModuleDisplayPlugin",
        "columns_results",
    )
}


def _volatility_root() -> Path | None:
    spec = importlib.util.find_spec("volatility3")
    if spec is None or not spec.submodule_search_locations:
        return None
    return Path(next(iter(spec.submodule_search_locations)))


ROOT = _volatility_root()
needs_source = pytest.mark.skipif(ROOT is None, reason="volatility3 is not installed here")


def _expr(value: ast.expr) -> str:
    return ast.unparse(value.value) if isinstance(value, ast.FormattedValue) else ""


def _column_names(node: ast.expr, scope: list[ast.stmt], root: Path) -> list[str]:
    if isinstance(node, ast.List | ast.Tuple):
        names = []
        for item in node.elts:
            assert isinstance(item, ast.Tuple), ast.dump(item)
            first = item.elts[0]
            if isinstance(first, ast.Constant):
                names.append(str(first.value))
            else:
                assert isinstance(first, ast.JoinedStr)
                pattern = "".join(
                    str(v.value) if isinstance(v, ast.Constant) else "{" + _expr(v) + "}"
                    for v in first.values
                )
                names.append(FSTRING_COLUMNS[pattern])
        return names
    if isinstance(node, ast.Name):
        assigned = [
            s.value
            for s in ast.walk(ast.Module(body=scope, type_ignores=[]))
            if isinstance(s, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == node.id for t in s.targets)
        ]
        assert assigned, f"no assignment of {node.id}"
        return _column_names(assigned[-1], scope, root)
    if isinstance(node, ast.Attribute):
        text = ast.unparse(node)
        path, cls, attr = EXTERNAL[next(k for k in EXTERNAL if text.endswith(k))]
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        klass = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls)
        value = next(
            s.value
            for s in klass.body
            if isinstance(s, ast.Assign) and any(getattr(t, "id", "") == attr for t in s.targets)
        )
        return _column_names(value, klass.body, root)
    raise AssertionError(f"unexpected TreeGrid column expression {ast.dump(node)}")


def source_columns(plugin: MemoryPlugin) -> list[str]:
    assert ROOT is not None
    module, cls = PLUGINS[plugin].class_path.rsplit(".", 1)
    path = ROOT / "framework" / "plugins" / (module.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    klass = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls)
    run = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    call = next(
        n
        for n in ast.walk(run)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith("TreeGrid")
    )
    return _column_names(call.args[0], run.body, ROOT)


@needs_source
@pytest.mark.parametrize("plugin", list(MemoryPlugin), ids=lambda p: p.value)
def test_model_columns_equal_the_installed_source(plugin: MemoryPlugin) -> None:
    assert list(COLUMNS[plugin]) == source_columns(plugin)


@pytest.mark.parametrize("plugin", list(MemoryPlugin), ids=lambda p: p.value)
def test_fixture_rows_use_exactly_those_columns(plugin: MemoryPlugin) -> None:
    files = sorted(VOL_ROWS.glob(f"*/{plugin.value}.jsonl"))
    assert files, f"no replay fixture for {plugin.value}"
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            assert set(row) - RESERVED == set(COLUMNS[plugin]), path


def source_requirements(plugin: MemoryPlugin) -> set[str]:
    """The `name=` of every requirement in the plugin class's `get_requirements`."""
    assert ROOT is not None
    module, cls = PLUGINS[plugin].class_path.rsplit(".", 1)
    path = ROOT / "framework" / "plugins" / (module.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    klass = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls)
    method = next(
        n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == "get_requirements"
    )
    return {
        str(k.value.value)
        for n in ast.walk(method)
        if isinstance(n, ast.Call)
        for k in n.keywords
        if k.arg == "name" and isinstance(k.value, ast.Constant)
    }


@needs_source
@pytest.mark.parametrize("plugin", list(MemoryPlugin), ids=lambda p: p.value)
def test_fixed_options_are_real_requirements(plugin: MemoryPlugin) -> None:
    """A misspelt option would silently keep Volatility's default (e.g. a dump switch)."""
    assert set(PLUGINS[plugin].options) <= source_requirements(plugin)
