"""`explain_function` context rules (M10 phase 9): the G / Q allowlists and renderers, the
`Q.code` exception (12 000 characters at a line boundary, RT16 literal / identifier cuts,
value transforms inside literals and comments only), the stats counters, and the structural
proof that no task but `explain_function` ever reads decompiled code."""

import ast
import json
import uuid
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import cyberlab_jobs
from cyberlab_jobs.reverse import RE_LINE_ADAPTER, ReDecompiledRecord

from app.modules.ai import text as aitext
from app.modules.ai.context import c_literals
from app.modules.ai.context import fields as F
from app.modules.ai.context.assemble import Selection, assemble
from app.modules.ai.context.fields import RawItem
from app.modules.ai.context.pseudonymize import Pseudonymizer, neutralize
from app.modules.ai.context.transform import ItemCounts, Transformer, truncate_lines
from app.modules.ai.contracts import AiScope, AiTask, RefKind, RunScope

API = Path(__file__).resolve().parents[2]
AI = API / "app" / "modules" / "ai"
FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "reverse"
JOB = uuid.UUID(int=10)
SCOPE = RunScope(scope=AiScope.JOB, job_ids=(JOB,))


def _fn(**over: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": uuid.UUID(int=1),
        "job_id": JOB,
        "entry": Decimal(0x1400011E0),
        "name": "inject_remote",
        "name_source": "symbol",
        "size": 320,
        "signature": "int inject_remote(ulong pid)",
        "is_thunk": False,
        "is_external": False,
        "is_library": True,
        "decompile_status": "ok",
    }
    base.update(over)
    return SimpleNamespace(**base)


def _code(code: str, **over: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": uuid.UUID(int=2),
        "job_id": JOB,
        "code_kind": "pseudo_c",
        "status": "ok",
        "code": code,
        "lines": code.count("\n") + 1,
        "truncated_bytes": 0,
    }
    base.update(over)
    return SimpleNamespace(**base)


def _fixture_codes() -> list[str]:
    codes = []
    for path in sorted(FIXTURES.glob("*.ndjson")):
        for raw in path.read_bytes().splitlines():
            line = RE_LINE_ADAPTER.validate_json(raw)
            if isinstance(line, ReDecompiledRecord) and line.code:
                codes.append(line.code)
    assert len(codes) >= 8
    return codes


# --- allowlists and renderers ---------------------------------------------------------------


def test_function_fields_are_allowlisted_and_lists_are_indexed_and_capped() -> None:
    fields = F.function_fields(
        _fn(),
        callers=[f"caller_{n}" for n in range(30)],
        callees=["VirtualAllocEx"],
        imports=[f"KERNEL32.DLL!Api{n}" for n in range(40)],
        strings=["x" * 400, "http://203.0.113.10/gate.php"],
        capabilities=["inject thread"],
        code_note=None,
    )
    assert all(F.is_allowed(RefKind.FUNCTION, name) for name in fields)
    assert fields["entry"] == "0x1400011e0" and fields["flags"] == "library"
    assert sum(1 for n in fields if n.startswith("callers.")) == F.MAX_FUNCTION_CALLERS
    assert sum(1 for n in fields if n.startswith("imports_called.")) == F.MAX_FUNCTION_IMPORTS
    assert fields["callers.01"] == "caller_0" and "callers.21" not in fields
    assert len(str(fields["strings.01"])) == F.MAX_FUNCTION_STRING_CHARS
    assert "code_note" not in fields  # empty values are never sent (never citable)


def test_code_fields_are_allowlisted() -> None:
    fields = F.code_fields(_code("int f(void)\n{\n  return 0;\n}", truncated_bytes=10))
    assert set(fields) == {"code_kind", "status", "code", "lines", "truncated"}
    assert all(F.is_allowed(RefKind.CODE, name) for name in fields)
    assert fields["truncated"] is True


def test_function_and_code_fields_are_credential_free_and_structural_where_expected() -> None:
    for kind in (RefKind.FUNCTION, RefKind.CODE):
        for name in F.ALLOWED[kind]:
            assert not any(m in name for m in F.CREDENTIAL_MARKERS), name
    assert F.is_structural(RefKind.FUNCTION, "entry")
    assert not F.is_structural(RefKind.FUNCTION, "name")  # attacker text: pseudonymized
    assert not F.is_structural(RefKind.FUNCTION, "strings.01")
    assert not F.is_structural(RefKind.CODE, "code")  # handled by Transformer.code


def test_import_labels() -> None:
    assert F.import_label("WS2_32.DLL", None, 4) == "WS2_32.DLL!#4"
    assert F.import_label("KERNEL32.DLL", "VirtualAllocEx", None) == "KERNEL32.DLL!VirtualAllocEx"


# --- the Q.code transforms --------------------------------------------------------------------


def _transform(code: str, *, max_code_chars: int = 12_000) -> tuple[str, ItemCounts]:
    counts = ItemCounts()
    out = Transformer(Pseudonymizer(), max_code_chars=max_code_chars).code(code, counts)
    return out, counts


def test_code_tokens_are_never_rewritten_as_domains_or_hosts() -> None:
    code = (
        "void f(struct cfg local_10)\n{\n"
        "  h = kernel32.dll;\n  local_10.field = cfg.local;\n  x = ctx.internal;\n"
        '  connect("http://srv01.corp/x?k=v", "10.1.2.3", "C:\\\\Users\\\\alice\\\\a.txt");\n'
        "  /* see evil.example */\n}"
    )
    out, counts = _transform(code)
    # Outside literals and comments: byte-identical.
    for token in ("kernel32.dll", "local_10.field = cfg.local", "ctx.internal"):
        assert token in out, token
    # Inside them: the M5 transforms (query value, internal host / IP / user, defang).
    assert "http://srv01.corp" not in out and "k=…" in out
    assert "10.1.2.3" not in out and "INT_IP_1" in out
    assert "alice" not in out
    assert "evil[.]example" in out
    assert counts.truncated == 0


def test_fixture_code_changes_only_inside_the_spans_the_transforms_own() -> None:
    """Over every phase-1 fixture's code: code and identifier spans come out exactly as
    sanitized and neutralized; only literals and comments get the value transforms."""
    for code in _fixture_codes():
        cut = c_literals.cut(code)
        out, _ = _transform(code)
        expected = []
        for segment in cut.segments:
            clean = aitext.nfc(aitext.sanitize(segment.text)[0])
            clean = neutralize(clean)[0]
            expected.append((segment.kind, clean))
        rebuilt = "".join(text for _, text in expected)
        if rebuilt == out:
            continue
        # Literal / comment segments may differ; every code segment must appear verbatim.
        position = 0
        for kind, text in expected:
            if kind in c_literals.TEXT_KINDS or not text:
                continue
            found = out.find(text, position)
            assert found >= 0, (kind, text)
            position = found + len(text)


def test_code_is_cut_at_a_line_boundary_with_the_marker() -> None:
    code = "\n".join(f"  local_{n:05d} = local_{n:05d} ^ 0x5a;" for n in range(1_000))
    out, counts = _transform(code)
    assert len(code) > 12_000
    body, _, marker = out.rpartition("\n")
    assert marker.startswith("…[truncated ") and len(body) <= 12_000
    assert body == code[: len(body)] and code[len(body)] == "\n"
    assert counts.truncated == 1
    assert truncate_lines("x" * 50, 20) == "x" * 20 + "\n…[truncated 30]"


def test_rt16_cuts_are_counted_in_the_context_stats() -> None:
    long_name = "a" * 255
    code = f'void {long_name}(void)\n{{\n  puts("{"B" * 200}");\n  {long_name}();\n}}'
    items = [
        RawItem(RefKind.FUNCTION, "re_functions", "1", JOB, F.function_fields(_fn(name=long_name))),
        RawItem(RefKind.CODE, "re_decompilations", "2", JOB, F.code_fields(_code(code))),
    ]
    ctx = assemble(
        AiTask.EXPLAIN_FUNCTION,
        SCOPE,
        [Selection(RefKind.FUNCTION, items[:1], 1), Selection(RefKind.CODE, items[1:], 1)],
        Pseudonymizer(),
        budget_tokens=50_000,
    )
    assert ctx.stats.code_literals_truncated == 1
    assert ctx.stats.code_identifiers_truncated == 2
    sent = ctx.items[1].fields["code"]
    assert isinstance(sent, str) and "B" * 97 not in sent and "a" * 65 not in sent
    # Every other G / Q string keeps the 256-character cap (the name fits exactly).
    assert ctx.items[0].fields["name"] == long_name


def test_the_code_cap_follows_the_setting() -> None:
    code = "\n".join("x = 1;" for _ in range(200))
    items = [RawItem(RefKind.CODE, "re_decompilations", "2", JOB, F.code_fields(_code(code)))]
    ctx = assemble(
        AiTask.EXPLAIN_FUNCTION,
        SCOPE,
        [Selection(RefKind.CODE, items, 1)],
        Pseudonymizer(),
        budget_tokens=50_000,
        max_code_chars=256,
    )
    sent = str(ctx.items[0].fields["code"])
    assert sent.endswith("]") and len(sent.rpartition("\n")[0]) <= 256
    assert ctx.stats.truncated_fields == {RefKind.CODE: 1}


# --- nothing but explain_function reads decompiled code --------------------------------------


def _functions_referencing(path: Path, name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node)) or any(
                isinstance(n, ast.Attribute) and n.attr == name for n in ast.walk(node)
            ):
                found.add(node.name)
    return found


def test_only_the_function_selector_reads_decompilations_in_the_context_package() -> None:
    for path in sorted((AI / "context").glob("*.py")):
        users = _functions_referencing(path, "ReDecompilation") | _functions_referencing(
            path, "code_fields"
        )
        if path.name == "select.py":
            assert users == {"select_function_items"}, users
        elif path.name == "fields.py":
            assert users == {"code_fields"} or users == set(), users
        else:
            assert users == set(), (path.name, users)


def test_only_explain_function_routes_to_the_function_selector() -> None:
    tree = ast.parse((AI / "context" / "builder.py").read_text(encoding="utf-8"))
    callers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for n in ast.walk(node):
                if isinstance(n, ast.Attribute) and n.attr == "select_function_items":
                    callers.add(node.name)
    assert callers == {"_job_selections"}
    source = (AI / "context" / "builder.py").read_text(encoding="utf-8")
    branch = source[source.index("if task is AiTask.EXPLAIN_FUNCTION") :]
    assert branch.index("select_function_items") < branch.index("\n    if ")


def test_no_other_module_selects_the_code_column() -> None:
    """Deep links and report citations read ids, entries and hashes of decompilations, never
    the code (`ReDecompilation.code` / `d.code`)."""
    for path in (AI / "service_outputs.py", API / "app" / "modules" / "reports" / "citations.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = {"ReDecompilation"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple):
                for target, value in zip(
                    getattr(node.targets[0], "elts", []), node.value.elts, strict=False
                ):
                    if isinstance(value, ast.Name) and value.id == "ReDecompilation":
                        aliases.add(getattr(target, "id", ""))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "code":
                assert not (isinstance(node.value, ast.Name) and node.value.id in aliases), path
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "select":
                for arg in node.args:
                    assert not (isinstance(arg, ast.Name) and arg.id in aliases), path


def test_the_job_digest_of_a_reverse_job_has_no_function_or_code_selector() -> None:
    source = (AI / "context" / "builder.py").read_text(encoding="utf-8")
    start = source.index("async def _re_digest(")
    body = source[start : source.index("\nasync def ", start + 1)]
    assert "select_function_items" not in body and "code" not in body.split('"""')[-1]


def test_context_stats_carry_the_code_counters_only_as_counts() -> None:
    stats = json.loads(
        assemble(
            AiTask.EXPLAIN_FUNCTION,
            SCOPE,
            [
                Selection(
                    RefKind.FUNCTION,
                    [RawItem(RefKind.FUNCTION, "re_functions", "1", JOB, F.function_fields(_fn()))],
                    1,
                )
            ],
            Pseudonymizer(),
            budget_tokens=10_000,
        ).stats.model_dump_json()
    )
    assert stats["code_literals_truncated"] == 0 and stats["code_identifiers_truncated"] == 0


# --- deep links ---------------------------------------------------------------------------------


def test_g_and_q_citations_link_to_the_function_of_the_re_job_page() -> None:
    from app.modules.ai.models import AiCitation
    from app.modules.ai.service_outputs import LinkContext, deep_link

    job, row = uuid.uuid4(), str(uuid.uuid4())
    links = LinkContext({job: "reverse"}, {}, {row: "0x1400011e0"})
    for kind, tab in (("function", "facts"), ("code", "code")):
        link = deep_link(AiCitation(status="verified", kind=kind, ref_id=row, job_id=job), links)
        assert link is not None
        assert (link.route, link.job_id, link.tab, link.ref) == (
            "reverse-engineering",
            job,
            tab,
            "0x1400011e0",
        )
    # No entry looked up (a missing row) or not verified: no link.
    missing = AiCitation(status="verified", kind="code", ref_id=str(uuid.uuid4()), job_id=job)
    assert deep_link(missing, links) is None
    unverified = AiCitation(status="unverified", kind="function", ref_id=row, job_id=job)
    assert deep_link(unverified, links) is None
    # A G item of a job that is not a reverse job gets no link.
    assert deep_link(
        AiCitation(status="verified", kind="function", ref_id=row, job_id=job),
        LinkContext({job: "static"}, {}, {row: "0x1"}),
    ) is None
