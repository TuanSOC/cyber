"""`heuristic:re_api_set_function@1` (M10 phase 5, RT7): every M3 set and combination fires
within one function and only there, with the M3 data and semantics (`cyberlab_worker.apisets`),
through thunks and normalized import names, with the run-key pseudo-API from a referenced
string; never on thunks, externals or library code; capped at `medium`."""

import pytest
from cyberlab_worker.apisets import API_SETS, RUN_KEY_FLAG, ApiSet

from dataset.generate import LIMITS, RUN_KEY, Builder
from re_worker import detections
from re_worker.detections import KNOWN_APIS
from re_worker.detections.apisets import matches
from re_worker.detections.base import METHOD_API_SET, api_name


def _combination_apis(api_set: ApiSet, combo: frozenset[str]) -> list[str]:
    """One API per group of the combination (the run-key group becomes a string)."""
    return [sorted(api_set.groups[g])[0] for g in sorted(combo)]


def _view_with(apis: list[str]) -> Builder:
    b = Builder()
    b.fn("main", 0x40)
    b.fn("worker", 0x100)
    b.call("main", "worker")
    for api in apis:
        if api == RUN_KEY_FLAG:
            b.string(RUN_KEY, "worker")
        else:
            b.imp(api, "worker")
    return b


CASES = [
    (api_set, combo) for api_set in API_SETS for combo in api_set.any_of
]


@pytest.mark.parametrize(
    ("api_set", "combo"), CASES, ids=[f"{s.type}-{'+'.join(sorted(c))}" for s, c in CASES]
)
def test_every_combination_fires_in_one_function(api_set: ApiSet, combo: frozenset[str]) -> None:
    b = _view_with(_combination_apis(api_set, combo))
    out = detections.run(b.view(), LIMITS)
    hits = [f for f in out.findings if f.type == api_set.type]
    assert len(hits) == 1, [f.type for f in out.findings]
    finding = hits[0]
    assert finding.detection_method == METHOD_API_SET
    assert finding.attributes["function_entry"] == f"0x{b.entry('worker'):x}"
    assert finding.attributes["set"] == api_set.type
    assert finding.severity == (api_set.severity if api_set.severity != "high" else "medium")
    assert set(finding.attributes["groups"].split(", ")) >= set(combo)


@pytest.mark.parametrize(
    ("api_set", "combo"), CASES, ids=[f"{s.type}-{'+'.join(sorted(c))}" for s, c in CASES]
)
def test_one_group_short_never_fires(api_set: ApiSet, combo: frozenset[str]) -> None:
    for dropped in combo:
        apis = _combination_apis(api_set, frozenset(combo - {dropped}))
        names = frozenset(a for a in apis)
        if matches(api_set, names) is not None:  # another combination of the set still holds
            continue
        out = detections.run(_view_with(apis).view(), LIMITS)
        assert [f for f in out.findings if f.type == api_set.type] == [], (combo, dropped)


def test_split_across_two_functions_never_fires() -> None:
    b = Builder()
    b.fn("a", 0x40)
    b.fn("b", 0x40)
    b.imp("VirtualAllocEx", "a")
    b.imp("WriteProcessMemory", "a")
    b.imp("CreateRemoteThread", "b")
    assert detections.run(b.view(), LIMITS).findings == []


def test_thunks_and_decorated_names_count() -> None:
    b = Builder()
    b.fn("worker", 0x100)
    b.thunk("VirtualAllocEx", "worker")
    b.fn("__imp_WriteProcessMemory", 0x8, source="import", external=True)
    b.call("worker", "__imp_WriteProcessMemory")
    b.imp("_CreateRemoteThread@28", "worker")
    out = detections.run(b.view(), LIMITS)
    assert [f.type for f in out.findings] == ["api_injection"]
    assert out.findings[0].attributes["function_name"] == "worker"


def test_thunks_externals_and_library_code_are_never_cited() -> None:
    b = Builder()
    b.fn("lib", 0x100, source="fid_library", library=True)
    for api in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"):
        b.imp(api, "lib")
    b.fn("thunky", 0x10, thunk=True)
    for api in ("SetWindowsHookExW", "GetAsyncKeyState"):
        b.imp(api, "thunky")
    assert detections.run(b.view(), LIMITS).findings == []


def test_run_key_must_be_referenced_by_the_same_function() -> None:
    b = _view_with(["RegSetValueExW"])
    b.fn("other", 0x20)
    b.string(RUN_KEY, "other")
    assert detections.run(b.view(), LIMITS).findings == []
    b = _view_with(["RegSetValueExW", RUN_KEY_FLAG])
    [finding] = detections.run(b.view(), LIMITS).findings
    assert finding.type == "api_persistence" and "Run-key registry path" in finding.description


@pytest.mark.parametrize(
    ("raw", "plain"),
    [
        ("__imp_VirtualAllocEx", "VirtualAllocEx"),
        ("__imp__CreateRemoteThread@28", "CreateRemoteThread"),
        ("sym.imp.KERNEL32.dll_WriteProcessMemory", "WriteProcessMemory"),
        ("connect@plt", "connect"),
        ("_IsDebuggerPresent@0", "IsDebuggerPresent"),
        ("_private_helper", "_private_helper"),
    ],
)
def test_api_name_normalization(raw: str, plain: str) -> None:
    assert api_name(raw, KNOWN_APIS) == plain
