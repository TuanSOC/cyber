"""The `labels.json` schema of the RE sample set (M10 phase 4), checked by `check_labels`.

Top level: one entry per sample file plus three reserved keys:
- `_meta`: `{"version": 1, "seed": int, "caveat": str}`;
- `_skipped`: build name -> reason (a missing compiler / binutils / M3 source);
- `_injections`: `{"version": 1, "payloads": {id: {"text", "description"}},
  "twins": {twin sample: {"clean": unstripped clean build, "plants": [{"field", "function",
  "payload"}]}}}` (the M3 `_injections` shape).

A sample entry (`kind` = `build` | `twin` | `edge_case`):
- always: `kind`, `format` (`pe` | `elf`), `arch` (`x86` | `x86_64`), `stripped`, `file`,
  `size_bytes`, `sha256`, `expected_findings`, `expected_iocs`;
- `build` / `twin` also: `source`, `target`, `opt` (`O0` | `O2`), `pie`, `dll`, `truth` (the
  truth file of the unstripped build), `unstripped`, `expected_functions` (`all`,
  `non_library`), `edges`, `string_refs`, `import_refs`, `compiler`; a twin has `twin_of`;
- `edge_case`: `truth` is null and `expect` is `clean_end` (no function truth).
`expected_findings` items: `method`, `type`, `severity`, `function` (+ `inlined_from` when
-O2 inlined the annotated function); `expected_iocs` items: `type`, `value`.
"""

from typing import Any

RESERVED = frozenset({"_meta", "_skipped", "_injections"})
COMMON = frozenset(
    {"kind", "format", "arch", "stripped", "file", "size_bytes", "sha256", "expected_findings",
     "expected_iocs"}
)  # fmt: skip
BUILD = COMMON | {
    "source", "target", "opt", "pie", "dll", "truth", "unstripped", "expected_functions",
    "edges", "string_refs", "import_refs", "compiler",
}  # fmt: skip
EDGE = COMMON | {"truth", "expect"}
FINDING_KEYS = frozenset({"method", "type", "severity", "function"})
METHODS = frozenset(
    {
        "heuristic:re_api_set_function@1",
        "heuristic:re_runtime_api_resolution@1",
        "heuristic:re_network_string_function@1",
    }
)


def _problems(name: str, label: dict[str, Any]) -> list[str]:
    kind = label.get("kind")
    required = {"build": BUILD, "twin": BUILD | {"twin_of"}, "edge_case": EDGE}.get(str(kind))
    if required is None:
        return [f"{name}: unknown kind {kind!r}"]
    problems = [f"{name}: missing {key}" for key in sorted(required - set(label))]
    if label.get("format") not in {"pe", "elf"}:
        problems.append(f"{name}: format")
    if label.get("arch") not in {"x86", "x86_64"}:
        problems.append(f"{name}: arch")
    for finding in label.get("expected_findings", []):
        if not FINDING_KEYS <= set(finding) or finding["method"] not in METHODS:
            problems.append(f"{name}: finding {finding}")
        elif finding["severity"] not in {"info", "low", "medium"}:
            problems.append(f"{name}: severity above medium {finding}")
    for ioc in label.get("expected_iocs", []):
        if set(ioc) != {"type", "value"} or ioc["type"] not in {"url", "domain", "ip"}:
            problems.append(f"{name}: ioc {ioc}")
    if kind == "edge_case":
        if label.get("truth") is not None or label.get("expect") != "clean_end":
            problems.append(f"{name}: an edge case has no truth and must end cleanly")
    elif not problems:
        if label["opt"] not in {"O0", "O2"}:
            problems.append(f"{name}: opt")
        counts = label["expected_functions"]
        if not 0 <= counts["non_library"] <= counts["all"]:
            problems.append(f"{name}: function counts")
    return problems


def check_labels(labels: dict[str, Any]) -> None:
    """Raise ValueError naming every problem of a generated labels mapping."""
    problems: list[str] = []
    for key in sorted(RESERVED - set(labels)):
        problems.append(f"missing {key}")
    meta = labels.get("_meta", {})
    if meta.get("version") != 1 or not meta.get("caveat"):
        problems.append("_meta")
    injections = labels.get("_injections", {})
    for twin, record in injections.get("twins", {}).items():
        if twin not in labels or labels[twin].get("kind") != "twin":
            problems.append(f"_injections: unknown twin {twin}")
        elif record.get("clean") not in labels:
            problems.append(f"_injections: {twin} copies an unknown sample")
        for plant in record.get("plants", []):
            if plant.get("payload") not in injections.get("payloads", {}):
                problems.append(f"_injections: {twin} plants an unknown payload")
    for name, label in labels.items():
        if name not in RESERVED:
            problems += _problems(name, label)
    if problems:
        raise ValueError("; ".join(problems))
