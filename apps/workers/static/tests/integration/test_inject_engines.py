"""`--inject` twins through the real analyzer: the planted payloads survive into the static
result (`strings`, FLOSS, IOCs), so the AI evaluation actually sees them.

Heavy (the probes, ClamAV, YARA and FLOSS): worker image only, like the rest of
`tests/integration`. The light checks of the generator itself live in
`tests/unit/test_inject.py`.
"""

import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from samples import inject
from samples.generate import STACK_STRING, TWIN_SUFFIX, generate
from tests.conftest import in_container
from tests.helpers import FAST, analyze

pytestmark = in_container
# Visible text each payload leaves for an ASCII / UTF-16LE `strings` pass. P4 is all Unicode
# tag characters after "ok", too short to be a string: by design it only reaches readers that
# decode the field (VersionInfo parsers), so it has no expectation here.
VISIBLE = {pid: text for pid, text in inject.PAYLOADS.items() if text.isascii()}
VISIBLE["P5"] = "naelc si elif siht"


@pytest.fixture(scope="module")
def twins() -> tuple[dict[str, Path], dict[str, Any]]:
    out = Path("/tmp/static-samples-inject")  # root-only scratch, as the sample_set fixture
    shutil.rmtree(out, ignore_errors=True)
    paths = generate(out, mingw=False, inject=True)
    labels = json.loads((out / "labels.json").read_text())
    return paths, labels["_injections"]["twins"]


def _strings(out: dict[str, Any], *encodings: str) -> list[str]:
    return [s.value for s in out.get("string", []) if s.encoding in encodings]


@pytest.mark.parametrize("name", ["benign_pe32", "benign_elf", "packed_like"])
def test_payloads_survive_into_strings(
    twins: tuple[dict[str, Path], dict[str, Any]], name: str
) -> None:
    paths, records = twins
    twin = name + TWIN_SUFFIX
    out = analyze(paths[twin])
    encoding = {"string.ascii": "ascii"}
    missing = []
    for plant in records[twin]["plants"]:
        visible = VISIBLE.get(plant["payload"])
        if visible is None:
            continue
        # VersionInfo values are UTF-16LE in the file: `strings` sees them as wide strings.
        wanted = encoding.get(plant["carrier"], "utf16le")
        if not any(visible in value for value in _strings(out, wanted)):
            missing.append((plant["payload"], plant["carrier"]))
    assert missing == [], _strings(out, "ascii", "utf16le")
    iocs = {i.value for i in out.get("ioc", [])}
    assert any("attacker.example" in value for value in iocs), iocs


def test_stack_payload_is_visible_through_floss_only(
    twins: tuple[dict[str, Path], dict[str, Any]],
) -> None:
    paths, _ = twins
    out = analyze(paths["stack_string" + TWIN_SUFFIX], engines=replace(FAST, floss_enabled=True))
    assert not {"floss_failed", "floss_timeout"} & set(out["header"].engine_errors)
    hidden = inject.PAYLOADS[inject.STACK]
    floss = _strings(out, "floss_stack", "floss_tight", "floss_decoded")
    assert hidden in floss and STACK_STRING in floss, floss
    assert not any(hidden in value for value in _strings(out, "ascii", "utf16le"))
