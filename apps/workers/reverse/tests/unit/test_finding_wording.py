# ruff: noqa: E501 - long assertion lines
"""Findings describe observations, never verdicts (M2 / M3 rule; M10 phase 5): checked on
every template and on every finding the scenario set produces, including findings about
functions whose engine-supplied names are hostile (verdict words, injection payloads, a
255-character name, bidi and homoglyph characters): those appear only quoted, the text
around them stays neutral."""

import re
import string

import pytest

from dataset.generate import LIMITS, SCENARIOS, Builder, build
from re_worker import detections
from re_worker.detections.base import METHOD_MAX, SEVERITY_RANK, TEMPLATES
from samples import twins

# The M3 list (static test_detections.py) plus the M8 additions; "inject" stays allowed
# here: "process-injection" names an API set, the M3 wording.
VERDICT = re.compile(
    r"malicious|is malware|malware detected|\bvirus\b|infected|\b(?:malware|compromised?|"
    r"attacker|evil|backdoor|trojan|rootkit|hacked|exploit(?:ed)?|threat actor|ransomware|"
    r"confirmed)\b",
    re.I,
)
QUOTED = re.compile(r'"[^"]*"')
HOSTILE_NAMES = [
    "malicious_backdoor_trojan",
    twins.INJECT_EXPORT,
    twins.LONG_IDENT,
    twins.HOMOGLYPH,
    "x‮elif_live",
    'quote" is malware "',
]


@pytest.mark.parametrize("kind", sorted(TEMPLATES))
def test_templates_never_use_verdict_words(kind: str) -> None:
    method, title, description = TEMPLATES[kind]
    assert not VERDICT.search(title), kind
    assert not VERDICT.search(description), kind
    assert method in METHOD_MAX
    assert re.fullmatch(r"heuristic:re_[a-z_]+@1", method)


@pytest.mark.parametrize("kind", sorted(TEMPLATES))
def test_template_placeholders_are_plain_names(kind: str) -> None:
    _, title, description = TEMPLATES[kind]
    for template in (title, description):
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is None:
                continue
            assert re.fullmatch(r"[a-z_]+", name), (kind, name)
            assert not spec and conversion is None, (kind, name)
        assert "by the engine" in description or template is title


def test_scenario_findings_are_neutral_and_capped() -> None:
    for name in SCENARIOS:
        for finding in detections.run(build(name).view, LIMITS).findings:
            assert not VERDICT.search(finding.title), (name, finding.title)
            assert not VERDICT.search(finding.description), (name, finding.description)
            assert SEVERITY_RANK[finding.severity] <= SEVERITY_RANK["medium"]
            assert SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[METHOD_MAX[finding.detection_method]]


@pytest.mark.parametrize("hostile", HOSTILE_NAMES, ids=range(len(HOSTILE_NAMES)))
def test_hostile_function_names_are_quoted_not_judged(hostile: str) -> None:
    b = Builder()
    b.fn(hostile, 0x100, source="export")
    for api in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "GetProcAddress",
                "connect"):  # fmt: skip
        b.imp(api, hostile)
    for value in ("Sleep", "lstrlenW", "GetTickCount64", "http://198.51.100.4/x"):
        b.string(value, hostile)
    findings = detections.run(b.view(), LIMITS).findings
    assert {f.type for f in findings} == {
        "api_injection",
        "runtime_api_resolution",
        "network_string_function",
    }
    for finding in findings:
        assert len(finding.title) <= 255 and len(finding.description) <= 2048
        assert finding.attributes["function_name"] == hostile
        shown = hostile if len(hostile) <= 64 else hostile[:63] + "…"
        assert f'"{shown}"' in finding.title
        for text in (finding.title, finding.description):
            neutral = text.replace(f'"{shown}"', '""').replace(f'"{hostile}"', '""')
            assert not VERDICT.search(QUOTED.sub('""', neutral)), text
