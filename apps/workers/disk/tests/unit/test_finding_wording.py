# ruff: noqa: E501 - test data tables
"""Findings describe observations, never verdicts (the M2 / M3 / M8 wording rule, plan phase 6):
checked on every template and on every finding, IOC and timeline title the scenario set
produces; image text is quoted as data, masked, and never used as a format string."""

import re
import string

import pytest

from dataset import evaluate
from dataset import records as r
from dataset.baselines import Draft
from dataset.scenarios import SCENARIOS
from disk_worker import detections
from disk_worker.detections.base import METHOD_MAX, TEMPLATES

VERDICT = re.compile(
    r"\b(?:malicious|malware|infected|infection|compromised?|attacker|evil|backdoor|trojan|"
    r"virus|rootkit|hacked|exploit(?:ed)?|threat actor|ransomware|confirmed|suspicious|"
    r"intrusion|breach(?:ed)?)\b",
    re.I,
)
NTFS = r.NTFS_PARTITION
T0 = r.ts("2026-10-06T10:00:00")


@pytest.mark.parametrize("kind", sorted(TEMPLATES))
def test_templates_never_use_verdict_words(kind: str) -> None:
    method, title, description = TEMPLATES[kind]
    assert not VERDICT.search(title), kind
    assert not VERDICT.search(description), kind
    assert method in METHOD_MAX
    assert re.fullmatch(r"(?:heuristic:disk_[a-z_]+|signature:yara|known_file:hashset)@1", method)


@pytest.mark.parametrize("kind", sorted(TEMPLATES))
def test_template_placeholders_are_plain_names(kind: str) -> None:
    """Values go into named placeholders only: no attribute access or indexing on image values,
    no positional fields, no format specs."""
    _, title, description = TEMPLATES[kind]
    for template in (title, description):
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is None:
                continue
            assert re.fullmatch(r"[a-z_]+", name), (kind, name)
            assert not spec and conversion is None, (kind, name)


def test_every_method_has_a_template() -> None:
    assert {m for m, _, _ in TEMPLATES.values()} == set(METHOD_MAX)


def test_scenario_output_never_uses_verdict_words() -> None:
    report = evaluate.evaluate()
    for name in SCENARIOS:
        out = report.outputs[name]
        for finding in out.findings:
            assert not VERDICT.search(finding.title), (name, finding.title)
            assert not VERDICT.search(finding.description), (name, finding.description)
            assert finding.type in TEMPLATES
        for event in out.timeline:
            assert not VERDICT.search(event.title), (name, event.title)


def test_image_text_is_quoted_not_judged_nor_formatted() -> None:
    """A verdict word or a format string inside image data appears only as quoted data: the
    template around it stays neutral, and `{...}` in a name is never expanded."""
    d = Draft("unit", "triage", [r.partition(NTFS, "ntfs", "windows")])
    d.add_file(NTFS, "Users/Public/malware {path.__class__} {0}.exe", magic="pe", mtime=T0)
    d.add_run_key(
        T0,
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ["evil: C:\\Users\\Public\\backdoor{x}.exe --password=Pw12345678"],
    )
    out = detections.run(d.view(), r.limits())
    exec_finding = next(f for f in out.findings if f.type == "disk_exec_user_writable")
    assert "malware {path.__class__} {0}.exe" in exec_finding.description
    run_key = next(f for f in out.findings if f.type == "disk_persistence_run_key")
    assert "backdoor{x}.exe" in run_key.description and "Pw12345678" not in run_key.description
    for finding in out.findings:
        template = TEMPLATES[finding.type][2]
        assert not VERDICT.search(template)
