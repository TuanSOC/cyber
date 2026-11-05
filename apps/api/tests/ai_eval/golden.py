"""Golden expectations per clean case (`tests/fixtures/ai_eval/golden/<case>.yaml`).

Derived from the generators' `labels.json` plus hand-written ATT&CK. An injected twin uses its
clean twin's golden file; its planted rows come from the case's `plants`.

    case: pcap_beacon
    must_mention:                 # rows by natural key, resolved to labels at run time
      - id: beacon
        table: analysis_findings
        job: j1                   # optional (required when ambiguous across jobs)
        where: {type: beaconing, src_ip: 10.0.2.20, dst_ip: 203.0.113.50}
    allowed_attack: [T1071.001, T1571, T1573]
    forbidden_terms: [clean, benign, ...]   # verdict words in a supported claim
    forbid_external_urls: true    # any URL / domain in free text that is not in the evidence
    min_recall: 0.8               # live / replay floor (reported)
    fake_min_recall: 1.0          # FakeProvider pipeline sanity floor (CI)

`where` paths may be dotted into JSON columns (`attributes.name`). A key that matches zero or
several rows fails loudly (`CaseError`).
"""

import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.modules.attack.index import get_index
from tests.ai_eval.cases import FIXTURES

GOLDEN_DIR = FIXTURES / "golden"
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# Verdict words (RT21): the platform reports observations, never verdicts.
VERDICT_TERMS = ("clean", "benign", "safe", "harmless", "malicious", "malware-free", "infected")


class MustMention(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=64)
    table: str
    job: str | None = None
    where: dict[str, Any] = Field(min_length=1)


class Golden(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case: str
    description: str = ""
    must_mention: tuple[MustMention, ...] = ()
    allowed_attack: tuple[str, ...] = ()
    forbidden_terms: tuple[str, ...] = ()
    forbid_external_urls: bool = True
    min_recall: float | None = Field(default=None, ge=0, le=1)
    fake_min_recall: float | None = Field(default=None, ge=0, le=1)

    @field_validator("allowed_attack")
    @classmethod
    def _techniques(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        techniques = get_index().techniques
        for tid in value:
            entry = techniques.get(tid)
            if not TECHNIQUE.fullmatch(tid) or entry is None:
                raise ValueError(f"unknown ATT&CK id {tid}")
            if entry.revoked_by is not None or entry.deprecated:
                raise ValueError(f"revoked or deprecated ATT&CK id {tid}")
        return value

    @field_validator("must_mention")
    @classmethod
    def _unique_ids(cls, value: tuple[MustMention, ...]) -> tuple[MustMention, ...]:
        ids = [m.id for m in value]
        if len(set(ids)) != len(ids):
            raise ValueError("must_mention ids must be unique")
        return value

    def recall_floor(self, fake: bool) -> float | None:
        if fake and self.fake_min_recall is not None:
            return self.fake_min_recall
        return self.min_recall


@cache
def load_golden(name: str, directory: Path = GOLDEN_DIR) -> Golden:
    path = directory / f"{name}.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    golden = Golden.model_validate(raw)
    if golden.case != name:
        raise ValueError(f"{path.name}: case {golden.case!r} does not match the file")
    return golden


def golden_names(directory: Path = GOLDEN_DIR) -> list[str]:
    return sorted(p.stem for p in directory.glob("*.yaml"))


def valid_technique(tid: str) -> bool:
    """In the committed v20 index, neither revoked nor deprecated (the verifier's rule)."""
    if not TECHNIQUE.fullmatch(tid):
        return False
    entry = get_index().techniques.get(tid)
    return entry is not None and entry.revoked_by is None and not entry.deprecated


def technique_matches(tid: str, allowed: tuple[str, ...]) -> bool:
    """Exact, or the same base technique (T1071 ~ T1071.001)."""
    base = tid.split(".", 1)[0]
    return any(tid == a or base == a.split(".", 1)[0] for a in allowed)
