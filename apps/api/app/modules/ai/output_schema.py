"""The model output contract `ai.v1` (M5 phase 1, FROZEN).

`AnalysisOutput` is the full local model: every object forbids extra keys, every list and
string has a presentation cap. The provider schema is derived per provider
(`provider_json_schema`), and the full model is always re-validated locally after
`coerce_caps` has truncated over-cap lists and strings (a presentation cap is never a reason
for a paid repair call, RT19).

Labels (`ref`) and ATT&CK ids are deliberately not pattern-constrained here: an invented
label or technique is a verifier finding (invalid / dropped), not a schema failure.
"""

import copy
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

OUTPUT_SCHEMA_VERSION = "ai.v1"

MAX_OBSERVED = 40
MAX_INTERPRETATION = 20
MAX_HYPOTHESES = 10
MAX_NEXT_STEPS = 10
MAX_ATTACK = 20
MAX_TIMELINE = 60
MAX_LIMITATIONS = 10
MAX_CITATIONS = 8
MAX_REFS = 8
MAX_TEXT = 600
MAX_QUOTE = 256
MAX_FIELD = 64
MAX_LABEL = 16
MAX_ID = 16
MAX_TECHNIQUE = 16
# Serialized worst case of a capped AnalysisOutput must fit `ai_outputs.body` (64 KiB);
# `tests/unit/test_ai_contracts.py` proves it.
BODY_MAX_BYTES = 64 * 1024

ConfidenceLevel = Literal["low", "medium", "high"]
_STRICT = ConfigDict(extra="forbid")


class Citation(BaseModel):
    model_config = _STRICT

    ref: str = Field(max_length=MAX_LABEL, description="A label exactly as given, e.g. F3")
    field: str | None = Field(default=None, max_length=MAX_FIELD)
    quote: str | None = Field(default=None, max_length=MAX_QUOTE)


class Claim(BaseModel):
    model_config = _STRICT

    id: str = Field(max_length=MAX_ID)
    text: str = Field(max_length=MAX_TEXT)
    confidence: ConfidenceLevel
    citations: list[Citation] = Field(default_factory=list, max_length=MAX_CITATIONS)


class Hypothesis(BaseModel):
    model_config = _STRICT

    id: str = Field(max_length=MAX_ID)
    text: str = Field(max_length=MAX_TEXT)
    confidence: ConfidenceLevel
    supporting: list[Citation] = Field(default_factory=list, max_length=MAX_CITATIONS)
    contradicting: list[Citation] = Field(default_factory=list, max_length=MAX_CITATIONS)


class OverallConfidence(BaseModel):
    model_config = _STRICT

    level: ConfidenceLevel
    rationale: str = Field(max_length=MAX_TEXT)


class NextStep(BaseModel):
    model_config = _STRICT

    text: str = Field(max_length=MAX_TEXT)
    rationale: str = Field(max_length=MAX_TEXT)
    refs: list[str] = Field(default_factory=list, max_length=MAX_REFS)


class AttackTechnique(BaseModel):
    model_config = _STRICT

    technique_id: str = Field(max_length=MAX_TECHNIQUE)
    rationale: str = Field(max_length=MAX_TEXT)
    citations: list[Citation] = Field(default_factory=list, max_length=MAX_CITATIONS)


class TimelineEntry(BaseModel):
    """Timestamps always come from the cited record, never from the model."""

    model_config = _STRICT

    text: str = Field(max_length=MAX_TEXT)
    citations: list[Citation] = Field(default_factory=list, max_length=MAX_CITATIONS)


class AnalysisOutput(BaseModel):
    model_config = _STRICT

    observed: list[Claim] = Field(default_factory=list, max_length=MAX_OBSERVED)
    interpretation: list[Claim] = Field(default_factory=list, max_length=MAX_INTERPRETATION)
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=MAX_HYPOTHESES)
    overall_confidence: OverallConfidence
    next_steps: list[NextStep] = Field(default_factory=list, max_length=MAX_NEXT_STEPS)
    limitations: list[str] = Field(default_factory=list, max_length=MAX_LIMITATIONS)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list, max_length=MAX_ATTACK)
    timeline: list[TimelineEntry] = Field(default_factory=list, max_length=MAX_TIMELINE)


# --- provider schemas ----------------------------------------------------------------------

# Keywords the Anthropic structured-output compiler does not support (string and number
# bounds, complex array constraints, RT19); the local model enforces them instead.
_ANTHROPIC_DROP = frozenset(
    {
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "pattern",
        "format",
    }
)
# Gemini keeps minItems/maxItems and number bounds but ignores string lengths.
_GEMINI_DROP = frozenset({"minLength", "maxLength", "pattern", "format"})
_ALWAYS_DROP = frozenset({"title", "default", "description"})


def _inline(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            return _inline(copy.deepcopy(defs[ref.rsplit("/", 1)[-1]]), defs)
        return {k: _inline(v, defs) for k, v in node.items() if k != "$defs"}
    if isinstance(node, list):
        return [_inline(v, defs) for v in node]
    return node


def _strip(node: Any, drop: frozenset[str]) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                # Property names are data here, never keywords.
                out[key] = {name: _strip(sub, drop) for name, sub in value.items()}
            elif key not in drop:
                out[key] = _strip(value, drop)
        if out.get("type") == "object":
            out["additionalProperties"] = False
        return out
    if isinstance(node, list):
        return [_strip(v, drop) for v in node]
    return node


def provider_json_schema(provider: str) -> dict[str, Any]:
    """The JSON schema sent to `provider` (`anthropic`, `gemini`, `mock`): references inlined
    (the schema is not recursive), titles/defaults/descriptions dropped, every object
    `additionalProperties: false`; Anthropic also loses length, number and array bounds."""
    raw = AnalysisOutput.model_json_schema()
    inlined = _inline(raw, raw.get("$defs", {}))
    if provider == "anthropic":
        drop = _ALWAYS_DROP | _ANTHROPIC_DROP
    elif provider == "gemini":
        drop = _ALWAYS_DROP | _GEMINI_DROP
    else:
        drop = _ALWAYS_DROP
    result: dict[str, Any] = _strip(inlined, drop)
    return result


# --- lenient loader ------------------------------------------------------------------------

_LIST_CAPS: dict[str, int] = {
    "observed": MAX_OBSERVED,
    "interpretation": MAX_INTERPRETATION,
    "hypotheses": MAX_HYPOTHESES,
    "next_steps": MAX_NEXT_STEPS,
    "limitations": MAX_LIMITATIONS,
    "attack_techniques": MAX_ATTACK,
    "timeline": MAX_TIMELINE,
    "citations": MAX_CITATIONS,
    "supporting": MAX_CITATIONS,
    "contradicting": MAX_CITATIONS,
    "refs": MAX_REFS,
}
_STRING_CAPS: dict[str, int] = {
    "text": MAX_TEXT,
    "rationale": MAX_TEXT,
    "quote": MAX_QUOTE,
    "field": MAX_FIELD,
    "ref": MAX_LABEL,
    "id": MAX_ID,
    "technique_id": MAX_TECHNIQUE,
}


# When the per-item caps still leave a body over BODY_MAX_BYTES, whole entries are dropped
# from the end of these sections, in this order (least to most important), until it fits.
_TRIM_ORDER = (
    "timeline",
    "attack_techniques",
    "hypotheses",
    "interpretation",
    "limitations",
    "next_steps",
    "observed",
)
# Measured like Postgres `jsonb::text` (", " and ": " separators, UTF-8), with headroom for
# the post-processing (defang adds characters).
_TRIM_TARGET = BODY_MAX_BYTES - 4 * 1024


def body_size(doc: Any) -> int:
    """Bytes of `doc` as `ai_outputs.body::text` would store it."""
    return len(json.dumps(doc, ensure_ascii=False).encode())


def coerce_caps(parsed: Any) -> tuple[Any, dict[str, int]]:
    """Truncate over-cap lists and strings in a parsed (untrusted) output before strict
    validation, then drop whole entries (`_TRIM_ORDER`) until the body fits 60 KiB.

    Returns a new object and the counts `{"lists": n, "strings": n, "size_trimmed": n}`.
    Presentation caps are never a reason for a paid repair call (RT19). Anything that is not
    the expected shape is left for `AnalysisOutput` to reject."""
    counts = {"lists": 0, "strings": 0, "size_trimmed": 0}

    def cap_str(value: Any, limit: int) -> Any:
        if isinstance(value, str) and len(value) > limit:
            counts["strings"] += 1
            return value[:limit]
        return value

    def walk(node: Any, key: str | None) -> Any:
        if isinstance(node, dict):
            return {k: walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            limit = _LIST_CAPS.get(key or "")
            if limit is not None and len(node) > limit:
                counts["lists"] += 1
                node = node[:limit]
            if key == "limitations":
                return [cap_str(v, MAX_TEXT) for v in node]
            if key == "refs":
                return [cap_str(v, MAX_LABEL) for v in node]
            return [walk(v, None) for v in node]
        if key is not None and key in _STRING_CAPS:
            return cap_str(node, _STRING_CAPS[key])
        return node

    coerced = walk(copy.deepcopy(parsed), None)
    if isinstance(coerced, dict):
        size = body_size(coerced)
        for section in _TRIM_ORDER:
            entries = coerced.get(section)
            while isinstance(entries, list) and entries and size > _TRIM_TARGET:
                size -= body_size(entries.pop()) + 2  # the entry and its ", " separator
                counts["size_trimmed"] += 1
    return coerced, counts
