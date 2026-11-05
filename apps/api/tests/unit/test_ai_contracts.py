"""Frozen AI contracts (M5 phase 1): schema export per provider, worst-case size, label
grammar, the sanitizer tables, defang/refang, catalog consistency, messages, FakeProvider."""

import json
import uuid
from typing import Any

import pytest
from cyberlab_jobs import AI_RESUME, AI_RUN, AI_VERIFY, Queues
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.ai import labels, text
from app.modules.ai.availability import provider_available
from app.modules.ai.catalog import AI_CATALOG, PRICE_VERSION, cost_micros, find_model
from app.modules.ai.contracts import (
    AiProviderName,
    AiRunRequest,
    AiTask,
    ContextBuildError,
    LlmProvider,
    ProviderError,
    ProviderErrorKind,
    ProviderRequest,
    ProviderUsage,
    RefKind,
    RunMetrics,
    ValidationFailed,
)
from app.modules.ai.messages import AiRunMessage, AiVerifyMessage
from app.modules.ai.output_schema import (
    BODY_MAX_BYTES,
    MAX_CITATIONS,
    MAX_OBSERVED,
    MAX_QUOTE,
    MAX_TEXT,
    OUTPUT_SCHEMA_VERSION,
    AnalysisOutput,
    body_size,
    coerce_caps,
    provider_json_schema,
)
from app.modules.ai.providers.fake import FakeProvider, fake_output
from tests.ai_doubles import make_context

BASE = {
    "database_url": "postgresql+asyncpg://cyberlab_app:s3cret@postgres/cyberlab",
    "redis_url": "redis://redis:6379/0",
    "jwt_secret": "x" * 48,
    "minio_endpoint": "minio:9000",
    "minio_access_key": "cyberlab-api",
    "minio_secret_key": "s3cret-minio",
}

# --- output schema --------------------------------------------------------------------------


def _walk(node: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        found.append(node)
        for value in node.values():
            found += _walk(value)
    elif isinstance(node, list):
        for value in node:
            found += _walk(value)
    return found


def _keywords(schema: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for node in _walk(schema):
        props = node.get("properties")
        keys |= {k for k in node if not (props is not None and k in props and k != "properties")}
    return keys


@pytest.mark.parametrize("provider", ["anthropic", "gemini", "mock"])
def test_provider_schemas_are_closed_and_inlined(provider: str) -> None:
    schema = provider_json_schema(provider)
    assert OUTPUT_SCHEMA_VERSION == "ai.v1"
    assert "$defs" not in json.dumps(schema) and "$ref" not in json.dumps(schema)
    objects = [n for n in _walk(schema) if n.get("type") == "object"]
    assert len(objects) >= 8
    assert all(n["additionalProperties"] is False for n in objects)
    assert schema["required"] == ["overall_confidence"]


def test_anthropic_schema_drops_unsupported_bounds() -> None:
    dumped = json.dumps(provider_json_schema("anthropic"))
    for keyword in ("maxLength", "minLength", "maxItems", "minItems", "minimum", "maximum"):
        assert f'"{keyword}"' not in dumped
    assert '"title"' not in dumped and '"default"' not in dumped


def test_gemini_schema_keeps_array_bounds() -> None:
    dumped = json.dumps(provider_json_schema("gemini"))
    assert '"maxItems"' in dumped and '"maxLength"' not in dumped
    assert provider_json_schema("mock")["properties"]["observed"]["maxItems"] == MAX_OBSERVED


def _worst_case() -> dict[str, Any]:
    citation = {"ref": "J999:F9999"[:16], "field": "f" * 64, "quote": "q" * MAX_QUOTE}
    claim = {
        "id": "x" * 16,
        "text": "t" * MAX_TEXT,
        "confidence": "medium",
        "citations": [citation] * MAX_CITATIONS,
    }
    return {
        "observed": [claim] * 40,
        "interpretation": [claim] * 20,
        "hypotheses": [
            {
                "id": "h" * 16,
                "text": "t" * MAX_TEXT,
                "confidence": "low",
                "supporting": [citation] * 8,
                "contradicting": [citation] * 8,
            }
        ]
        * 10,
        "overall_confidence": {"level": "low", "rationale": "r" * MAX_TEXT},
        "next_steps": [{"text": "t" * 600, "rationale": "r" * 600, "refs": ["J999:F9999"] * 8}]
        * 10,
        "limitations": ["l" * 600] * 10,
        "attack_techniques": [
            {"technique_id": "T1234.567", "rationale": "r" * 600, "citations": [citation] * 8}
        ]
        * 20,
        "timeline": [{"text": "t" * 600, "citations": [citation] * 8}] * 60,
    }


def test_the_serialized_worst_case_fits_the_body_column() -> None:
    """Every list and string at its cap (non-ASCII text, 2-4 UTF-8 bytes per character) is
    far over 64 KiB; `coerce_caps` trims whole entries from the least important sections
    until the stored `jsonb::text` fits (RT19: never a repair call)."""
    doc = _worst_case()
    doc["observed"] = [
        {**c, "text": "漢" * MAX_TEXT} for c in doc["observed"]
    ]  # 3 bytes per character
    assert body_size(doc) > 8 * BODY_MAX_BYTES
    coerced, counts = coerce_caps(doc)
    body = AnalysisOutput.model_validate(coerced)
    stored = body_size(body.model_dump(mode="json"))
    assert stored <= BODY_MAX_BYTES - 4096 and counts["size_trimmed"] > 0
    assert body.observed  # the most important section survives
    assert body.timeline == [] and body.attack_techniques == []  # trimmed first
    minimal = {"overall_confidence": {"level": "low", "rationale": "x"}}
    assert coerce_caps(minimal) == (minimal, {"lists": 0, "strings": 0, "size_trimmed": 0})


def test_a_realistic_full_output_fits_the_body_column() -> None:
    """Every section at its cap with typical lengths (200-char texts, 2 citations with
    80-char quotes) stays within 64 KiB."""
    citation = {"ref": "F12", "field": "summary", "quote": "q" * 80}
    claim = {"id": "O1", "text": "t" * 200, "confidence": "high", "citations": [citation] * 2}
    doc = {
        "observed": [claim] * 40,
        "interpretation": [claim] * 20,
        "hypotheses": [{"id": "H1", "text": "t" * 200, "confidence": "low"}] * 10,
        "overall_confidence": {"level": "medium", "rationale": "r" * 200},
        "next_steps": [{"text": "t" * 200, "rationale": "r" * 100, "refs": ["F1"]}] * 10,
        "limitations": ["l" * 200] * 10,
        "attack_techniques": [
            {"technique_id": "T1071.001", "rationale": "r" * 100, "citations": [citation]}
        ]
        * 20,
        "timeline": [{"text": "t" * 100, "citations": [citation]}] * 30,
    }
    assert body_size(AnalysisOutput.model_validate(doc).model_dump(mode="json")) <= BODY_MAX_BYTES
    assert coerce_caps(doc)[1]["size_trimmed"] == 0


def test_strict_model_rejects_extras_and_over_caps() -> None:
    base = {"overall_confidence": {"level": "low", "rationale": "x"}}
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate({**base, "verdict": "clean"})
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate({**base, "observed": [{"id": "O1", "text": "x"}]})
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate({**base, "limitations": ["x"] * 11})


def test_coerce_caps_truncates_instead_of_failing() -> None:
    claim = {"id": "O1", "text": "short", "confidence": "low", "citations": [{"ref": "F1"}] * 20}
    doc: dict[str, Any] = {
        "observed": [claim] * 80,
        "overall_confidence": {"level": "low", "rationale": "x"},
        "limitations": ["l" * 5000] * 30,
        "next_steps": [{"text": "t", "rationale": "r", "refs": ["X" * 40] * 30}],
    }
    doc["observed"][0] = {**claim, "text": "t" * 5000}
    coerced, counts = coerce_caps(doc)
    body = AnalysisOutput.model_validate(coerced)
    assert len(body.observed) == MAX_OBSERVED and len(body.observed[0].text) == MAX_TEXT
    assert len(body.observed[1].citations) == MAX_CITATIONS
    assert counts["lists"] >= 3 and counts["strings"] >= 2 and counts["size_trimmed"] == 0
    assert doc["observed"][0]["text"] == "t" * 5000  # input untouched


def test_coerce_caps_leaves_bad_shapes_to_the_validator() -> None:
    coerced, counts = coerce_caps({"observed": "not a list", "overall_confidence": 3})
    assert counts == {"lists": 0, "strings": 0, "size_trimmed": 0}
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate(coerced)


# --- labels ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "kind", "index", "job"),
    [
        ("F3", RefKind.FINDING, 3, None),
        ("J2:F3", RefKind.FINDING, 3, 2),
        ("N9999", RefKind.FLOW, 9999, None),
        ("D1", RefKind.DIGEST_CLAIM, 1, None),
        ("J1", RefKind.JOB, 1, None),
    ],
)
def test_labels_round_trip(label: str, kind: RefKind, index: int, job: int | None) -> None:
    parsed = labels.parse_label(label)
    assert parsed == labels.ParsedLabel(kind=kind, index=index, job=job)
    assert labels.format_label(kind, index, job) == label


@pytest.mark.parametrize(
    "bad", ["", "f3", "F0", "F10000", "Z1", "J0:F1", "J1000:F1", "F3 ", "J2:", "FF3", "F-1", "1F"]
)
def test_label_grammar_rejects(bad: str) -> None:
    assert labels.parse_label(bad) is None and not labels.is_label(bad)


def test_every_kind_has_a_unique_prefix() -> None:
    prefixes = [k.prefix for k in RefKind]
    assert len(set(prefixes)) == len(prefixes) == 16
    assert all(RefKind.from_prefix(k.prefix) is k for k in RefKind)
    assert labels.qualify("F3", 2) == "J2:F3"
    with pytest.raises(ValueError):
        labels.format_label(RefKind.FINDING, 0)


# --- text -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "category"),
    [
        ("\x00", "control"),
        ("\x1b", "control"),
        ("\r", "control"),
        ("\x7f", "control"),
        ("\x85", "control"),
        ("​", "zero_width"),
        ("‍", "zero_width"),
        ("﻿", "zero_width"),
        ("‎", "bidi"),
        ("‏", "bidi"),
        ("‪", "bidi"),
        ("‮", "bidi"),
        ("⁦", "bidi"),
        ("⁩", "bidi"),
        ("\U000e0001", "tag"),
        ("\U000e0041", "tag"),
        ("\U000e007f", "tag"),
    ],
)
def test_sanitize_strips_and_counts(raw: str, category: str) -> None:
    clean, counts = text.sanitize(f"a{raw}b{raw}")
    assert clean == "ab"
    assert counts.as_dict()[category] == 2 and counts.total == 2


def test_sanitize_keeps_newlines_tabs_and_text() -> None:
    value = "line 1\n\tline 2 — ünïcödé 漢字"
    assert text.sanitize(value) == (value, text.StripCounts())


@pytest.mark.parametrize(
    ("raw", "defanged"),
    [
        ("http://evil.example.com/a", "hxxp[:]//evil[.]example[.]com/a"),
        ("HTTPS://Evil.Example/x?y=1", "HXXPS[:]//Evil[.]Example/x?y=1"),
        ("ftp://files.example.org", "fxp[:]//files[.]example[.]org"),
        ("beacon to c2.example.net:8080", "beacon to c2[.]example[.]net:8080"),
        ("10.0.0.5 and 203.0.113.50", "10.0.0.5 and 203.0.113.50"),
        ("user@corp.example", "user@corp[.]example"),
        ("no domains here", "no domains here"),
    ],
)
def test_defang_and_refang(raw: str, defanged: str) -> None:
    assert text.defang(raw) == defanged
    assert text.defang(defanged) == defanged  # idempotent
    assert text.refang(defanged) == raw


def test_canonical_forms_and_truncation() -> None:
    assert text.canonical_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert text.canonical_ip("[2001:DB8::0:1]") == "2001:db8::1"
    assert text.canonical_ip("10.0.0") is None
    assert text.canonical_hash("A" * 64) == "a" * 64
    assert text.canonical_hash("abc") is None and text.canonical_hash("g" * 32) is None
    assert text.truncate("abcdef", 4) == "abcd…[truncated 2]"
    assert text.truncate("abc", 4) == "abc"
    assert text.collapse_ws("  a \n\t b  ") == "a b"
    assert text.nfc("é") == "é"


# --- catalog and availability ---------------------------------------------------------------


def test_catalog_is_consistent() -> None:
    assert set(AI_CATALOG) == set(AiProviderName)
    anthropic = AI_CATALOG[AiProviderName.ANTHROPIC]
    assert anthropic.default_model == "claude-sonnet-5"
    assert anthropic.model_ids == ("claude-sonnet-5", "claude-opus-5-5")
    assert (
        anthropic.model("claude-sonnet-5").price.input,
        anthropic.model("claude-sonnet-5").price.output,
    ) == (2.0, 10.0)  # type: ignore[union-attr]
    assert "claude-sonnet-5-5" not in anthropic.model_ids  # unverified ids stay out (RT24)
    assert AI_CATALOG[AiProviderName.GEMINI].requires_billing_flag
    assert AI_CATALOG[AiProviderName.MOCK].dev_only
    for entry in AI_CATALOG.values():
        assert entry.default_model in entry.model_ids
        assert entry.default_limits.per_minute <= entry.ceilings.per_minute
        assert entry.tos_note and entry.privacy_note
    for name in (AiProviderName.ANTHROPIC, AiProviderName.GEMINI):
        assert "own" in AI_CATALOG[name].tos_note  # BYOK orgs are bound by their own terms
    assert PRICE_VERSION


def test_cost_is_estimated_from_the_price_table() -> None:
    usage = ProviderUsage(input_tokens=1_000_000, output_tokens=100_000, cache_read_tokens=10)
    assert cost_micros("claude-sonnet-5", usage) == 2_000_000 + 1_000_000 + 2
    assert cost_micros("claude-opus-4-8", usage) is None  # unpriced: an estimate flag
    assert find_model("mock-1") is not None


@pytest.mark.parametrize(
    ("overrides", "provider", "expected"),
    [
        ({}, "anthropic", (True, None)),
        ({"ai_enabled": False}, "anthropic", (False, "ai_disabled_platform")),
        ({}, "gemini", (False, "gemini_billing_required")),
        ({"gemini_billing_enabled": True}, "gemini", (True, None)),
        ({"ai_mock_enabled": True}, "mock", (True, None)),
        ({"ai_mock_enabled": False}, "mock", (False, "prod_mock")),
    ],
)
def test_availability(overrides: dict[str, Any], provider: str, expected: tuple[bool, Any]) -> None:
    settings = Settings(**BASE, **{"ai_mock_enabled": False, **overrides})
    assert provider_available(settings, provider) == expected


def test_the_mock_is_never_available_in_prod() -> None:
    settings = Settings(**BASE, ai_mock_enabled=False).model_copy(
        update={"env": "prod", "ai_mock_enabled": True}
    )
    assert provider_available(settings, "mock") == (False, "prod_mock")


# --- requests, errors, messages, jobs package -----------------------------------------------

JOB = uuid.uuid4()
CASE = uuid.uuid4()


@pytest.mark.parametrize(
    "body",
    [
        {"task": "summarize_pcap", "job_id": JOB},
        {"task": "explain_finding", "job_id": JOB, "target_id": uuid.uuid4()},
        {"task": "incident_summary", "investigation_id": CASE},
        {"task": "ioc_correlation", "investigation_id": CASE},
        {"task": "attack_mapping", "job_id": JOB, "provider": "mock", "model": "mock-1"},
    ],
)
def test_valid_run_requests(body: dict[str, Any]) -> None:
    req = AiRunRequest.model_validate(body)
    assert req.scope.value == ("job" if "job_id" in body else "investigation")


@pytest.mark.parametrize(
    "body",
    [
        {"task": "job_digest", "job_id": JOB},
        {"task": "summarize_pcap"},
        {"task": "summarize_pcap", "job_id": JOB, "investigation_id": CASE},
        {"task": "summarize_pcap", "investigation_id": CASE},
        {"task": "incident_summary", "job_id": JOB},
        {"task": "explain_alert", "job_id": JOB},
        {"task": "summarize_pcap", "job_id": JOB, "target_id": uuid.uuid4()},
        {"task": "summarize_pcap", "job_id": JOB, "provider": "openai"},
        {"task": "summarize_pcap", "job_id": JOB, "fallback": True},
    ],
)
def test_invalid_run_requests(body: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AiRunRequest.model_validate(body)


def test_errors_never_carry_secrets() -> None:
    error = ProviderError(
        ProviderErrorKind.REFUSED, http_status=200, category="c" * 40, request_sent=True
    )
    assert str(error) == "refused" and error.category == "c" * 32 and error.request_sent
    assert "ProviderError(kind='refused'" in repr(error)
    assert str(ValidationFailed(["observed.0.text: too_long"])) == "invalid_output"
    assert ContextBuildError("job_not_ready").code == "job_not_ready"
    request = ProviderRequest(
        model="m", system="SECRET-SYSTEM", user="SECRET-USER", output_schema={}, max_output_tokens=1
    )
    assert "SECRET" not in repr(request)
    assert "context" not in request.model_dump()


def test_messages_and_jobs_package() -> None:
    assert (AI_RUN, AI_RESUME, AI_VERIFY) == ("ai.run", "ai.resume", "ai.verify")
    assert (Queues().analyst, Queues("test.").analyst) == ("analyst", "test.analyst")
    run = AiRunMessage(run_id=uuid.uuid4(), org_id=uuid.uuid4())
    assert set(run.model_dump()) == {"run_id", "org_id"}
    with pytest.raises(ValidationError):
        AiRunMessage.model_validate({**run.model_dump(), "context": "x"})
    with pytest.raises(ValidationError):
        AiVerifyMessage.model_validate(
            {"org_id": uuid.uuid4(), "provider": "otx", "key_version": 1}
        )


def test_run_metrics_shape_is_small() -> None:
    assert len(RunMetrics(flags=("verdict_language",)).model_dump_json()) < 4096


# --- context and FakeProvider ---------------------------------------------------------------


def test_frozen_context_hash_covers_only_what_is_sent() -> None:
    ctx = make_context()
    same = ctx.model_copy(update={"pseudonym_map": {"INT_IP_1": "10.9.9.9"}, "refs": ()})
    assert ctx.sha256 == same.sha256 and len(ctx.sha256) == 64
    assert "pseudonym_map" not in ctx.canonical_json() and "10.9.9.9" not in repr(same)
    changed = ctx.model_copy(update={"items": ctx.items[:-1]})
    assert changed.sha256 != ctx.sha256
    assert json.loads(ctx.canonical_json())["task"] == ctx.task.value


async def test_fake_provider_is_deterministic_and_schema_valid() -> None:
    ctx = make_context(task=AiTask.SUMMARIZE_PCAP)
    provider = FakeProvider()
    assert isinstance(provider, LlmProvider)
    request = ProviderRequest(
        model="fake-1",
        system="system",
        user="user turn",
        output_schema=provider_json_schema("mock"),
        max_output_tokens=16_000,
        context=ctx,
    )
    first = await provider.analyze(request)
    second = await provider.analyze(request)
    assert first == second and provider.calls == 2
    body = AnalysisOutput.model_validate(first.parsed)
    assert body.observed and body.interpretation and body.hypotheses and body.next_steps
    assert body.limitations and body.timeline
    for claim in body.observed:
        [citation] = claim.citations
        item = ctx.item(citation.ref)
        assert item is not None and citation.field is not None and citation.quote
        assert citation.quote in str(item.fields[citation.field])
        assert citation.quote in claim.text  # anchored (RT1)
    assert {t.technique_id for t in body.attack_techniques} == {"T1071.001", "T1573"}
    assert all(c.ref[0] != "D" for claim in body.observed for c in claim.citations)
    assert first.usage.input_tokens == len("systemuser turn") // 4
    assert await provider.count_tokens(request) == len("systemuser turn") // 4
    assert (await provider.verify()).status == "valid"


def test_fake_output_without_context() -> None:
    body = AnalysisOutput.model_validate(fake_output(None))
    assert body.observed == [] and body.limitations
