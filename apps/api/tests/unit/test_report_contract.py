"""The `cyberlab.report.v1` contract (`packages/py-jobs/src/cyberlab_jobs/report.py`, M6
phase 1): round trip, canonical bytes, caps, text rules, the render budget pin, the TLP and
STIX constants, and the render messages."""

import base64
import json
import random
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import REPORT_RENDER, REPORT_RENDERED, Queues
from cyberlab_jobs.report import (
    ANALYST_TEXT_CHARS,
    BOUNDED_TEXT_CHARS,
    CAPS,
    MAX_SNAPSHOT_BYTES,
    STIX_TLP_EXTENSION_ID,
    STIX_TLP_MARKINGS,
    TLP,
    TLP_COLOURS,
    TLP_DEFINITIONS,
    TLP_LABELS,
    TLP_ORDER,
    Manifest,
    Profile,
    ReportRenderedV1,
    ReportRenderMessageV1,
    ReportSnapshot,
    canonical_json,
    manifest_bytes,
    parse_snapshot,
    render_units,
    section_counts,
    truncate_text,
)
from pydantic import ValidationError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "report"
# Pinned on the golden fixture (RT1): a change of `render_units` or of the fixture is a
# frozen-contract change and needs the parent.
GOLDEN_RENDER_UNITS = 4768


def _golden() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "golden_snapshot.json").read_text("utf-8"))
    return data


def _shuffled(value: Any, rng: random.Random) -> Any:
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {k: _shuffled(v, rng) for k, v in items}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


# --- round trip and canonical bytes ---------------------------------------------------------


@pytest.mark.parametrize("name", ["golden_snapshot.json", "hostile_snapshot.json"])
def test_fixtures_round_trip_to_identical_canonical_bytes(name: str) -> None:
    raw = (FIXTURES / name).read_bytes()
    snapshot = ReportSnapshot.model_validate_json(raw)
    canonical = canonical_json(snapshot)
    assert canonical_json(parse_snapshot(canonical)) == canonical
    assert json.loads(canonical) == json.loads(raw)


def test_canonical_bytes_are_stable_across_key_order() -> None:
    data = _golden()
    expected = canonical_json(ReportSnapshot.model_validate(data))
    rng = random.Random(6)  # noqa: S311 - reproducible shuffles
    for _ in range(5):
        assert canonical_json(ReportSnapshot.model_validate(_shuffled(data, rng))) == expected


def test_canonical_form() -> None:
    canonical = canonical_json(ReportSnapshot.model_validate(_golden()))
    text = canonical.decode("utf-8")
    assert text == json.dumps(
        json.loads(text), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert '"finalized_at":"2026-11-06T09:00:00.000000Z"' in text
    keys = list(json.loads(text))
    assert keys == sorted(keys)


def test_timestamps_are_utc_with_z() -> None:
    data = _golden()
    data["report"]["finalized_at"] = "2026-11-06T16:00:00+07:00"
    snapshot = ReportSnapshot.model_validate(data)
    assert snapshot.report.finalized_at == datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
    assert b'"finalized_at":"2026-11-06T09:00:00.000000Z"' in canonical_json(snapshot)
    data["report"]["finalized_at"] = "2026-11-06T09:00:00"
    with pytest.raises(ValidationError, match="timezone"):
        ReportSnapshot.model_validate(data)


def test_floats_are_refused_in_canonical_json() -> None:
    with pytest.raises(TypeError, match="floats"):
        canonical_json({"score": 0.5})
    data = _golden()
    data["findings"]["items"][0]["score"] = 0.92
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)


# --- text rules -------------------------------------------------------------------------------


def test_bounded_text_is_truncated_with_the_marker_and_idempotent() -> None:
    data = _golden()
    data["findings"]["items"][0]["description"] = "x" * 10_000
    snapshot = ReportSnapshot.model_validate(data)
    text = snapshot.findings.items[0].description
    assert len(text) <= BOUNDED_TEXT_CHARS
    assert text.endswith("]") and "…[truncated " in text
    cut = int(text.rsplit(" ", 1)[1].rstrip("]"))
    assert len(text) - len(text[text.index("…") :]) + cut == 10_000
    assert truncate_text(text) == text
    assert canonical_json(parse_snapshot(canonical_json(snapshot))) == canonical_json(snapshot)


def test_analyst_text_is_never_truncated_and_refused_above_the_cap() -> None:
    data = _golden()
    vietnamese = ("Tiếng Việt có dấu, " * 2000)[:ANALYST_TEXT_CHARS]
    data["sections"]["executive_summary"] = vietnamese
    assert ReportSnapshot.model_validate(data).sections.executive_summary == vietnamese
    data["sections"]["executive_summary"] = vietnamese + "x"
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("sections", "scope"), "a\x00b"),
        (("findings", "items", 0, "title"), "a\x00b"),
        (("case", "title"), "a\x00b"),
        (("findings", "items", 0, "title"), "lone \ud800 surrogate"),
    ],
)
def test_nul_and_lone_surrogates_are_refused(path: tuple[Any, ...], value: str) -> None:
    data = _golden()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)


# --- caps, totals, citations ------------------------------------------------------------------


@pytest.mark.parametrize("section", ["findings", "alerts", "iocs", "timeline", "notes"])
def test_caps_reject_oversize_sections(section: str) -> None:
    data = _golden()
    item = data[section]["items"][0]
    data[section]["items"] = [item] * (CAPS[section] + 1)
    data[section]["total"] = CAPS[section] + 1
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)


def test_ai_runs_and_citations_are_capped() -> None:
    assert (CAPS["ai_runs"], CAPS["citations"], CAPS["iocs"]) == (10, 2000, 2000)
    assert (CAPS["findings"], CAPS["alerts"], CAPS["timeline"], CAPS["notes"]) == (
        500,
        500,
        1000,
        200,
    )
    data = _golden()
    data["ai"]["items"] = data["ai"]["items"] * 11
    data["ai"]["total"] = 11
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)


def test_total_must_cover_the_items() -> None:
    data = _golden()
    data["findings"]["total"] = 0
    with pytest.raises(ValidationError, match="total"):
        ReportSnapshot.model_validate(data)


def test_every_cited_number_resolves_and_is_unique() -> None:
    data = _golden()
    data["findings"]["items"][0]["cite_no"] = 99
    with pytest.raises(ValidationError, match=r"\[C99\]"):
        ReportSnapshot.model_validate(data)
    data = _golden()
    data["citations"]["items"][1]["cite_no"] = 1
    with pytest.raises(ValidationError, match="unique"):
        ReportSnapshot.model_validate(data)


def test_extra_fields_are_refused() -> None:
    data = _golden()
    data["report"]["surprise"] = 1
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)


@pytest.mark.parametrize(
    "url", ["http://cyberlab.example", "https://x.example/path", "javascript:alert(1)"]
)
def test_base_url_is_an_https_origin(url: str) -> None:
    data = _golden()
    data["report"]["base_url"] = url
    with pytest.raises(ValidationError):
        ReportSnapshot.model_validate(data)
    data["report"]["base_url"] = "http://localhost:8080"
    assert ReportSnapshot.model_validate(data).report.base_url == "http://localhost:8080"


def test_section_counts() -> None:
    counts = section_counts(ReportSnapshot.model_validate(_golden()))
    assert counts["timeline"] == {"included": 2, "total": 2}
    assert counts["citations"] == {"included": 3, "total": 3}
    assert counts["status_history"] == {"included": 1, "total": 1}


# --- size and render budget (RT1) -------------------------------------------------------------


def test_render_units_pin_on_the_golden_snapshot() -> None:
    assert render_units(ReportSnapshot.model_validate(_golden())) == GOLDEN_RENDER_UNITS


def test_render_units_grow_with_text_and_rows() -> None:
    data = _golden()
    before = render_units(ReportSnapshot.model_validate(data))
    data["sections"]["impact"] += "x" * 100
    assert render_units(ReportSnapshot.model_validate(data)) == before + 100
    data["findings"]["items"].append(dict(data["findings"]["items"][0], cite_no=None))
    data["findings"]["total"] = 2
    assert render_units(ReportSnapshot.model_validate(data)) > before + 100


def test_a_worst_case_snapshot_near_the_size_cap_stays_canonical() -> None:
    """Caps alone allow more than 8 MiB (the API refuses `report_too_large`); a snapshot just
    under the cap serializes deterministically and fits."""
    data = _golden()
    ioc = data["iocs"]["items"][0]
    filler = "y" * BOUNDED_TEXT_CHARS
    rows = [dict(ioc, value=filler, ioc_key=f"{i:064x}") for i in range(CAPS["iocs"])]
    data["iocs"] = {"items": rows[:1900], "total": CAPS["iocs"]}
    canonical = canonical_json(ReportSnapshot.model_validate(data))
    assert len(canonical) <= MAX_SNAPSHOT_BYTES
    assert canonical_json(parse_snapshot(canonical)) == canonical


# --- TLP and STIX (RT18, RT23) ----------------------------------------------------------------


def test_tlp_constants() -> None:
    assert [t.value for t in sorted(TLP, key=TLP_ORDER.__getitem__)] == [
        "clear",
        "green",
        "amber",
        "amber_strict",
        "red",
    ]
    assert TLP_LABELS[TLP.AMBER_STRICT] == "TLP:AMBER+STRICT"
    assert TLP_COLOURS == {
        TLP.CLEAR: "#FFFFFF",
        TLP.GREEN: "#33FF00",
        TLP.AMBER: "#FFC000",
        TLP.AMBER_STRICT: "#FFC000",
        TLP.RED: "#FF2B2B",
    }
    assert set(TLP_DEFINITIONS) == set(TLP) and all(TLP_DEFINITIONS.values())


def test_stix_tlp_markings_are_the_oasis_objects() -> None:
    ids = {tlp: m["id"] for tlp, m in STIX_TLP_MARKINGS.items()}
    assert ids == {
        TLP.CLEAR: "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        TLP.GREEN: "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        TLP.AMBER: "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        TLP.AMBER_STRICT: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        TLP.RED: "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    }
    # As published in oasis-open/cti-stix-common-objects (tlp-2.0/examples).
    assert STIX_TLP_MARKINGS[TLP.AMBER_STRICT] == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        "created": "2022-10-01T00:00:00.000Z",
        "name": "TLP:AMBER+STRICT",
        "extensions": {
            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                "extension_type": "property-extension",
                "tlp_2_0": "amber+strict",
            }
        },
    }
    for tlp, marking in STIX_TLP_MARKINGS.items():
        assert marking["name"] == TLP_LABELS[tlp]
        assert set(marking["extensions"]) == {STIX_TLP_EXTENSION_ID}


# --- manifest and render messages -------------------------------------------------------------


def _manifest() -> Manifest:
    return Manifest(
        report_id=uuid.UUID(int=1),
        version=1,
        org_id=uuid.UUID(int=2),
        snapshot_sha256="a" * 64,
        snapshot_bytes=10,
        tlp=TLP.RED,
        profile=Profile.EXTERNAL,
        finalized_at=datetime(2026, 11, 6, 9, 0, tzinfo=UTC),
        finalized_by=uuid.UUID(int=3),
        kid="prod-report-1",
    )


def test_manifest_bytes_are_canonical() -> None:
    raw = manifest_bytes(_manifest())
    assert raw == canonical_json(json.loads(raw))
    assert b'"finalized_by":"00000000-0000-0000-0000-000000000003"' in raw
    assert Manifest.model_validate_json(raw) == _manifest()


def _render_message(**over: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "render_id": str(uuid.uuid4()),
        "org_id": str(uuid.uuid4()),
        "format": "pdf",
        "snapshot_url": "http://minio:9000/reports/x?sig=1",
        "snapshot_sha256": "b" * 64,
        "snapshot_bytes": 1000,
        "manifest_b64": base64.b64encode(manifest_bytes(_manifest())).decode(),
        "signature": base64.b64encode(bytes(64)).decode(),
        "kid": "prod-report-1",
        "finalized_at": "2026-11-06T09:00:00Z",
        "upload": {"url": "http://minio:9000/reports", "fields": {"key": "k"}},
        "token": "t" * 43,
        "deadline": (
            datetime.now(timezone(timedelta(hours=7))) + timedelta(minutes=10)
        ).isoformat(),
    }
    values.update(over)
    return values


def test_render_message_validates() -> None:
    msg = ReportRenderMessageV1.model_validate(_render_message())
    assert msg.format == "pdf" and msg.deadline.tzinfo is not None
    for bad in (
        {"format": "docx"},
        {"signature": base64.b64encode(bytes(63)).decode()},
        {"manifest_b64": base64.b64encode(b"{}").decode()},
        {"snapshot_bytes": MAX_SNAPSHOT_BYTES + 1},
        {"snapshot_url": "file:///etc/passwd"},
        {"surprise": True},
    ):
        with pytest.raises(ValidationError):
            ReportRenderMessageV1.model_validate(_render_message(**bad))


def test_rendered_message_consistency() -> None:
    base = {"render_id": str(uuid.uuid4()), "token": "t" * 43, "renderer_version": "rw/0.1.0"}
    ok = ReportRenderedV1.model_validate(
        {
            **base,
            "status": "succeeded",
            "sha256": "c" * 64,
            "bytes": 100,
            "pages": 3,
            "object_version_id": "v1",
        }
    )
    assert ok.error_code is None
    assert ReportRenderedV1.model_validate(
        {**base, "status": "failed", "error_code": "not_implemented"}
    )
    for bad in (
        {"status": "succeeded", "sha256": "c" * 64},
        {"status": "succeeded", "sha256": "c" * 64, "bytes": 1},
        {"status": "failed"},
        {"status": "failed", "error_code": "made_up"},
        {"status": "succeeded", "sha256": "c" * 64, "bytes": 1, "object_version_id": "v",
         "error_code": "oom"},
    ):  # fmt: skip
        with pytest.raises(ValidationError):
            ReportRenderedV1.model_validate({**base, **bad})


def test_task_names_and_queue() -> None:
    assert (REPORT_RENDER, REPORT_RENDERED) == ("report.render", "report.rendered")
    assert Queues("test.").report == "test.report"
