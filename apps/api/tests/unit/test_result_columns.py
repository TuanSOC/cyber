"""Every contract limit fits its column: a validated stream can never fail at insert time.

Compares the `pcap.v1` and `static.v1` contracts (JSON schema of each record model) with the
SQLAlchemy columns the ingest row builders fill: text max lengths against VARCHAR lengths,
integer bounds against the integer / NUMERIC column types. A column with no bounded contract
field fails.
"""

from typing import Any

import pytest
from cyberlab_jobs import results as contract
from cyberlab_jobs import static
from pydantic import BaseModel
from sqlalchemy import BigInteger, Column, Integer, Numeric, SmallInteger, String, Table

from app.modules.pcap_analysis import ingest
from app.modules.static_analysis import ingest as static_ingest
from app.modules.static_analysis import models as static_models

TABLE_MODELS: dict[Table, tuple[type[BaseModel], ...]] = {
    ingest.FLOWS: (contract.FlowRecord,),
    ingest.RECORDS: (contract.DnsRecord, contract.HttpRecord, contract.TlsRecord),
    ingest.ALERTS: (contract.AlertRecord,),
    ingest.FINDINGS: (contract.FindingRecord,),
    ingest.IOCS: (contract.IocRecord,),
    ingest.TIMELINE: (contract.TimelineEvent,),
    static_ingest.SAMPLES: (static.SampleInfo,),
    static_ingest.SECTIONS: (static.SectionRecord,),
    static_ingest.IMPORTS: (static.ImportRecord,),
    static_ingest.EXPORTS: (static.ExportRecord,),
    static_ingest.RESOURCES: (static.ResourceRecord,),
    static_ingest.STRINGS: (static.StringRecord,),
    static_ingest.SIGNATURES: (static.SignatureMatch,),
    static_ingest.CAPABILITIES: (static.CapabilityRecord,),
}
# Columns filled from another line of the stream than the table's own record.
OTHER_SOURCES: dict[tuple[str, str], type[BaseModel]] = {
    ("malware_samples", "file_format"): static.StaticResultHeader,
}
# Filled by the server or from the scope, derived by the row builder (checked below), or
# JSONB documents of a whole contract record (`pe`, `elf`).
NOT_FROM_CONTRACT = {
    "id",
    "organization_id",
    "job_id",
    "total_bytes",
    "summary",
    "details",
    "pe",
    "elf",
}
# Text fields bounded only by a pattern: the longest string each pattern admits.
PATTERN_LENGTHS = {
    r"^[a-z][a-z0-9_]{0,63}$": 64,
    r"^[0-9a-f]{32}$": 32,
    r"^[0-9a-f]{40}$": 40,
    r"^[0-9a-f]{64}$": 64,
}
INT_RANGES = {
    SmallInteger: (-(2**15), 2**15 - 1),
    Integer: (-(2**31), 2**31 - 1),
    BigInteger: (-(2**63), 2**63 - 1),
}


def _options(prop: dict[str, Any]) -> list[dict[str, Any]]:
    return [o for o in prop.get("anyOf", [prop]) if o.get("type") != "null"]


def _max_length(prop: dict[str, Any]) -> int:
    lengths = []
    for option in _options(prop):
        if "maxLength" in option:
            lengths.append(option["maxLength"])
        elif "const" in option:
            lengths.append(len(option["const"]))
        elif "enum" in option:
            lengths.append(max(len(v) for v in option["enum"]))
        elif option.get("pattern") in PATTERN_LENGTHS:
            lengths.append(PATTERN_LENGTHS[option["pattern"]])
        else:
            raise AssertionError(f"unbounded text in the contract: {option}")
    return max(lengths)


def _int_range(prop: dict[str, Any]) -> tuple[int, int]:
    lows, highs = [], []
    for option in _options(prop):
        assert option.get("type") == "integer", option
        assert "minimum" in option and "maximum" in option, f"unbounded integer: {option}"
        lows.append(option["minimum"])
        highs.append(option["maximum"])
    return min(lows), max(highs)


def _contract_columns() -> list[tuple[str, Column[Any], dict[str, Any]]]:
    cases = []
    for table, models in TABLE_MODELS.items():
        for column in table.columns:
            if column.name in NOT_FROM_CONTRACT:
                continue
            sources = models
            if (table.name, column.name) in OTHER_SOURCES:
                sources = (OTHER_SOURCES[(table.name, column.name)],)
            for model in sources:
                props = model.model_json_schema()["properties"]
                assert column.name in props, f"{table.name}.{column.name} not in {model.__name__}"
                cases.append(
                    (f"{table.name}.{column.name}/{model.__name__}", column, props[column.name])
                )
    return cases


CASES = _contract_columns()


@pytest.mark.parametrize(("name", "column", "prop"), CASES, ids=[c[0] for c in CASES])
def test_contract_limit_fits_the_column(
    name: str, column: Column[Any], prop: dict[str, Any]
) -> None:
    if isinstance(column.type, String) and column.type.length is not None:
        assert _max_length(prop) <= column.type.length, name
    for int_type, (low, high) in INT_RANGES.items():
        if type(column.type) is int_type:
            got_low, got_high = _int_range(prop)
            assert low <= got_low and got_high <= high, name
    if type(column.type) is Numeric:  # NUMERIC(p, 0): unsigned 64-bit addresses
        assert column.type.scale == 0 and column.type.precision is not None, name
        got_low, got_high = _int_range(prop)
        assert -(10**column.type.precision) < got_low and got_high < 10**column.type.precision


def test_parity_covers_the_bounded_columns() -> None:
    checked = {(c.table.name, c.name) for _, c, _ in CASES}
    for table in TABLE_MODELS:
        for column in table.columns:
            bounded = isinstance(column.type, String) and column.type.length is not None
            bounded = bounded or type(column.type) in INT_RANGES or type(column.type) is Numeric
            if bounded and column.name not in {"id", "organization_id", "job_id"}:
                assert (table.name, column.name) in checked or column.name == "total_bytes"


def test_derived_columns_are_bounded_by_the_row_builder() -> None:
    assert ingest.MAX_BIGINT == INT_RANGES[BigInteger][1]  # total_bytes is clamped to it
    assert ingest.RECORDS.c.summary.type.length is None  # TEXT, cut at SUMMARY_MAX anyway


def test_static_tables_are_covered() -> None:
    names = {t.name for t in TABLE_MODELS}
    assert {m.__tablename__ for m in static_models.RESULT_TABLES} <= names
    assert static_ingest.SECTIONS.c.virtual_address.type.precision == 20  # 2**64 - 1 fits
