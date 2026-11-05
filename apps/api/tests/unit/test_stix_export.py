"""IOC export builders (M6 phase 2): the STIX 2.1 bundle (patterns, escaping, deterministic
ids, the OASIS TLP 2.0 markings), defanging and the formula-safe CSV."""

import json
import re
import uuid
from datetime import UTC, datetime

import pytest
from cyberlab_jobs.report import STIX_TLP_EXTENSION_ID, STIX_TLP_MARKINGS, TLP

from app.core.csv_safe import csv_safe, write_csv
from app.modules.ioc_collections import stix
from app.modules.ioc_collections.normalize import (
    Invalid,
    Item,
    defang,
    normalize_item,
    ti_eligible,
)
from app.modules.threat_intel.normalize import Normalized, normalize

ORG = uuid.UUID("11111111-1111-4111-8111-111111111111")
COLLECTION = uuid.UUID("22222222-2222-4222-8222-222222222222")
T = datetime(2026, 11, 5, 12, 30, 45, 123456, tzinfo=UTC)
OASIS_IDS = {
    TLP.CLEAR: "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    TLP.GREEN: "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    TLP.AMBER: "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    TLP.AMBER_STRICT: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    TLP.RED: "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}


def _item(ioc_type: str, value: str, key: str | None = None) -> stix.StixItem:
    return stix.StixItem(ioc_type, value, key or f"{abs(hash((ioc_type, value))):064x}"[:64], T)


def _bundle(*items: stix.StixItem, tlp: TLP = TLP.AMBER, defang_: bool = False) -> stix.StixBundle:
    return stix.build_bundle(
        org_id=ORG,
        org_name="Acme IR",
        org_created_at=T,
        collection_id=COLLECTION,
        collection_name="Blocklist",
        tlp=tlp,
        items=items,
        exported_at=T,
        defang=defang_,
    )


# --- patterns -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        ("ipv4", "203.0.113.9", "[ipv4-addr:value = '203.0.113.9']"),
        ("ipv6", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("domain", "evil.com", "[domain-name:value = 'evil.com']"),
        ("url", "https://evil.com/a", "[url:value = 'https://evil.com/a']"),
        ("email", "a@evil.com", "[email-addr:value = 'a@evil.com']"),
        ("md5", "a" * 32, f"[file:hashes.MD5 = '{'a' * 32}']"),
        ("sha1", "b" * 40, f"[file:hashes.'SHA-1' = '{'b' * 40}']"),
        ("sha256", "c" * 64, f"[file:hashes.'SHA-256' = '{'c' * 64}']"),
        ("cert_sha256", "d" * 64, f"[x509-certificate:hashes.'SHA-256' = '{'d' * 64}']"),
        ("registry_key", "HKLM\\Run", "[windows-registry-key:key = 'HKLM\\\\Run']"),
    ],
)
def test_patterns(ioc_type: str, value: str, expected: str) -> None:
    assert stix.pattern(ioc_type, value) == expected


@pytest.mark.parametrize(
    "hostile",
    [
        "evil.com' OR [file:name = 'x",
        "a\\' ] OR [x:y = 'z",
        "back\\slash'quote",
        "'']",
        "\\",
    ],
)
def test_hostile_values_cannot_break_out_of_the_literal(hostile: str) -> None:
    built = stix.pattern("url", hostile)
    assert built is not None
    assert built.startswith("[url:value = '") and built.endswith("']")
    body = built[len("[url:value = '") : -2]
    # Every quote inside the literal is escaped, and the escaping is reversible.
    assert re.fullmatch(r"(?:[^'\\]|\\['\\])*", body), body
    unescaped = re.sub(r"\\(['\\])", r"\1", body)
    assert unescaped == hostile


@pytest.mark.parametrize("ioc_type", ["ja3", "ja3s", "file_path", "unknown"])
def test_types_without_a_stix_path_are_skipped_with_a_count(ioc_type: str) -> None:
    assert stix.pattern(ioc_type, "x") is None
    built = _bundle(_item(ioc_type, "x"), _item("domain", "evil.com"))
    assert (built.indicators, built.skipped) == (1, 1)


# --- bundle -----------------------------------------------------------------------------------


def test_bundle_shape_marking_and_identity() -> None:
    built = _bundle(_item("domain", "evil.com", "k" * 64), tlp=TLP.AMBER_STRICT)
    objects = built.bundle["objects"]
    assert built.bundle["type"] == "bundle" and built.bundle["id"].startswith("bundle--")
    marking, identity, indicator = objects
    assert marking == STIX_TLP_MARKINGS[TLP.AMBER_STRICT]
    assert marking["extensions"][STIX_TLP_EXTENSION_ID]["tlp_2_0"] == "amber+strict"
    assert identity["type"] == "identity" and identity["name"] == "Acme IR"
    assert identity["identity_class"] == "organization"
    assert indicator["created_by_ref"] == identity["id"]
    for obj in (identity, indicator):
        assert obj["object_marking_refs"] == [OASIS_IDS[TLP.AMBER_STRICT]]
        assert obj["spec_version"] == "2.1"
    assert indicator["pattern_type"] == "stix"
    assert indicator["valid_from"] == "2026-11-05T12:30:45.123Z"
    assert "x_cyberlab_defanged" not in indicator
    json.dumps(built.bundle)  # serializable


@pytest.mark.parametrize("tlp", list(TLP))
def test_the_five_oasis_tlp_marking_ids(tlp: TLP) -> None:
    built = _bundle(_item("domain", "evil.com"), tlp=tlp)
    marking = built.bundle["objects"][0]
    assert marking["id"] == OASIS_IDS[tlp]
    assert marking["type"] == "marking-definition"
    assert built.bundle["objects"][2]["object_marking_refs"] == [OASIS_IDS[tlp]]


def test_ids_are_deterministic() -> None:
    a = _bundle(_item("domain", "evil.com", "a" * 64), _item("ipv4", "203.0.113.9", "b" * 64))
    b = _bundle(_item("domain", "evil.com", "a" * 64), _item("ipv4", "203.0.113.9", "b" * 64))
    assert a.bundle == b.bundle
    ids = [o["id"] for o in a.bundle["objects"][2:]]
    assert ids[0] == stix.indicator_id(ORG, COLLECTION, "a" * 64)
    assert ids[0] != ids[1]
    other = stix.indicator_id(uuid.uuid4(), COLLECTION, "a" * 64)
    assert other != ids[0]
    assert re.fullmatch(r"indicator--[0-9a-f-]{36}", ids[0])
    assert uuid.UUID(ids[0].removeprefix("indicator--")).version == 5


def test_defanged_bundle_says_so() -> None:
    built = _bundle(_item("url", "https://evil.com/a"), defang_=True)
    indicator = built.bundle["objects"][2]
    assert indicator["pattern"] == "[url:value = 'hxxps[:]//evil[.]com/a']"
    assert indicator["x_cyberlab_defanged"] is True


# --- defang ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        ("domain", "evil.com", "evil[.]com"),
        ("ipv4", "10.0.0.1", "10[.]0[.]0[.]1"),
        ("url", "http://evil.com/x.php", "hxxp[:]//evil[.]com/x[.]php"),
        ("url", "https://evil.com/", "hxxps[:]//evil[.]com/"),
        ("email", "a@evil.com", "a[@]evil[.]com"),
        ("sha256", "a" * 64, "a" * 64),
        ("registry_key", "HKLM\\a.b", "HKLM\\a.b"),
    ],
)
def test_defang(ioc_type: str, value: str, expected: str) -> None:
    assert defang(ioc_type, value) == expected


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        ("domain", "evil.com"),
        ("url", "https://evil.com/a"),
        ("email", "a@evil.com"),
        ("ipv4", "203.0.113.9"),
    ],
)
def test_defanged_values_refang_to_the_same_indicator(ioc_type: str, value: str) -> None:
    refanged = normalize(ioc_type, defang(ioc_type, value))
    direct = normalize(ioc_type, value)
    assert type(refanged) is type(direct)
    if isinstance(direct, Normalized):
        assert isinstance(refanged, Normalized) and refanged.ioc_key == direct.ioc_key


# --- normalization fallbacks -------------------------------------------------------------------


def test_private_and_internal_values_are_kept_but_not_eligible() -> None:
    for type_name, raw, value in [
        ("ip", "192.168.1.10", "192.168.1.10"),
        ("ipv6", "fe80::1", "fe80::1"),
        ("domain", "HOST01", "host01"),
        ("email", "admin@corp", "admin@corp"),
    ]:
        item = normalize_item(type_name, raw)
        assert isinstance(item, Item), (type_name, raw, item)
        assert (item.value_norm, item.ti_eligible) == (value, False)
        assert ti_eligible(item.ioc_type, item.value_norm) is False
    public = normalize_item("domain", "evil.com")
    assert isinstance(public, Item) and public.ti_eligible
    assert ti_eligible(public.ioc_type, public.value_norm)
    assert normalize_item("domain", "x" * 3000) == Invalid("too_long")
    assert normalize_item("domain", "   ") == Invalid("invalid")


# --- CSV ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cell",
    [
        "=1+1",
        "+cmd",
        "-2",
        "@SUM(A1)",
        "\t=x",
        "\r=x",
        "  =1+1",
        "　=x",
        "＝1",
        "＋1",
        "－1",
        "＠x",
    ],
)
def test_formula_cells_are_quoted(cell: str) -> None:
    assert csv_safe(cell) == "'" + cell


def test_csv_quotes_values_and_keeps_rows_intact() -> None:
    rows = [("type", "value"), ("domain", 'evil".com,=x'), ("url", "http://a/b\r\nc")]
    data = b"".join(write_csv(rows, header_comment="# TLP:AMBER")).decode()
    assert data.startswith("# TLP:AMBER\r\n")
    assert '"evil"".com,=x"' in data
    assert '"http://a/b\r\nc"' in data
    assert "'=" not in data.split("\r\n")[2]  # not a leading formula: unchanged


def test_stix_time_is_utc_millis() -> None:
    assert stix.stix_time(datetime(2026, 1, 2, 3, 4, 5, 999999, tzinfo=UTC)) == (
        "2026-01-02T03:04:05.999Z"
    )
