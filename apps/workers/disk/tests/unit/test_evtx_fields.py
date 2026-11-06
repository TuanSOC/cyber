"""`detections.evtx_fields`: positional EVTX fields by (provider, event id, string count); an
unknown layout is reported (never guessed), and `xml_string` is never read."""

import ast
from pathlib import Path

import pytest
from cyberlab_jobs.disk import DiskEventRecord

from dataset import records as r
from disk_worker.detections import evtx_fields as ef

WHEN = r.ts("2026-10-06T10:00:00")
SECURITY = "Microsoft-Windows-Security-Auditing"
DETECTIONS = Path(ef.__file__).parent


def test_tables_fit_the_attribute_convention() -> None:
    for (provider, event_id), layouts in ef.LAYOUTS.items():
        assert provider == provider.casefold(), provider
        for count, fields in layouts.items():
            assert count <= ef.MAX_STRINGS, (provider, event_id, count)
            assert max(fields.values()) < count, (provider, event_id, count)
            assert len(set(fields.values())) == len(fields), (provider, event_id)


def test_flatten_strings_counts_and_cuts() -> None:
    flat = ef.flatten_strings(["a", None, 5, "x" * 2000] + ["-"] * 40)
    assert flat[ef.STRINGS_COUNT] == 44
    assert flat["strings.1"] == "" and flat["strings.2"] == "5"
    assert len(flat["strings.3"]) == 1024  # type: ignore[arg-type]
    assert f"strings.{ef.MAX_STRINGS}" not in flat


def test_4624_fields_by_position() -> None:
    record = ef.read(r.evtx(0, WHEN, SECURITY, 4624, r.logon_strings("alice", 10, "203.0.113.5")))
    assert record is not None and record.fields is not None
    assert record.provider == ef.SECURITY and record.event_id == 4624
    assert record.get("TargetUserName") == "alice"
    assert record.get("LogonType") == "10"
    assert record.get("IpAddress") == "203.0.113.5"


@pytest.mark.parametrize("count", [20, 23, 27])
def test_4624_versions_share_the_first_twenty_positions(count: int) -> None:
    strings = r.logon_strings("bob", 3, "198.51.100.1")[:count]
    record = ef.read(r.evtx(0, WHEN, SECURITY, 4624, strings))
    assert record is not None and record.get("IpAddress") == "198.51.100.1"


def test_unknown_layout_is_reported_not_guessed() -> None:
    record = ef.read(
        r.evtx(0, WHEN, SECURITY, 4624, ["S-1-0-0", "-", "alice", "WKS", "10", "203.0.113.5"])
    )
    assert record is not None and record.fields is None and record.get("IpAddress") is None


def test_provider_aliases_and_qualifiers() -> None:
    event = r.evtx(
        0, WHEN, "Service Control Manager", 7045, r.service_strings("x", "C:\\x.exe"), "System"
    )
    attrs = dict(event.attributes)
    attrs["event_identifier"] = 7045 | (16384 << 16)  # qualifiers folded into the id
    attrs["source_name"] = "Microsoft-Windows-Service Control Manager"
    record = ef.read(event.model_copy(update={"attributes": attrs}))
    assert (
        record is not None and record.provider == ef.SCM and record.get("ImagePath") == "C:\\x.exe"
    )


def test_non_evtx_and_id_less_events_are_none() -> None:
    other = r.event(0, WHEN, "syslog", "syslog:line", "var/log/syslog", "x")
    assert ef.read(other) is None
    no_id = r.evtx(0, WHEN, SECURITY, 4624, [])
    attrs = {k: v for k, v in no_id.attributes.items() if k != "event_identifier"}
    assert (
        ef.read(DiskEventRecord.model_validate({**no_id.model_dump(), "attributes": attrs})) is None
    )


def test_xml_string_is_never_read() -> None:
    """No detection module mentions `xml_string` outside comments / docstrings."""
    for path in DETECTIONS.glob("*.py"):
        tree = ast.parse(path.read_text("utf-8"))
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                assert "xml_string" not in node.value, path.name
            if isinstance(node, ast.Name | ast.Attribute):
                assert "xml" not in (getattr(node, "id", "") or getattr(node, "attr", "")), (
                    path.name
                )


def test_a_record_carrying_xml_is_read_from_strings_only() -> None:
    event = r.evtx(0, WHEN, SECURITY, 4624, r.logon_strings("alice", 10, "203.0.113.5"))
    attrs = dict(event.attributes)
    attrs["xml_string"] = "<Event><Data Name='IpAddress'>198.51.100.99</Data></Event>"
    record = ef.read(event.model_copy(update={"attributes": attrs}))
    assert record is not None and record.get("IpAddress") == "203.0.113.5"
