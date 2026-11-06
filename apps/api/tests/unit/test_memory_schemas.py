"""Memory read models send addresses as hex text (review fix: a JSON number above 2**53 loses
its low bits in the browser, and kernel addresses are above 2**63)."""

import uuid
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.modules.memory_analysis.schemas import ArtifactOut, ConnectionOut, InjectionOut

KERNEL = 0xFFFF_F800_1234_5678


def _region(**over: object) -> dict[str, object]:
    return {
        "id": uuid.uuid4(),
        "pid": 4,
        "process": "System",
        "start": Decimal(KERNEL),
        "end": KERNEL + 0xFFF,
        "protection": None,
        "tag": None,
        "private": None,
        "commit_charge": None,
        "has_pe": False,
        "head_hex": "",
        "disasm": None,
        **over,
    }


def test_addresses_serialize_as_hex_strings() -> None:
    out = InjectionOut.model_validate(_region()).model_dump(mode="json")
    assert out["start"] == "0xfffff80012345678"
    assert out["end"] == f"0x{KERNEL + 0xFFF:x}"
    schema = InjectionOut.model_json_schema(mode="serialization")
    assert schema["properties"]["start"]["type"] == "string"


def test_address_range_is_checked() -> None:
    with pytest.raises(ValidationError):
        InjectionOut.model_validate(_region(start=2**64))
    with pytest.raises(ValidationError):
        InjectionOut.model_validate(_region(start=-1))


def test_optional_offset_stays_null() -> None:
    row = {
        "id": uuid.uuid4(),
        "proto": "TCPv4",
        "local_addr": None,
        "local_port": None,
        "remote_addr": None,
        "remote_port": None,
        "state": None,
        "pid": None,
        "owner": None,
        "created": None,
        "offset": None,
    }
    assert ConnectionOut.model_validate(row).offset is None
    assert ConnectionOut.model_validate({**row, "offset": Decimal(4096)}).offset == "0x1000"


def test_address_attributes_become_hex_and_others_stay() -> None:
    art = ArtifactOut.model_validate(
        {
            "id": uuid.uuid4(),
            "type": "module",
            "pid": 4,
            "attributes": {
                "base": 2**62 + 1,
                "offset": "0xffff800000000000",
                "size": 2**60,
                "in_load": True,
                "name": "ntdll.dll",
            },
        }
    ).model_dump(mode="json")
    attrs = art["attributes"]
    assert attrs["base"] == f"0x{2**62 + 1:x}"
    assert attrs["offset"] == "0xffff800000000000"
    assert attrs["size"] == 2**60  # not an address: the UI marks it approximate
    assert attrs["in_load"] is True and attrs["name"] == "ntdll.dll"
