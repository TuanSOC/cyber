"""STIX 2.1 bundle of an IOC collection (M6, RT18). Pure: no I/O.

- One `indicator` per item, its pattern built from the escaped value (`'` and `\\` escaped
  per the STIX 2.1 pattern grammar). Types without a STIX object path (`ja3`, `ja3s`,
  `file_path`) get no pattern and are skipped with a count, never guessed.
- Ids are deterministic `uuid5`s: an indicator from (org, collection, ioc_key), the identity
  from the org, the bundle from (org, collection, exported_at).
- Every indicator and the identity carry `object_marking_refs` to the TLP 2.0
  marking-definition of the case's TLP: the OASIS `cti-stix-common-objects` id from
  `cyberlab_jobs.report.STIX_TLP_MARKINGS`, whose object is included in the bundle.
- `created_by_ref` is an `identity` (class `organization`) named after the org.
- With `defang=True` (the default of the export route) the pattern holds the defanged value
  and the indicator says so (`x_cyberlab_defanged`): such a bundle documents, it does not
  match. Only `defang=False` gives matchable patterns.
"""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cyberlab_jobs.report import STIX_TLP_MARKINGS, TLP

from app.modules.ioc_collections.normalize import defang as defang_value

# The namespace of every deterministic CyberLab STIX id (a fixed, random UUID).
STIX_NAMESPACE = uuid.UUID("6f0c8f7e-3b8e-5d2a-9a41-c1b7e0d4a6f3")

# ioc_type -> STIX object path of the comparison (the left side of `[path = 'value']`).
PATTERN_PATHS: dict[str, str] = {
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "email": "email-addr:value",
    "md5": "file:hashes.MD5",
    "sha1": "file:hashes.'SHA-1'",
    "sha256": "file:hashes.'SHA-256'",
    "cert_sha256": "x509-certificate:hashes.'SHA-256'",
    "registry_key": "windows-registry-key:key",
}


@dataclass(frozen=True)
class StixItem:
    ioc_type: str
    value: str
    ioc_key: str
    added_at: datetime
    note: str | None = None


@dataclass(frozen=True)
class StixBundle:
    bundle: dict[str, Any]
    indicators: int
    skipped: int


def escape_pattern_value(value: str) -> str:
    """A STIX 2.1 pattern string literal body: backslash and single quote escaped."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pattern(ioc_type: str, value: str) -> str | None:
    path = PATTERN_PATHS.get(ioc_type)
    if path is None:
        return None
    return f"[{path} = '{escape_pattern_value(value)}']"


def stix_time(ts: datetime) -> str:
    """STIX timestamps: UTC, `Z`, millisecond precision."""
    ts = ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def indicator_id(org_id: uuid.UUID, collection_id: uuid.UUID, ioc_key: str) -> str:
    return f"indicator--{uuid.uuid5(STIX_NAMESPACE, f'{org_id}:{collection_id}:{ioc_key}')}"


def identity_id(org_id: uuid.UUID) -> str:
    return f"identity--{uuid.uuid5(STIX_NAMESPACE, f'org:{org_id}')}"


def build_bundle(
    *,
    org_id: uuid.UUID,
    org_name: str,
    org_created_at: datetime,
    collection_id: uuid.UUID,
    collection_name: str,
    tlp: TLP,
    items: Sequence[StixItem],
    exported_at: datetime,
    defang: bool = True,
) -> StixBundle:
    marking = STIX_TLP_MARKINGS[tlp]
    marking_refs = [marking["id"]]
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id(org_id),
        "created": stix_time(org_created_at),
        "modified": stix_time(org_created_at),
        "name": org_name,
        "identity_class": "organization",
        "object_marking_refs": marking_refs,
    }
    indicators: list[dict[str, Any]] = []
    skipped = 0
    for item in items:
        value = defang_value(item.ioc_type, item.value) if defang else item.value
        built = pattern(item.ioc_type, value)
        if built is None:
            skipped += 1
            continue
        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id(org_id, collection_id, item.ioc_key),
            "created_by_ref": identity["id"],
            "created": stix_time(item.added_at),
            "modified": stix_time(item.added_at),
            "name": f"{item.ioc_type}: {value}",
            "indicator_types": ["unknown"],
            "pattern": built,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": stix_time(item.added_at),
            "labels": [f"collection:{collection_name}"],
            "object_marking_refs": marking_refs,
        }
        if item.note:
            indicator["description"] = item.note
        if defang:
            indicator["x_cyberlab_defanged"] = True
        indicators.append(indicator)
    bundle_id = uuid.uuid5(STIX_NAMESPACE, f"{org_id}:{collection_id}:{exported_at.isoformat()}")
    bundle = {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": [marking, identity, *indicators],
    }
    return StixBundle(bundle=bundle, indicators=len(indicators), skipped=skipped)
