"""EVTX event fields by position (M9 phase 6).

Event-specific values are read from Plaso's positional `strings` (the substitution values of the
record, in template order) through fixed index tables keyed by (provider, event id, string
count). `xml_string` is never read: it is attacker-controlled XML and parsing it in the trusted
root process is out of the question. A record whose string count is not in the table ("unknown
layout") is not guessed at: the caller skips the rule for that event and counts it.

**Attribute convention** (shared with phase 3's normaliser, which calls `flatten_strings`): a
normalised `windows:evtx:record` event carries
- `event_identifier` (int), `source_name` (str, the provider);
- `strings_count` (int): the number of strings Plaso exported, before any cut;
- `strings.<i>` (str, <= 1 024 characters): the i-th string, for the first `MAX_STRINGS`.

The tables follow the documented event schemas (Security auditing 4624 v0-v2, 4625, 4688 v0-v2,
4720, 4722, 4728, 4732; Eventlog 1102, 104; Service Control Manager 7045). Fields at the same
index across versions share one map.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from cyberlab_jobs.disk import DiskEventRecord

DATA_TYPE = "windows:evtx:record"
STRINGS_PREFIX = "strings."
STRINGS_COUNT = "strings_count"
MAX_STRINGS = 28  # 4624 v2 has 27; with the identifiers this stays within 32 attributes
MAX_STRING_CHARS = 1024

SECURITY = "microsoft-windows-security-auditing"
EVENTLOG = "microsoft-windows-eventlog"
SCM = "service control manager"
# Provider spellings Plaso reports (case-folded) -> the table key.
PROVIDER_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        SECURITY: SECURITY,
        EVENTLOG: EVENTLOG,
        "eventlog": EVENTLOG,
        SCM: SCM,
        "microsoft-windows-service control manager": SCM,
    }
)

_LOGON_V0 = {
    "SubjectUserSid": 0,
    "SubjectUserName": 1,
    "SubjectDomainName": 2,
    "SubjectLogonId": 3,
    "TargetUserSid": 4,
    "TargetUserName": 5,
    "TargetDomainName": 6,
    "TargetLogonId": 7,
    "LogonType": 8,
    "LogonProcessName": 9,
    "AuthenticationPackageName": 10,
    "WorkstationName": 11,
    "LogonGuid": 12,
    "TransmittedServices": 13,
    "LmPackageName": 14,
    "KeyLength": 15,
    "ProcessId": 16,
    "ProcessName": 17,
    "IpAddress": 18,
    "IpPort": 19,
}
_LOGON_FAILED = {
    "SubjectUserSid": 0,
    "SubjectUserName": 1,
    "SubjectDomainName": 2,
    "SubjectLogonId": 3,
    "TargetUserSid": 4,
    "TargetUserName": 5,
    "TargetDomainName": 6,
    "Status": 7,
    "FailureReason": 8,
    "SubStatus": 9,
    "LogonType": 10,
    "LogonProcessName": 11,
    "AuthenticationPackageName": 12,
    "WorkstationName": 13,
    "TransmittedServices": 14,
    "LmPackageName": 15,
    "KeyLength": 16,
    "ProcessId": 17,
    "ProcessName": 18,
    "IpAddress": 19,
    "IpPort": 20,
}
_PROCESS_V0 = {
    "SubjectUserSid": 0,
    "SubjectUserName": 1,
    "SubjectDomainName": 2,
    "SubjectLogonId": 3,
    "NewProcessId": 4,
    "NewProcessName": 5,
    "TokenElevationType": 6,
    "ProcessId": 7,
}
_PROCESS_V1 = {**_PROCESS_V0, "CommandLine": 8}
_PROCESS_V2 = {
    **_PROCESS_V1,
    "TargetUserSid": 9,
    "TargetUserName": 10,
    "TargetDomainName": 11,
    "TargetLogonId": 12,
    "ParentProcessName": 13,
    "MandatoryLabel": 14,
}
_USER_TARGET = {
    "TargetUserName": 0,
    "TargetDomainName": 1,
    "TargetSid": 2,
    "SubjectUserSid": 3,
    "SubjectUserName": 4,
    "SubjectDomainName": 5,
    "SubjectLogonId": 6,
}
_GROUP_MEMBER = {
    "MemberName": 0,
    "MemberSid": 1,
    "TargetUserName": 2,
    "TargetDomainName": 3,
    "TargetSid": 4,
    "SubjectUserSid": 5,
    "SubjectUserName": 6,
    "SubjectDomainName": 7,
    "SubjectLogonId": 8,
    "PrivilegeList": 9,
}
_LOG_CLEARED_SECURITY = {
    "SubjectUserSid": 0,
    "SubjectUserName": 1,
    "SubjectDomainName": 2,
    "SubjectLogonId": 3,
}
_LOG_CLEARED_OTHER_V0 = {"SubjectUserName": 0, "SubjectDomainName": 1, "Channel": 2}
_LOG_CLEARED_OTHER = {**_LOG_CLEARED_OTHER_V0, "BackupPath": 3}
_SERVICE_INSTALLED_V0 = {"ServiceName": 0, "ImagePath": 1, "ServiceType": 2, "StartType": 3}
_SERVICE_INSTALLED = {**_SERVICE_INSTALLED_V0, "AccountName": 4}

FieldMap = Mapping[str, int]
# (provider, event id) -> {string count: field -> index}.
LAYOUTS: Mapping[tuple[str, int], Mapping[int, FieldMap]] = MappingProxyType(
    {
        (SECURITY, 4624): {20: _LOGON_V0, 23: _LOGON_V0, 27: _LOGON_V0},
        (SECURITY, 4625): {21: _LOGON_FAILED},
        (SECURITY, 4688): {8: _PROCESS_V0, 9: _PROCESS_V1, 15: _PROCESS_V2},
        (SECURITY, 4720): {26: _USER_TARGET, 27: _USER_TARGET},
        (SECURITY, 4722): {7: _USER_TARGET},
        (SECURITY, 4728): {10: _GROUP_MEMBER},
        (SECURITY, 4732): {10: _GROUP_MEMBER},
        (EVENTLOG, 1102): {4: _LOG_CLEARED_SECURITY},
        (EVENTLOG, 104): {3: _LOG_CLEARED_OTHER_V0, 4: _LOG_CLEARED_OTHER},
        (SCM, 7045): {4: _SERVICE_INSTALLED_V0, 5: _SERVICE_INSTALLED},
    }
)
# Every string count of the tables fits under MAX_STRINGS (checked by the table test).


@dataclass(frozen=True)
class EvtxRecord:
    provider: str  # the table key (case-folded alias target), or the case-folded raw name
    event_id: int
    fields: Mapping[str, str] | None  # None: unknown layout (skip and count)

    def get(self, name: str) -> str | None:
        return None if self.fields is None else self.fields.get(name)


def flatten_strings(strings: Sequence[object]) -> dict[str, str | int]:
    """The attribute form of Plaso's `strings` list (phase 3 calls this)."""
    out: dict[str, str | int] = {STRINGS_COUNT: len(strings)}
    for i, value in enumerate(strings[:MAX_STRINGS]):
        text = value if isinstance(value, str) else "" if value is None else str(value)
        out[f"{STRINGS_PREFIX}{i}"] = text.replace("\x00", "")[:MAX_STRING_CHARS]
    return out


def _event_id(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value & 0xFFFF  # drop the qualifiers some exports fold into the id


def _strings(attributes: Mapping[str, object]) -> tuple[int, dict[int, str]] | None:
    count = attributes.get(STRINGS_COUNT)
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return None
    values: dict[int, str] = {}
    for i in range(min(count, MAX_STRINGS)):
        value = attributes.get(f"{STRINGS_PREFIX}{i}")
        if isinstance(value, str):
            values[i] = value
    return count, values


def read(event: DiskEventRecord) -> EvtxRecord | None:
    """The record's provider, id and (when the layout is known) its named fields; None when the
    event is not an EVTX record with an identifier."""
    if event.data_type != DATA_TYPE:
        return None
    attrs = event.attributes
    event_id = _event_id(attrs.get("event_identifier"))
    if event_id is None:
        return None
    raw_provider = attrs.get("source_name")
    provider = raw_provider.casefold() if isinstance(raw_provider, str) else ""
    provider = PROVIDER_ALIASES.get(provider, provider)
    layouts = LAYOUTS.get((provider, event_id))
    strings = _strings(attrs)
    if layouts is None or strings is None:
        return EvtxRecord(provider, event_id, None)
    count, values = strings
    layout = layouts.get(count)
    if layout is None:
        return EvtxRecord(provider, event_id, None)
    fields = {name: values[i] for name, i in layout.items() if i in values}
    return EvtxRecord(provider, event_id, MappingProxyType(fields))


def known(provider: str, event_id: int) -> bool:
    return (provider, event_id) in LAYOUTS


__all__ = [
    "DATA_TYPE",
    "EVENTLOG",
    "LAYOUTS",
    "MAX_STRINGS",
    "SCM",
    "SECURITY",
    "STRINGS_COUNT",
    "STRINGS_PREFIX",
    "EvtxRecord",
    "flatten_strings",
    "known",
    "read",
]
