"""The two string-driven function rules (M10 phase 5).

- `heuristic:re_runtime_api_resolution@1` (`low`; `medium` when at least 3 of the resolved
  names belong to one M3 suspicious set): the function calls a by-name resolver
  (`GetProcAddress`, `LdrGetProcedureAddress[Ex]`, `dlsym`, `dlvsym`) and references at least
  3 distinct strings that are exact API names (`api_names.API_NAMES`).
- `heuristic:re_network_string_function@1` (`low`): the function references a string that
  yields a URL / domain / IP observable and calls a network API (`connect`, `WSAConnect*`,
  `getaddrinfo` / `GetAddrInfo*`, `gethostbyname`, `InternetOpenUrl*`, `InternetConnect*`,
  `HttpOpenRequest*`, `URLDownloadTo*File*`, any `WinHttp*`).
"""

from cyberlab_worker.apisets import API_SETS

from re_worker.detections.base import (
    SET_LABELS,
    Finding,
    base_attributes,
    joined,
    name_values,
)
from re_worker.view import ReView

RESOLVERS = frozenset(
    {"GetProcAddress", "LdrGetProcedureAddress", "LdrGetProcedureAddressEx", "dlsym", "dlvsym"}
)
MIN_RESOLVED = 3
NETWORK_APIS = frozenset(
    {
        "connect", "WSAConnect", "WSAConnectByNameA", "WSAConnectByNameW", "getaddrinfo",
        "GetAddrInfoW", "GetAddrInfoExA", "GetAddrInfoExW", "gethostbyname", "InternetOpenUrlA",
        "InternetOpenUrlW", "InternetConnectA", "InternetConnectW", "HttpOpenRequestA",
        "HttpOpenRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
        "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
    }
)  # fmt: skip
SET_MEMBERS = {
    api_set.type: frozenset().union(*api_set.groups.values()) for api_set in API_SETS
}


def is_network_api(name: str) -> bool:
    return name in NETWORK_APIS or name.startswith("WinHttp")


def runtime_resolution(
    view: ReView, entry: int, names: frozenset[str], api_names: frozenset[str]
) -> Finding | None:
    resolvers = sorted(names & RESOLVERS)
    if not resolvers:
        return None
    resolved = sorted(
        {view.strings[i].value for i in view.strings_referenced(entry)} & api_names
    )
    if len(resolved) < MIN_RESOLVED:
        return None
    best_type, best = "", 0
    for set_type, members in SET_MEMBERS.items():
        overlap = len(members.intersection(resolved))
        if overlap > best:
            best_type, best = set_type, overlap
    medium = best >= MIN_RESOLVED
    set_note = f" {best} of them belong to the {SET_LABELS[best_type]} set." if medium else ""
    attributes = {
        **base_attributes(view, entry),
        "resolvers": joined(resolvers),
        "api_strings": len(resolved),
        "names": joined(resolved),
    }
    if medium:
        attributes["set"] = best_type
    return Finding(
        type="runtime_api_resolution",
        entry=entry,
        severity="medium" if medium else "low",
        confidence=0.6 if medium else 0.5,
        values={
            **name_values(view, entry),
            "resolvers": joined(resolvers),
            "count": len(resolved),
            "names": joined(resolved, 900),
            "set_note": set_note,
        },
        refs=[f"import:{r}" for r in resolvers],
        attributes=attributes,
    )


def network_string(
    view: ReView, entry: int, names: frozenset[str], indicators: list[str]
) -> Finding | None:
    apis = sorted(n for n in names if is_network_api(n))
    if not apis or not indicators:
        return None
    return Finding(
        type="network_string_function",
        entry=entry,
        severity="low",
        confidence=0.4,
        values={
            **name_values(view, entry),
            "indicators": joined(indicators, 600),
            "apis": joined(apis, 600),
        },
        refs=[f"import:{api}" for api in apis],
        attributes={
            **base_attributes(view, entry),
            "apis": joined(apis),
            "indicators": joined(indicators),
        },
    )
