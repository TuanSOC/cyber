"""`GET /api/v1/attack/techniques?ids=...`: labels for T-ids plus the version and MITRE notice."""

import re
from collections.abc import Iterable

from app.core.errors import AppError
from app.modules.attack import index
from app.modules.attack.schemas import TECHNIQUE_ID_PATTERN, AttackLabel, AttackTechniquesOut

MAX_IDS = 100
# Generous bound on the raw query value before splitting (100 ids of 9 chars plus commas).
MAX_IDS_PARAM_LENGTH = 2000
_TECHNIQUE_ID = re.compile(TECHNIQUE_ID_PATTERN)


class InvalidAttackIds(AppError):
    status_code = 422
    code = "invalid_attack_ids"
    message = f"ids must be at most {MAX_IDS} comma-separated ATT&CK technique ids (T1234[.001])"


def parse_ids(raw: str | None) -> list[str]:
    """Split `T1055,T1059.001`; trims, uppercases, de-duplicates (order kept); empty is allowed."""
    if not raw:
        return []
    if len(raw) > MAX_IDS_PARAM_LENGTH:
        raise InvalidAttackIds()
    ids: list[str] = []
    for part in raw.split(","):
        tid = part.strip().upper()
        if not tid:
            continue
        if not _TECHNIQUE_ID.fullmatch(tid):
            raise InvalidAttackIds()
        if tid not in ids:
            ids.append(tid)
    if len(ids) > MAX_IDS:
        raise InvalidAttackIds()
    return ids


def lookup_techniques(ids: Iterable[str]) -> AttackTechniquesOut:
    """Labels for already-parsed ids; ids absent from the index are listed in `unknown`."""
    labels: list[AttackLabel] = []
    unknown: list[str] = []
    for tid in ids:
        found = index.label(tid)
        if found is None:
            unknown.append(tid)
        else:
            labels.append(found)
    return AttackTechniquesOut(meta=index.meta(), techniques=labels, unknown=unknown)


def techniques_response(raw_ids: str | None) -> AttackTechniquesOut:
    """Route body: parse the `ids` query value (422 on bad input), then label."""
    return lookup_techniques(parse_ids(raw_ids))
