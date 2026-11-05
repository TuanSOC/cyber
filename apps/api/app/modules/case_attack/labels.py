"""ATT&CK labels and tactic order for case mappings, from the pinned offline v20 index.

The index stores tactics as a key-sorted map, so the kill-chain order of the Enterprise
matrix is pinned here. Since v19, Defense Evasion (TA0005) is split into Stealth (TA0005)
and Defense Impairment (TA0112); both sit where Defense Evasion was. A tactic that the
index holds but this order does not (a future index bump) is appended alphabetically, so
nothing is ever dropped from the matrix.
"""

import re

from app.modules.attack.index import get_index
from app.modules.attack.schemas import AttackTechniqueEntry
from app.modules.case_attack.schemas import TechniqueLabel

TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
# A T-id inside free text (capa lists, finding attributes such as "T1055.012, T1622"). The
# look-arounds refuse a cut-off id ("T1055.0...") rather than reading it as its parent.
_TID_IN_TEXT = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![0-9.])")


def tactic_shortnames() -> list[str]:
    """Every tactic of the index, in matrix order."""
    tactics = get_index().tactics
    known = [s for s in TACTIC_ORDER if s in tactics]
    return known + sorted(set(tactics) - set(TACTIC_ORDER))


def tactic_name(shortname: str) -> str:
    return get_index().tactics.get(shortname, shortname)


def entry(technique_id: str) -> AttackTechniqueEntry | None:
    return get_index().techniques.get(technique_id)


def is_mappable(technique_id: str) -> bool:
    """In the v20 index, and neither revoked nor deprecated."""
    found = entry(technique_id)
    return found is not None and found.revoked_by is None and not found.deprecated


def technique_label(technique_id: str) -> TechniqueLabel:
    """The id's own index entry (a revoked id is flagged, never silently replaced)."""
    found = entry(technique_id)
    if found is None:
        return TechniqueLabel(
            technique_id=technique_id,
            name=None,
            tactics=[],
            url=None,
            revoked=False,
            deprecated=False,
        )
    return TechniqueLabel(
        technique_id=technique_id,
        name=found.name,
        tactics=[tactic_name(s) for s in found.tactics],
        url=found.url or None,
        revoked=found.revoked_by is not None,
        deprecated=found.deprecated,
    )


def technique_ids_in(value: object) -> list[str]:
    """T-ids in a string or a list of strings (order kept, de-duplicated)."""
    texts = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    found: list[str] = []
    for text in texts:
        if not isinstance(text, str):
            continue
        for tid in _TID_IN_TEXT.findall(text):
            if tid not in found:
                found.append(tid)
    return found
