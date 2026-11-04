"""Shared types of the route-wide IDOR suite (M5 phase 1 split, RT11).

`test_idor_routes.py` merges the cases of every `idor_cases_*.py` module; a module owns its
routes' cases and may seed extra victim resources (`VICTIM_EXTENDERS`, results land in
`Victim.extra`), override path parameters of its own templates (`PATH_OVERRIDES`), declare new
resource parameters (`RESOURCE_PARAMS`) and add to the "nothing changed" snapshot
(`STATE_HOOKS`).
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from tests.factories import Registered


@dataclass(frozen=True)
class Victim:
    """Resources owned by another organization."""

    org_id: uuid.UUID
    member_id: str  # an analyst in the victim org (not the owner, so the owner may change it)
    investigation_id: str
    evidence_id: str
    job_id: str  # an analysis job (on a second evidence, so the first can still be analyzed)
    static_job_id: str  # the second evidence's automatic static job, with results
    outsider_email: str  # a real user who is not a member of the victim org
    run_id: str  # a threat intel enrichment run
    result_id: str  # one of its provider answers
    provider: str = "mock"  # a configured, enabled provider (not an org-owned id)
    # Resources seeded by the case modules' VICTIM_EXTENDERS (e.g. "ai_run_id").
    extra: dict[str, str] = field(default_factory=dict)


Request = dict[str, Any]
CaseBuilder = Callable[[Victim], Request]
RouteCases = dict[tuple[str, str], CaseBuilder]
# (owner, victim) -> extra resource ids, merged into Victim.extra.
VictimExtender = Callable[[Registered, Victim], Awaitable[dict[str, str]]]
# path template -> victim -> path parameters that replace the defaults for that template.
PathOverrides = dict[str, Callable[[Victim], dict[str, str]]]
# (owner, victim) -> a JSON-able snapshot that must not change after an attack.
StateHook = Callable[[Registered, Victim], Awaitable[dict[str, Any]]]
