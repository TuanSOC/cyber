"""ATT&CK label route (registered in `app/main.py`)."""

from typing import Annotated

from fastapi import APIRouter, Query

from app.core.deps import CurrentUserDep
from app.modules.attack.schemas import AttackTechniquesOut
from app.modules.attack.service import techniques_response

router = APIRouter(tags=["attack"])


@router.get("/attack/techniques", response_model=AttackTechniquesOut)
async def attack_techniques(
    _user: CurrentUserDep, ids: Annotated[str | None, Query(max_length=2000)] = None
) -> AttackTechniquesOut:
    """Labels for MITRE ATT&CK technique ids from the pinned offline index, with its notice."""
    return techniques_response(ids)
