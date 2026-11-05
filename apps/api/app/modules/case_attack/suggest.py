"""ATT&CK suggestions of a case (frozen entry point of M6 phase 1; implemented by phase 5):
capa capabilities and finding ATT&CK ids of the latest jobs, and AI `attack_techniques` of
completed runs with at least one verified citation. Never confirmed automatically."""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.case_attack.schemas import AttackSuggestion


async def suggestions(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> list[AttackSuggestion]:
    """Phase 5."""
    raise NotImplementedError("case_attack.suggest.suggestions lands in M6 phase 5")
