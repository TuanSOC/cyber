"""API error codes of the evidence-level sensitivity for disk images and derived evidence (M9
phase 1, FROZEN; RT2). M8's `memory_sensitivity_restricted` / `_released` codes stay the codes
of memory evidence; these two answer for the `disk` and `derived` sources."""

from app.core.errors import Conflict


class EvidenceSensitivityRestricted(Conflict):
    """The share-policy flags of restricted disk (or derived) evidence cannot be cleared
    before an admin releases it."""

    code = "evidence_sensitivity_restricted"
    message = "This evidence is restricted (TLP:RED): an admin must release it first"


class EvidenceSensitivityReleased(Conflict):
    code = "evidence_sensitivity_released"
    message = "This evidence was already released"


ERROR_CODES = (EvidenceSensitivityRestricted.code, EvidenceSensitivityReleased.code)
