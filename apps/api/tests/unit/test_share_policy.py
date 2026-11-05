"""The pure parts of `investigations/policy.py` (M6 phase 1): case-level resolution, the TLP
order and the 409 body. The database resolution and the call sites are integration tests
(`tests/integration/test_share_policy.py`)."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.errors import register_error_handlers
from app.modules.investigations.policy import (
    CASE_AI_EXCLUDED,
    CASE_TI_EXCLUDED,
    TLP_RED,
    PolicyBlocked,
    case_policy,
    is_downgrade,
    raise_if_ai_blocked,
    raise_if_ti_blocked,
    tlp_at_least,
)


def test_nothing_set_blocks_nothing() -> None:
    policy = case_policy("amber", False, False)
    assert (policy.ai_blocked, policy.ti_blocked, policy.reasons) == (False, False, [])
    raise_if_ai_blocked(policy)
    raise_if_ti_blocked(policy)


def test_red_implies_both() -> None:
    policy = case_policy("red", False, False)
    assert policy.ai_blocked and policy.ti_blocked
    assert policy.ai_reason == policy.ti_reason == TLP_RED


def test_flags_block_their_domain_only() -> None:
    ai = case_policy("green", True, False)
    assert ai.ai_blocked and not ai.ti_blocked and ai.ai_reason == CASE_AI_EXCLUDED
    ti = case_policy("green", False, True)
    assert ti.ti_blocked and not ti.ai_blocked and ti.ti_reason == CASE_TI_EXCLUDED


def test_reason_order_puts_tlp_red_first() -> None:
    policy = case_policy("red", True, True)
    assert policy.reasons == [TLP_RED, CASE_AI_EXCLUDED, CASE_TI_EXCLUDED]
    assert policy.ai_reasons == [TLP_RED, CASE_AI_EXCLUDED]


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("red", "amber", True),
        ("amber", "amber", True),
        ("amber_strict", "amber", True),
        ("green", "amber", False),
        ("clear", "green", False),
    ],
)
def test_tlp_order(a: str, b: str, expected: bool) -> None:
    assert tlp_at_least(a, b) is expected
    assert is_downgrade(a, b) is not expected


def test_policy_blocked_answers_409_with_the_reason() -> None:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/x")
    async def blocked() -> None:
        raise_if_ai_blocked(case_policy("red", False, False))

    response = TestClient(app).get("/x")
    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "policy_blocked",
            "message": PolicyBlocked.message,
            "reason": "tlp_red",
        }
    }
