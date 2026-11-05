"""Registers the `ai_eval` marker (live evaluation, never in the gate) for this package."""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "ai_eval: live AI evaluation (AI_EVAL_LIVE=1, local only; never in the gate)"
    )
