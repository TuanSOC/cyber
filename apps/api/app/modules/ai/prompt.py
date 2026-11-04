"""Prompt rendering (signatures FROZEN in phase 1; phase 5 fills the bodies and owns
`PROMPT_VERSION`, which it bumps on any template change).

`render` returns the system prompt (stable, cacheable) and the user turn: the task enum,
kind/count stats and the evidence JSON between `<<EVIDENCE {delimiter}>>` lines. Nothing
analyzer-, user- or TI-controlled appears outside that block (RT4).
"""

from app.modules.ai.contracts import AiTask, FrozenContext, PromptParts

PROMPT_VERSION = "m5.1"


def render(ctx: FrozenContext, task: AiTask, *, delimiter: str, canary: str) -> PromptParts:
    raise NotImplementedError("phase 5")


def repair_hint(errors: list[str]) -> str:
    """A short fixed text naming the schema violations (paths only, never values)."""
    raise NotImplementedError("phase 5")
