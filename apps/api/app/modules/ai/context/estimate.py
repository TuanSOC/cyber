"""Conservative token estimate for the context budget (M5 phase 4).

The API has no egress, so it cannot call a provider's token counter: the estimate is
`ceil(len(canonical_json) / 3)` characters per token (conservative for ASCII-heavy evidence;
the worker's `count_tokens` preflight catches the rest as `context_too_large`).

`PROMPT_OVERHEAD_TOKENS` reserves room for the system prompt, the task line, the stats summary
and the delimiters; phase 5 asserts its rendered prompt overhead stays under it.
"""

import math

CHARS_PER_TOKEN = 3
PROMPT_OVERHEAD_TOKENS = 4_000


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def chars_for_tokens(tokens: int) -> int:
    """The longest canonical JSON (in characters) whose estimate stays within `tokens`."""
    return max(tokens, 0) * CHARS_PER_TOKEN


def context_budget(max_input_tokens: int) -> int:
    """Tokens available to the evidence block (`AI_MAX_INPUT_TOKENS` minus the overhead)."""
    return max(max_input_tokens - PROMPT_OVERHEAD_TOKENS, 0)
