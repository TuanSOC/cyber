"""LLM provider adapters (phase 3) and the rule-based `FakeProvider` (phase 1).

Only the analyst worker and the adapter modules may import `anthropic`, `gemini`, `mock`,
`registry` (and `ai.http` / the vendor SDKs): `tests/unit/test_ai_import_guard.py`. This
package `__init__` and `fake.py` import none of them.
"""
