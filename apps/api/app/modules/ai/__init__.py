"""AI security analyst (M5): evidence-cited analysis of normalized findings.

Trust split (as in M4 threat intel): the API builds and freezes the context, seals provider
keys (`seal.py`, public key only), records runs and publishes ids; only the analyst worker
(`app/workers/analyst*.py`) imports the provider adapters, the egress HTTP clients, the
vendor SDKs and `unseal.py`, and only it has egress. The model gets no tools, ever.
`tests/unit/test_ai_import_guard.py` enforces the import rules.

Frozen in phase 1: `contracts`, `output_schema`, `labels`, `text`, `catalog`,
`availability`, `messages`, `seal`, `unseal`, `models`, `router`, and the signatures of the
stubs `context/builder.py`, `context/reduce.py`, `prompt.py`, `verify.py`,
`providers/registry.py`, `runs.py`.
"""
