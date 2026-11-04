"""Threat intelligence (M4): lookup-only IOC enrichment from external providers.

Trust split: the API seals provider keys (`seal.py`), plans runs and reads results; only the
enrich worker (`app/workers/enrich*.py`) imports the adapters, the HTTP client and
`unseal.py`, and only it has egress. `tests/unit/test_ti_import_guard.py` enforces this.
"""
