"""Context builder (phase 4 owns this package after the phase-1 stubs).

The API builds and freezes the context in the requester's RLS session: deterministic
selection, sanitization, pseudonymization, defanging, labels, canonical JSON + sha256.
"""
