"""`pnpm identity:admin approve-domain --org <id> --domain <d>` and `recheck-domains`
(M11 phase 7; phase 1 stubs).

`approve-domain`: the air-gapped fallback (method `operator`). `recheck-domains`: the weekly
host cron re-queries every verified domain's TXT record through the egress proxy; a vanished
record -> `failed`, JIT stops, audit. The org comes from the CLI or the verified-domain list
(the vetted entry of `tests/unit/test_tenant_session_guard.py`).
"""

import argparse


def approve(args: argparse.Namespace) -> int:
    print("identity:admin approve-domain lands in M11 phase 7 (not implemented)")
    return 2


def recheck(args: argparse.Namespace) -> int:
    print("identity:admin recheck-domains lands in M11 phase 7 (not implemented)")
    return 2
