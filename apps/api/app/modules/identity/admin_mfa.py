"""`pnpm identity:admin reset-mfa --email <e>` (M11 phase 5; phase 1 stub).

Disables the factor and the recovery codes, revokes every session
(`sessions_store.revoke_all(reason=operator)`), records `mfa_reset_by_operator` and mails
the user. Org admins cannot reset MFA (users are global).
"""

import argparse


def run(args: argparse.Namespace) -> int:
    print("identity:admin reset-mfa lands in M11 phase 5 (not implemented)")
    return 2
