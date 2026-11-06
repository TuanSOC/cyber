"""`pnpm identity:admin bootstrap-owner --email <e> --org-name <n> --yes` (M11 phase 3, RT12;
phase 1 stub).

Creates the org (`created_by` = the M7 system user) and an owner invitation, and prints the
`{PUBLIC_BASE_URL}/register#t=…` link once; the normal register-with-invitation flow does the
rest. There is no automatic "first registration" rule.
"""

import argparse


def run(args: argparse.Namespace) -> int:
    """Exit 2 until phase 3."""
    print("identity:admin bootstrap-owner lands in M11 phase 3 (not implemented)")
    return 2
