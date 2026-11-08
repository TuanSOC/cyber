"""Identity operator commands (M11): `pnpm identity:admin <command> ...`.

Runs in a one-off api container (app DB role). Subcommands and their owning phases:
- `bootstrap-owner --email E --org-name N --yes` (phase 3, RT12): the first owner of a fresh
  install, through an owner invitation link printed once;
- `reset-mfa --email E` (phase 5);
- `approve-domain --org ORG --domain D` and `recheck-domains` (phase 7).
Each exits 2 until its phase lands.
"""

import argparse
import sys

from app.modules.identity import admin_domains, admin_mfa
from app.modules.invitations import admin_bootstrap


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="identity:admin", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap-owner", help="create an org and its owner invitation")
    boot.add_argument("--email", required=True)
    boot.add_argument("--org-name", required=True)
    boot.add_argument("--yes", action="store_true", help="confirm (required)")
    boot.set_defaults(run=admin_bootstrap.run)
    reset = sub.add_parser("reset-mfa", help="disable a user's MFA and revoke every session")
    reset.add_argument("--email", required=True)
    reset.add_argument("--yes", action="store_true", help="confirm (required)")
    reset.set_defaults(run=admin_mfa.run)
    approve = sub.add_parser("approve-domain", help="mark a domain verified (method operator)")
    approve.add_argument("--org", required=True)
    approve.add_argument("--domain", required=True)
    approve.set_defaults(run=admin_domains.approve)
    recheck = sub.add_parser("recheck-domains", help="re-check every verified domain (cron)")
    recheck.set_defaults(run=admin_domains.recheck)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int = args.run(args)
    return code


if __name__ == "__main__":
    sys.exit(main())
