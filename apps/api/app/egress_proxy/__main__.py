"""Entry point of the egress proxy (M11 phase 1 stub: refuses a secret-bearing environment,
then exits 2 until phase 7 implements the tunnel)."""

import os
import sys

from app.core.config import EgressProxySettings, forbidden_env_present


def main() -> int:
    present = forbidden_env_present(dict(os.environ))
    if present:
        print(f"egress-proxy: refusing to start with {', '.join(present)}", file=sys.stderr)
        return 1
    EgressProxySettings()  # validates the caps and the prod refusals
    print("egress-proxy lands in M11 phase 7 (not implemented)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
