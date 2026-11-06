"""`python -I -m disk_worker.hashsets <command> ...` (the `disk-hashsets` tool; M9 phase 1 stub,
phase 5 owns it). Commands: `import-nsrl`, `import-list`, `list`, `verify`, `remove`. Offline
only: the service has `network_mode: none`; nothing is ever downloaded.
"""

import sys

COMMANDS = ("import-nsrl", "import-list", "list", "verify", "remove")


def main(argv: list[str]) -> int:
    print(
        f"disk-hashsets: not implemented yet (M9 phase 5); commands: {', '.join(COMMANDS)}",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
