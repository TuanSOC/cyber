"""`python -I -m memory_worker.symbols <command>`: the trusted operator tool (phase-1 STUB;
phase 5 implements it). Run through `pnpm memory:symbols -- <command> [--store test]`.

Commands (frozen names): `fetch-windows --pdb --guid --age` (operator only, never run by a
test, gate or worker), `import --file`, `reindex`, `verify`, `list`. Phase 1 exits 2.
"""

import sys

COMMANDS = ("fetch-windows", "import", "reindex", "verify", "list")


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in COMMANDS:
        print(f"usage: memory-symbols {{{','.join(COMMANDS)}}} ...", file=sys.stderr)
        return 2
    print(f"memory-symbols {argv[0]}: not implemented yet (M8 phase 5)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
