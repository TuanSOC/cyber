"""`python -m samples.diskgen.hashlists --out DIR` (M9 phase 13): the test hash lists.

Reads the `ground_truth.json` of the generated images in `DIR` and writes, under
`DIR/hashsets/`, two plain sha256 lists in the `disk-hashsets import-list` format (one digest
per line, `#` comments) and the expectation the pipeline test asserts:

- `test_known_good.sha256`: `/etc/os-release` of `ext4_linux` and, when `ntfs_windows` was
  generated, its `/Windows/System32/drivers/etc/hosts` (a plain, collected-nowhere file whose
  only role is to be hidden by "hide known-good");
- `test_known_bad.sha256`: `/tmp/.x/upd` of `ext4_linux` (the inert ELF the scenario drops in a
  user-writable path, so the known-bad match and `disk_exec_user_writable` meet on one file);
- `expected.json`: `{"known_good": [{"image", "path", "sha256"}], "known_bad": [...]}`.

The gate imports the lists into the **test** store only (`pnpm disk:hashsets -- --store test
import-list ... --name test-known-good|test-known-bad`), never into the operator's store. The
digests are of our own synthetic content: nothing here comes from a real hash set. Exit 2 when
`ext4_linux` (the one required image) has no ground truth.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from samples.diskgen import NOTE

KNOWN_GOOD: tuple[tuple[str, str, bool], ...] = (
    # (image id, path, required)
    ("ext4_linux", "/etc/os-release", True),
    ("ntfs_windows", "/Windows/System32/drivers/etc/hosts", False),
)
KNOWN_BAD: tuple[tuple[str, str, bool], ...] = (("ext4_linux", "/tmp/.x/upd", True),)  # noqa: S108
GOOD_FILE = "test_known_good.sha256"
BAD_FILE = "test_known_bad.sha256"
EXPECTED_FILE = "expected.json"


class MissingTruth(Exception):
    """A required image (or a required file of it) is not in the generated set."""


def _truth(out: Path, image_id: str) -> dict[str, Any] | None:
    path = out / image_id / "ground_truth.json"
    if not path.is_file():
        return None
    doc: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return doc


def _digest(doc: dict[str, Any], path: str) -> str | None:
    for entry in doc.get("files", []):
        if (
            entry.get("path") == path
            and entry.get("type") == "reg"
            and "stream" not in entry
            and not entry.get("deleted")
            and isinstance(entry.get("sha256"), str)
        ):
            return str(entry["sha256"]).lower()
    return None


def select(out: Path, wanted: tuple[tuple[str, str, bool], ...]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for image_id, path, required in wanted:
        doc = _truth(out, image_id)
        digest = _digest(doc, path) if doc is not None else None
        if digest is None:
            if required:
                raise MissingTruth(f"{image_id}:{path}")
            continue
        rows.append({"image": image_id, "path": path, "sha256": digest})
    return rows


def _list_text(kind: str, rows: list[dict[str, str]]) -> str:
    lines = [f"# cyberlab test hash list ({kind}); {NOTE}"]
    lines += [f"# {r['image']}:{r['path']}\n{r['sha256']}" for r in rows]
    return "\n".join(lines) + "\n"


def write(out: Path) -> dict[str, list[dict[str, str]]]:
    expected = {"known_good": select(out, KNOWN_GOOD), "known_bad": select(out, KNOWN_BAD)}
    target = out / "hashsets"
    target.mkdir(parents=True, exist_ok=True)
    (target / GOOD_FILE).write_text(
        _list_text("known_good", expected["known_good"]), encoding="utf-8"
    )
    (target / BAD_FILE).write_text(_list_text("known_bad", expected["known_bad"]), encoding="utf-8")
    (target / EXPECTED_FILE).write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m samples.diskgen.hashlists")
    parser.add_argument("--out", required=True, help="the `python -m samples.diskgen` output")
    args = parser.parse_args(argv)
    try:
        expected = write(Path(args.out))
    except MissingTruth as exc:
        print(f"hashlists: missing ground truth for {exc}", file=sys.stderr)
        return 2
    print(
        f"hashlists: {len(expected['known_good'])} known-good, "
        f"{len(expected['known_bad'])} known-bad -> {Path(args.out) / 'hashsets'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
