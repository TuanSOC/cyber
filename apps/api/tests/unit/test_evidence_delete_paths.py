"""M7 phase 11 (RT5): the api's MinIO delete grant on the evidence buckets is used in exactly
one place, the failed-upload cleanup `evidence/locking.discard_version`, which checks the
legal holds (case and org) and the evidence rows first. Every other object delete in `app/`
is the retention worker's (purge user) or the restore drill seeder's (drill root)."""

import re
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"
DELETE = re.compile(r"\b(remove_object|remove_objects|delete_version)\(")
ALLOWED = {
    "core/storage.py",  # the api client's primitive, called only by locking.py
    "modules/evidence/locking.py",  # discard_version: hold-checked
    "modules/retention/objects.py",  # the purge user's client
    "workers/retention.py",  # the retention worker, through objects.py
    "scripts/drill_seed.py",  # the restore drill's root client (a drill project only)
}


def _callers() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in APP.rglob("*.py"):
        rel = path.relative_to(APP).as_posix()
        hits = [line.strip() for line in path.read_text().splitlines() if DELETE.search(line)]
        if hits:
            found[rel] = hits
    return found


def test_only_the_known_paths_delete_objects() -> None:
    assert set(_callers()) <= ALLOWED, _callers()


def test_the_api_storage_delete_is_called_by_the_hold_checked_discard_only() -> None:
    users = [
        rel for rel, hits in _callers().items() if any("storage.delete_version(" in h for h in hits)
    ]
    assert users == ["modules/evidence/locking.py"]
