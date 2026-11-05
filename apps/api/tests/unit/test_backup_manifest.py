"""The backup manifest (M7 phase 2): building it from the file facts, and the restore's checks
on it: every file hash and size, the configured KMS key fingerprint (RT7) and the alembic head
known to the image (a newer backup is refused)."""

import hashlib
from typing import Any

import pytest

from app.scripts import restore_verify as rv

KMS_DEV = "cyberlab-dev-kms:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
KMS_OTHER = "cyberlab-kms-1:ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA="


def _facts() -> dict[str, dict[str, Any]]:
    return {
        name: {"sha256": hashlib.sha256(name.encode()).hexdigest(), "bytes": 10 + i}
        for i, name in enumerate(rv.BACKUP_FILES)
    }


def _manifest(**overrides: Any) -> dict[str, Any]:
    name, fingerprint = rv.kms_fingerprint(KMS_DEV)
    args: dict[str, Any] = {
        "files": _facts(),
        "alembic_head": "0014",
        "images": {"postgres": "sha256:" + "a" * 64, "api": "sha256:" + "b" * 64},
        "minio_image": "bitnamilegacy/minio:2025.5.24",
        "minio_data_dir": "/bitnami/minio/data",
        "evidence_lock_days": 30,
        "kms_key_name": name,
        "kms_key_fingerprint": fingerprint,
        "source_project": "cyberlab",
        "created_at": "2026-11-06T10:00:00+00:00",
    }
    args.update(overrides)
    return rv.build_manifest(**args)


def _check(manifest: dict[str, Any], files: dict[str, Any], **kw: Any) -> list[rv.Finding]:
    _, fingerprint = rv.kms_fingerprint(KMS_DEV)
    args: dict[str, Any] = {
        "kms_key_fingerprint": fingerprint,
        "known_revisions": {"0012", "0013", "0014"},
        "image_head": "0014",
    }
    args.update(kw)
    return rv.check_manifest(manifest, files, **args)


def _codes(found: list[rv.Finding]) -> list[str]:
    return [f.code for f in found]


def test_manifest_holds_every_fact_and_no_key() -> None:
    manifest = _manifest()
    assert manifest["tool_version"] == 1
    assert set(manifest["files"]) == set(rv.BACKUP_FILES)
    assert manifest["kms"]["name"] == "cyberlab-dev-kms"
    assert len(manifest["kms"]["fingerprint"]) == 64
    assert manifest["alembic_head"] == "0014"
    assert manifest["minio_data_dir"] == "/bitnami/minio/data"
    assert manifest["evidence_lock_days"] == 30
    assert manifest["source_project"] == "cyberlab"
    # The key itself (the part after the name) appears nowhere.
    assert KMS_DEV.split(":", 1)[1] not in repr(manifest)


def test_fingerprint_ignores_surrounding_whitespace_only() -> None:
    assert rv.kms_fingerprint(KMS_DEV + "\n") == rv.kms_fingerprint(KMS_DEV)
    assert rv.kms_fingerprint(KMS_DEV)[1] != rv.kms_fingerprint(KMS_OTHER)[1]
    with pytest.raises(ValueError):
        rv.kms_fingerprint("no-separator")


@pytest.mark.parametrize(
    "overrides",
    [
        {"files": {k: v for k, v in _facts().items() if k != "minio-data.tar"}},
        {"files": {**_facts(), "globals.sql": {"sha256": "XYZ", "bytes": 1}}},
        {"files": {**_facts(), "globals.sql": {"sha256": "a" * 64, "bytes": -1}}},
        {"alembic_head": "0014; drop"},
        {"kms_key_fingerprint": "short"},
        {"minio_data_dir": "data"},
        {"evidence_lock_days": -1},
    ],
)
def test_invalid_facts_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _manifest(**overrides)


def test_untouched_backup_passes() -> None:
    assert _check(_manifest(), _facts()) == []


def test_extra_files_in_the_directory_are_ignored() -> None:
    files = {**_facts(), "notes.txt": {"sha256": "c" * 64, "bytes": 3}}
    assert _check(_manifest(), files) == []


def test_tampered_file_is_detected() -> None:
    files = _facts()
    files["postgres.dump"] = {**files["postgres.dump"], "sha256": "d" * 64}
    found = _check(_manifest(), files)
    assert _codes(found) == ["file_hash_mismatch"]
    assert found[0].detail == {"file": "postgres.dump"}


def test_truncated_and_missing_files_are_detected() -> None:
    files = _facts()
    files["minio-data.tar"] = {**files["minio-data.tar"], "bytes": 1}
    del files["objects.json"]
    assert sorted(_codes(_check(_manifest(), files))) == ["file_missing", "file_size_mismatch"]


def test_a_manifest_missing_a_file_entry_is_refused() -> None:
    manifest = _manifest()
    del manifest["files"]["security.json"]
    assert "file_not_listed" in _codes(_check(manifest, _facts()))


def test_newer_backup_than_the_image_is_refused() -> None:
    found = _check(_manifest(alembic_head="0015"), _facts())
    assert _codes(found) == ["backup_newer_than_image"]
    assert found[0].detail == {"backup_head": "0015", "image_head": "0014"}


def test_older_backup_is_accepted_for_migrate_to_upgrade() -> None:
    assert _check(_manifest(alembic_head="0012"), _facts()) == []


def test_kms_fingerprint_mismatch_is_refused() -> None:
    _, other = rv.kms_fingerprint(KMS_OTHER)
    found = _check(_manifest(), _facts(), kms_key_fingerprint=other)
    assert _codes(found) == ["kms_key_mismatch"]
    # Only the backup's key name is reported, never a fingerprint or key.
    assert found[0].detail == {"backup_key_name": "cyberlab-dev-kms"}
    assert "kms_key_mismatch" in _codes(_check(_manifest(), _facts(), kms_key_fingerprint=None))


def test_unknown_tool_version_is_refused() -> None:
    manifest = {**_manifest(), "tool_version": 2}
    assert "tool_version" in _codes(_check(manifest, _facts()))


def test_image_revisions_know_the_current_head() -> None:
    head, known = rv.image_revisions()
    assert head is not None and head in known
    assert {"0013", "0014"} <= known
