"""`scripts/verify_report.py` (M6 phase 3): a snapshot plus its `.sig.json` verifies offline
against the published keys (exit 0); a tampered snapshot, a wrong key, an unknown kid or a
manifest that names another report fails (exit 1). A minimal PDF with the three embedded
files goes through the fallback attachment reader (the real PDF path is phase 9's).

The script lives in the repository's `scripts/`, which api-test mounts read-only at
`/srv/scripts`; elsewhere the test looks for it next to the api tree (or at
`VERIFY_REPORT_SCRIPT`) and is skipped (with the reason) when it is not there."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import uuid
import zlib
from pathlib import Path
from types import ModuleType

import pytest
from cyberlab_jobs.report import Manifest, Profile, canonical_json, manifest_bytes

from app.core.signing import sign
from tests.report_helpers import fake_snapshot, new_signing_keys

_CANDIDATES = [
    os.environ.get("VERIFY_REPORT_SCRIPT", ""),
    str(Path(__file__).resolve().parents[4] / "scripts" / "verify_report.py"),
    "/repo/scripts/verify_report.py",
    "/srv/scripts/verify_report.py",
]
SCRIPT = next((Path(p) for p in _CANDIDATES if p and Path(p).is_file()), None)
pytestmark = pytest.mark.skipif(
    SCRIPT is None, reason="scripts/verify_report.py is not mounted in this container"
)


def _module() -> ModuleType:
    assert SCRIPT is not None
    spec = importlib.util.spec_from_file_location("verify_report", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _signed(tmp_path: Path, **manifest_over: object) -> tuple[Path, Path, Path, dict[str, object]]:
    keys = new_signing_keys("offline-1")
    snapshot = fake_snapshot()
    data = canonical_json(snapshot)
    fields: dict[str, object] = {
        "report_id": snapshot.report.report_id,
        "version": snapshot.report.version,
        "org_id": uuid.uuid4(),
        "snapshot_sha256": hashlib.sha256(data).hexdigest(),
        "snapshot_bytes": len(data),
        "tlp": snapshot.report.tlp,
        "profile": Profile(snapshot.report.profile),
        "finalized_at": snapshot.report.finalized_at,
        "finalized_by": uuid.uuid4(),
        "kid": keys.kid,
    }
    fields.update(manifest_over)
    manifest = Manifest.model_validate(fields)
    raw = manifest_bytes(manifest)
    sig = {"alg": "Ed25519", "kid": keys.kid, "manifest": json.loads(raw)}
    sig["signature"] = sign(raw, keys.kid, keys.keys)
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_bytes(data)
    sig_path = tmp_path / "report.sig.json"
    sig_path.write_text(json.dumps(sig), encoding="utf-8")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({"keys": [{"kid": keys.kid, "alg": "Ed25519", "public_key": keys.public_b64}]}),
        encoding="utf-8",
    )
    return snapshot_path, sig_path, keys_path, sig


def _run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True, check=False
    )


def test_a_signed_snapshot_verifies(tmp_path: Path) -> None:
    snapshot, sig, keys, _ = _signed(tmp_path)
    result = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("VALID:")


def test_a_tampered_snapshot_fails(tmp_path: Path) -> None:
    snapshot, sig, keys, _ = _signed(tmp_path)
    snapshot.write_bytes(snapshot.read_bytes().replace(b"Suspicious", b"Harmless!!"))
    result = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert result.returncode == 1
    assert "sha256" in result.stderr


def test_a_wrong_key_or_kid_fails(tmp_path: Path) -> None:
    snapshot, sig, keys, _ = _signed(tmp_path)
    other = new_signing_keys("offline-1")
    keys.write_text(json.dumps({"offline-1": other.public_b64}), encoding="utf-8")
    assert _run("--snapshot", snapshot, "--sig", sig, "--keys", keys).returncode == 1
    keys.write_text(json.dumps({"someone-else": other.public_b64}), encoding="utf-8")
    result = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert result.returncode == 1 and "unknown signing key" in result.stderr


def test_a_manifest_for_another_version_fails(tmp_path: Path) -> None:
    # A valid signature over a manifest that names another version of the report.
    snapshot, sig, keys, _ = _signed(tmp_path, version=7)
    result = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert result.returncode == 1 and "version" in result.stderr


def _pdf(files: dict[str, bytes]) -> bytes:
    objects: list[bytes] = [b"<< /Type /Catalog >>"]
    for name, content in files.items():
        packed = zlib.compress(content)
        stream_no = len(objects) + 2
        objects.append(
            b"<< /Type /Filespec /F (" + name.encode() + b") /UF (" + name.encode() + b")"
            b" /EF << /F " + str(stream_no).encode() + b" 0 R >> >>"
        )
        objects.append(
            b"<< /Type /EmbeddedFile /Filter /FlateDecode /Length "
            + str(len(packed)).encode()
            + b" >>\nstream\n"
            + packed
            + b"\nendstream"
        )
    out = [b"%PDF-1.7\n"]
    for n, body in enumerate(objects, start=1):
        out.append(str(n).encode() + b" 0 obj\n" + body + b"\nendobj\n")
    out.append(b"trailer << /Root 1 0 R >>\n%%EOF\n")
    return b"".join(out)


def test_a_pdf_with_embedded_files_verifies(tmp_path: Path) -> None:
    snapshot, sig, keys, signed = _signed(tmp_path)
    manifest = json.dumps(signed["manifest"]).encode()
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(
        _pdf(
            {
                "snapshot.json": snapshot.read_bytes(),
                "manifest.json": manifest,
                "manifest.sig.json": sig.read_bytes(),
            }
        )
    )
    assert _run("--pdf", pdf, "--keys", keys).returncode == 0
    files = _module()._minimal_attachments(pdf.read_bytes())
    assert files["snapshot.json"] == snapshot.read_bytes()
    pdf.write_bytes(_pdf({"snapshot.json": snapshot.read_bytes()}))
    missing = _run("--pdf", pdf, "--keys", keys)
    assert missing.returncode == 1 and "does not embed" in missing.stderr


def test_the_canonical_form_matches_the_contract() -> None:
    module = _module()
    snapshot = fake_snapshot()
    assert module.canonical(json.loads(canonical_json(snapshot))) == canonical_json(snapshot)
