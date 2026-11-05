"""`scripts/verify_report.py` (M6 phase 3): a snapshot plus its `.sig.json` verifies offline
against the pinned keys (exit 0); a tampered snapshot, a wrong key, an unknown kid, the
committed dev key without `--allow-dev`, duplicate JSON keys or a manifest that names
another report fails (exit 1). A minimal PDF with the three embedded files goes through the
bounded attachment reader (the real PDF path is phase 9's); an incrementally updated PDF, a
duplicate or unexpected attachment and a stream that inflates past the bound are refused,
and a valid PDF result says the visible pages are not covered.

The script lives in the repository's `scripts/`, which api-test mounts read-only at
`/srv/scripts`; elsewhere the test looks for it next to the api tree (or at
`VERIFY_REPORT_SCRIPT`) and is skipped (with the reason) when it is not there."""

import base64
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


def _signed(
    tmp_path: Path, kid: str = "offline-1", **manifest_over: object
) -> tuple[Path, Path, Path, dict[str, object]]:
    keys = new_signing_keys(kid)
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


def _pdf(files: dict[str, bytes] | list[tuple[str, bytes]], tail: bytes = b"") -> bytes:
    objects: list[bytes] = [b"<< /Type /Catalog >>"]
    for name, content in files.items() if isinstance(files, dict) else files:
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
    return b"".join(out) + tail


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
    valid = _run("--pdf", pdf, "--public-keys", keys)
    assert valid.returncode == 0, valid.stderr
    # The result says what the signature does not cover.
    assert "not the PDF's visible pages" in valid.stdout
    files = _module()._minimal_attachments(pdf.read_bytes())
    assert files["snapshot.json"] == snapshot.read_bytes()
    pdf.write_bytes(_pdf({"snapshot.json": snapshot.read_bytes()}))
    missing = _run("--pdf", pdf, "--keys", keys)
    assert missing.returncode == 1 and "does not embed" in missing.stderr


def _three(snapshot: Path, sig: Path, signed: dict[str, object]) -> list[tuple[str, bytes]]:
    return [
        ("snapshot.json", snapshot.read_bytes()),
        ("manifest.json", json.dumps(signed["manifest"]).encode()),
        ("manifest.sig.json", sig.read_bytes()),
    ]


def test_an_incrementally_updated_pdf_is_refused(tmp_path: Path) -> None:
    """A signed rendition with a revision appended (a new page object, an xref section with
    `/Prev` and a second `%%EOF`) is refused even though the attachments still verify."""
    snapshot, sig, keys, signed = _signed(tmp_path)
    original = _pdf(_three(snapshot, sig, signed))
    update = (
        b"99 0 obj\n<< /Type /Page /Contents (Harmless printer ok) >>\nendobj\n"
        b"xref\n99 1\n0000000000 00000 n \n"
        b"trailer << /Root 1 0 R /Prev 0 >>\nstartxref\n" + str(len(original)).encode() + b"\n"
        b"%%EOF\n"
    )
    pdf = tmp_path / "updated.pdf"
    pdf.write_bytes(original + update)
    result = _run("--pdf", pdf, "--keys", keys)
    assert result.returncode == 1 and "incremental" in result.stderr
    # A redefinition of an existing object (the classic overlay) is refused on its own too.
    module = _module()
    with pytest.raises(module.Failed, match="twice"):
        module._minimal_attachments(original + b"2 0 obj\n<< >>\nendobj\n")
    with pytest.raises(module.Failed, match="Prev"):
        module.check_single_revision(
            b"%PDF-1.7\ntrailer << /Root 1 0 R /Prev 10 >>\nstartxref\n0\n%%EOF\n", {}
        )


def test_a_duplicate_or_unexpected_attachment_is_refused(tmp_path: Path) -> None:
    snapshot, sig, keys, signed = _signed(tmp_path)
    three = _three(snapshot, sig, signed)
    other = snapshot.read_bytes().replace(b"Suspicious", b"Harmless!!")
    pdf = tmp_path / "dup.pdf"
    for files, message in (
        ([*three, ("snapshot.json", other)], "more than once"),
        ([("snapshot.json", other), *three], "more than once"),
        ([*three, ("readme.txt", b"open me")], "unexpected file"),
    ):
        pdf.write_bytes(_pdf(files))
        result = _run("--pdf", pdf, "--keys", keys)
        assert result.returncode == 1 and message in result.stderr, result.stderr


def test_a_stream_that_inflates_past_the_bound_is_refused(tmp_path: Path) -> None:
    snapshot, sig, keys, signed = _signed(tmp_path)
    module = _module()
    bomb = b"\0" * (module.MAX_STREAM_BYTES + 1)
    pdf = tmp_path / "bomb.pdf"
    pdf.write_bytes(_pdf([*_three(snapshot, sig, signed)[1:], ("snapshot.json", bomb)]))
    assert len(pdf.read_bytes()) < 64 * 1024  # small on disk, huge inflated
    result = _run("--pdf", pdf, "--keys", keys)
    assert result.returncode == 1 and "size bound" in result.stderr


def test_duplicate_json_keys_are_refused(tmp_path: Path) -> None:
    snapshot, sig, keys, _ = _signed(tmp_path)
    raw = sig.read_text(encoding="utf-8")
    sig.write_text(raw[:-1] + ', "kid": "someone-else"}', encoding="utf-8")
    result = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert result.returncode == 1 and "duplicate JSON key 'kid'" in result.stderr
    keys.write_text('{"offline-1": "a", "offline-1": "b"}', encoding="utf-8")
    result = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert result.returncode == 1 and "duplicate JSON key" in result.stderr


def test_the_committed_dev_key_needs_allow_dev(tmp_path: Path) -> None:
    snapshot, sig, keys, _ = _signed(tmp_path, kid="dev-report-1")
    refused = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys)
    assert refused.returncode == 1 and "development key" in refused.stderr
    allowed = _run("--snapshot", snapshot, "--sig", sig, "--keys", keys, "--allow-dev")
    assert allowed.returncode == 0, allowed.stderr
    module = _module()
    dev = base64.b64decode(next(iter(module.DEV_PUBLIC_KEYS)))
    assert module.is_dev_key("prod-2026-1", dev) and not module.is_dev_key("prod-1", b"k" * 32)


def test_the_canonical_form_matches_the_contract() -> None:
    module = _module()
    snapshot = fake_snapshot()
    assert module.canonical(json.loads(canonical_json(snapshot))) == canonical_json(snapshot)
