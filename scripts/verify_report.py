#!/usr/bin/env python3
"""Verify a CyberLab report offline (M6): its snapshot hash, its Ed25519 manifest signature
and the manifest fields. Standard library + `cryptography`; `pypdf` is used for PDFs when it
is installed, otherwise a minimal reader of the PDF's embedded files.

  python scripts/verify_report.py --snapshot snapshot.json --sig report-v1.sig.json \\
      --keys report-signing-keys.json
  python scripts/verify_report.py --pdf report-v1.pdf --keys report-signing-keys.json

`--keys` is the JSON of the unauthenticated `GET /api/v1/report-signing-keys`
(`{"keys": [{"kid", "alg", "public_key", "active"}]}`) or a plain `{kid: base64 key}` map
(as listed in docs/DEPLOYMENT.md). A PDF carries `snapshot.json`, `manifest.json` and
`manifest.sig.json` as embedded files (PDF/A-3 attachments).

Checks: the signature file names the manifest's kid and the key is known; the signature is a
valid Ed25519 signature over the canonical JSON of the manifest (sorted keys, no
whitespace, UTF-8); sha256 and size of the snapshot bytes equal the manifest's; the snapshot
re-serializes to exactly the same canonical bytes; the snapshot's report id, version, TLP,
profile and schema equal the manifest's (and an embedded `manifest.json` equals the signed
one). Exit 0 when every check passes, 1 otherwise (2 on usage errors).
"""

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "cyberlab.report.manifest.v1"
REPORT_SCHEMA = "cyberlab.report.v1"
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
ATTACHMENTS = ("snapshot.json", "manifest.json", "manifest.sig.json")


class Failed(Exception):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


# --- keys -------------------------------------------------------------------------------------


def load_keys(raw: bytes) -> dict[str, bytes]:
    data = json.loads(raw)
    pairs: dict[str, str] = {}
    if isinstance(data, dict) and isinstance(data.get("keys"), list):
        for item in data["keys"]:
            if isinstance(item, dict) and item.get("alg", "Ed25519") == "Ed25519":
                pairs[str(item.get("kid"))] = str(item.get("public_key"))
    elif isinstance(data, dict):
        pairs = {str(k): str(v) for k, v in data.items()}
    out: dict[str, bytes] = {}
    for kid, encoded in pairs.items():
        try:
            key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(key) == 32:
            out[kid] = key
    if not out:
        raise Failed("no Ed25519 public key in the keys file")
    return out


def verify_signature(public_key: bytes, signature_b64: str, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# --- PDF attachments ----------------------------------------------------------------------------


def _pypdf_attachments(data: bytes) -> dict[str, bytes] | None:
    try:
        import io

        from pypdf import PdfReader
    except ImportError:
        return None
    reader = PdfReader(io.BytesIO(data))
    found: dict[str, bytes] = {}
    for name, contents in reader.attachments.items():
        if contents:
            found[name] = contents[0]
    return found


_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
_REF = rb"(\d+)\s+\d+\s+R"


def _stream(body: bytes, objects: dict[int, bytes]) -> bytes | None:
    head, sep, rest = body.partition(b"stream")
    if not sep:
        return None
    if rest.startswith(b"\r\n"):
        rest = rest[2:]
    elif rest.startswith((b"\n", b"\r")):
        rest = rest[1:]
    length_match = re.search(rb"/Length\s+(?:" + _REF + rb"|(\d+))", head)
    raw: bytes
    if length_match and length_match.group(2):
        raw = rest[: int(length_match.group(2))]
    elif length_match and length_match.group(1):
        target = objects.get(int(length_match.group(1)), b"").strip()
        raw = rest[: int(target)] if target.isdigit() else rest.rsplit(b"endstream", 1)[0]
    else:
        raw = rest.rsplit(b"endstream", 1)[0]
    if b"/FlateDecode" in head:
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            return None
    return raw


def _expand_object_streams(objects: dict[int, bytes]) -> None:
    """PDF 1.5 object streams (`/Type /ObjStm`): their objects are added to the table."""
    for body in list(objects.values()):
        if b"/ObjStm" not in body.partition(b"stream")[0]:
            continue
        head = body.partition(b"stream")[0]
        n = re.search(rb"/N\s+(\d+)", head)
        first = re.search(rb"/First\s+(\d+)", head)
        data = _stream(body, objects)
        if not (n and first and data):
            continue
        numbers = data[: int(first.group(1))].split()
        offsets = [(int(numbers[i]), int(numbers[i + 1])) for i in range(0, len(numbers) - 1, 2)]
        base = int(first.group(1))
        for k, (number, offset) in enumerate(offsets[: int(n.group(1))]):
            end = offsets[k + 1][1] if k + 1 < len(offsets) else len(data) - base
            objects.setdefault(number, data[base + offset : base + end])


def _pdf_string(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def _minimal_attachments(data: bytes) -> dict[str, bytes]:
    objects = {int(m.group(1)): m.group(3) for m in _OBJ.finditer(data)}
    _expand_object_streams(objects)
    found: dict[str, bytes] = {}
    for body in objects.values():
        if not re.search(rb"/Type\s*/Filespec", body):
            continue
        name_match = re.search(rb"/UF\s*\((.*?)(?<!\\)\)", body, re.DOTALL) or re.search(
            rb"/F\s*\((.*?)(?<!\\)\)", body, re.DOTALL
        )
        ef = re.search(rb"/EF\s*<<.*?/(?:UF|F)\s+" + _REF, body, re.DOTALL)
        if not (name_match and ef):
            continue
        stream = _stream(objects.get(int(ef.group(1)), b""), objects)
        if stream is not None:
            found[_pdf_string(name_match.group(1))] = stream
    return found


def pdf_attachments(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"%PDF-"):
        raise Failed("not a PDF")
    found = _pypdf_attachments(data)
    if found is None or not all(name in found for name in ATTACHMENTS):
        found = {**(found or {}), **_minimal_attachments(data)}
    missing = [name for name in ATTACHMENTS if name not in found]
    if missing:
        raise Failed(f"the PDF does not embed {', '.join(missing)}")
    return found


# --- verification -------------------------------------------------------------------------------


def verify(snapshot: bytes, sig_file: dict[str, Any], keys: dict[str, bytes]) -> list[str]:
    """Every check that failed (empty: valid)."""
    problems: list[str] = []
    manifest = sig_file.get("manifest")
    if not isinstance(manifest, dict):
        return ["the signature file has no manifest"]
    kid = sig_file.get("kid")
    if sig_file.get("alg", "Ed25519") != "Ed25519":
        problems.append("the signature algorithm is not Ed25519")
    if kid != manifest.get("kid"):
        problems.append("the signature kid differs from the manifest kid")
    key = keys.get(str(kid))
    if key is None:
        problems.append(f"unknown signing key {kid!r}")
    elif not verify_signature(key, str(sig_file.get("signature", "")), canonical(manifest)):
        problems.append("the manifest signature is not valid")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        problems.append("unexpected manifest schema")
    if manifest.get("report_schema") != REPORT_SCHEMA:
        problems.append("unexpected report schema in the manifest")
    if len(snapshot) > MAX_SNAPSHOT_BYTES:
        problems.append("the snapshot is larger than the format allows")
    if hashlib.sha256(snapshot).hexdigest() != manifest.get("snapshot_sha256"):
        problems.append("the snapshot sha256 differs from the manifest")
    if len(snapshot) != manifest.get("snapshot_bytes"):
        problems.append("the snapshot size differs from the manifest")
    try:
        parsed = json.loads(snapshot)
    except (ValueError, UnicodeDecodeError):
        return [*problems, "the snapshot is not JSON"]
    if not isinstance(parsed, dict):
        return [*problems, "the snapshot is not a JSON object"]
    if canonical(parsed) != snapshot:
        problems.append("the snapshot is not in canonical form")
    report = parsed.get("report") if isinstance(parsed.get("report"), dict) else {}
    if parsed.get("schema_version") != REPORT_SCHEMA:
        problems.append("unexpected snapshot schema")
    expected = {
        "report_id": manifest.get("report_id"),
        "version": manifest.get("version"),
        "tlp": manifest.get("tlp"),
        "profile": manifest.get("profile"),
        "finalized_at": manifest.get("finalized_at"),
    }
    for name, value in expected.items():
        if report.get(name) != value:
            problems.append(f"the snapshot {name} differs from the manifest")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pdf", type=Path, help="a rendered report PDF")
    source.add_argument("--snapshot", type=Path, help="the snapshot JSON as downloaded")
    parser.add_argument("--sig", type=Path, help="the .sig.json of the version (with --snapshot)")
    parser.add_argument("--keys", type=Path, required=True, help="the public keys JSON")
    parser.add_argument("--quiet", action="store_true", help="print nothing on success")
    args = parser.parse_args(argv)
    try:
        keys = load_keys(args.keys.read_bytes())
        if args.pdf is not None:
            files = pdf_attachments(args.pdf.read_bytes())
            snapshot = files["snapshot.json"]
            sig_file = json.loads(files["manifest.sig.json"])
            embedded = json.loads(files["manifest.json"])
        else:
            if args.sig is None:
                parser.error("--snapshot needs --sig")
            snapshot = args.snapshot.read_bytes()
            sig_file = json.loads(args.sig.read_bytes())
            embedded = None
        if not isinstance(sig_file, dict):
            raise Failed("the signature file is not a JSON object")
        problems = verify(snapshot, sig_file, keys)
        if embedded is not None and embedded != sig_file.get("manifest"):
            problems.append("the embedded manifest differs from the signed one")
    except (Failed, OSError, ValueError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(f"INVALID: {problem}", file=sys.stderr)
        return 1
    if not args.quiet:
        manifest = sig_file["manifest"]
        print(
            f"VALID: report {manifest['report_id']} v{manifest['version']} "
            f"({manifest['tlp']}, {manifest['profile']}) sha256 {manifest['snapshot_sha256']} "
            f"signed by {sig_file['kid']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
