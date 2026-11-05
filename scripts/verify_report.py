#!/usr/bin/env python3
"""Verify a CyberLab report offline (M6): its snapshot hash, its Ed25519 manifest signature
and the manifest fields. Standard library + `cryptography`; PDFs are read by a minimal,
bounded reader of their embedded files (`pypdf`, when installed, is only a fallback).

  python scripts/verify_report.py --snapshot snapshot.json --sig report-v1.sig.json \\
      --public-keys report-signing-keys.json
  python scripts/verify_report.py --pdf report-v1.pdf --public-keys report-signing-keys.json

`--public-keys` (alias `--keys`) pins the keys: the JSON of the unauthenticated
`GET /api/v1/report-signing-keys` (`{"keys": [{"kid", "alg", "public_key", "active"}]}`) or a
plain `{kid: base64 key}` map (as listed in docs/DEPLOYMENT.md), obtained from the operator
out of band. Nothing is fetched. The committed development key (and any `dev-` kid) is
refused unless `--allow-dev` is given. A PDF carries `snapshot.json`, `manifest.json` and
`manifest.sig.json` as embedded files (PDF/A-3 attachments).

Scope: **the signature covers the embedded snapshot, not the PDF's visible pages.** A valid
result proves the attached `snapshot.json` is the signed record; it says nothing about
what the pages show (a compromised renderer could draw other text). Read the snapshot, or
the version in CyberLab, as the authoritative content.

Checks: the PDF is a single revision (exactly one `%%EOF`, one cross-reference section, no
`/Prev`, no object defined twice: an incremental update is refused) and embeds exactly the
three files, each once, and nothing else; every stream is inflated with a size bound; every
JSON document has no duplicate keys and no NaN / Infinity; the signature file names the
manifest's kid and the key is pinned; the signature is a valid Ed25519 signature over the
canonical JSON of the manifest (sorted keys, no whitespace, UTF-8); sha256 and size of the
snapshot bytes equal the manifest's; the snapshot re-serializes to exactly the same
canonical bytes; the snapshot's report id, version, TLP, profile and schema equal the
manifest's (and an embedded `manifest.json` equals the signed one). Exit 0 when every check
passes, 1 otherwise (2 on usage errors).
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
MAX_JSON_BYTES = MAX_SNAPSHOT_BYTES + 64 * 1024
MAX_PDF_BYTES = 64 * 1024 * 1024
# Inflated size bounds (a zip bomb stops here): per stream and for the whole file.
MAX_STREAM_BYTES = MAX_SNAPSHOT_BYTES + 1024 * 1024
MAX_INFLATED_BYTES = 64 * 1024 * 1024
ATTACHMENTS = ("snapshot.json", "manifest.json", "manifest.sig.json")
# The committed development signing pair (infra/reports, .env.example): never a real report.
DEV_PUBLIC_KEYS = frozenset({"zS2iP9napZDeshJwfCiTwYl8amzPuWJEJwHK8CpnF2k="})
DEV_KID_PREFIX = "dev-"
SCOPE_NOTE = (
    "NOTE: the signature covers the embedded snapshot.json only, not the PDF's visible "
    "pages; read the snapshot (or the version in CyberLab) as the authoritative content."
)


class Failed(Exception):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Failed(f"duplicate JSON key {key[:64]!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise Failed(f"non-standard JSON constant {name}")


def loads(raw: bytes, what: str) -> Any:
    """Strict JSON: bounded, UTF-8, no duplicate keys, no NaN / Infinity."""
    if len(raw) > MAX_JSON_BYTES:
        raise Failed(f"{what} is larger than the format allows")
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_no_constant
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise Failed(f"{what} is not valid JSON") from exc


# --- keys -------------------------------------------------------------------------------------


def load_keys(raw: bytes) -> dict[str, bytes]:
    data = loads(raw, "the keys file")
    pairs: dict[str, str] = {}
    if isinstance(data, dict) and isinstance(data.get("keys"), list):
        for item in data["keys"]:
            if isinstance(item, dict) and item.get("alg", "Ed25519") == "Ed25519":
                kid = str(item.get("kid"))
                if kid in pairs:
                    raise Failed(f"the keys file lists kid {kid!r} twice")
                pairs[kid] = str(item.get("public_key"))
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


def is_dev_key(kid: str, key: bytes) -> bool:
    return kid.startswith(DEV_KID_PREFIX) or base64.b64encode(key).decode() in DEV_PUBLIC_KEYS


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


# --- PDF structure and attachments ----------------------------------------------------------------


class _Budget:
    """The inflated bytes left for the whole file."""

    def __init__(self) -> None:
        self.left = MAX_INFLATED_BYTES

    def inflate(self, raw: bytes) -> bytes:
        limit = min(MAX_STREAM_BYTES, self.left)
        inflater = zlib.decompressobj()
        try:
            out = inflater.decompress(raw, limit + 1)
        except zlib.error as exc:
            raise Failed("a PDF stream does not inflate") from exc
        if len(out) > limit or inflater.unconsumed_tail:
            raise Failed("a PDF stream inflates beyond the size bound")
        self.left -= len(out)
        return out


_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
_REF = rb"(\d+)\s+\d+\s+R"


def _objects(data: bytes) -> dict[int, bytes]:
    """The top-level objects; an object number defined twice is an incremental update."""
    objects: dict[int, bytes] = {}
    for match in _OBJ.finditer(data):
        number = int(match.group(1))
        if number in objects:
            raise Failed("the PDF defines an object twice (incremental update)")
        objects[number] = match.group(3)
    return objects


def check_single_revision(data: bytes, objects: dict[int, bytes]) -> None:
    """Refuse incremental updates: anything appended after the signed rendition was written
    (a new page, an extra attachment) would otherwise go unnoticed."""
    eofs = data.count(b"%%EOF")
    if eofs != 1:
        raise Failed(f"the PDF has {eofs} end-of-file markers (incremental updates refused)")
    if data[data.rindex(b"%%EOF") + 5 :].strip(b"\r\n\t\f\x00 "):
        raise Failed("the PDF has data after its end-of-file marker")
    if len(re.findall(rb"(?<![A-Za-z])startxref\b", data)) > 1:
        raise Failed("the PDF has more than one cross-reference section")
    if len(re.findall(rb"(?m)^[ \t]*xref[ \t]*\r?$", data)) > 1:
        raise Failed("the PDF has more than one cross-reference table")
    for match in re.finditer(rb"(?<![A-Za-z])trailer\b", data):
        end = data.find(b"startxref", match.end())
        segment = data[match.end() : end if end != -1 else match.end() + 4096]
        if b"/Prev" in segment:
            raise Failed("the PDF trailer points at a previous revision (/Prev)")
    xref_streams = [b for b in objects.values() if re.search(rb"/Type\s*/XRef\b", _head(b))]
    if len(xref_streams) > 1:
        raise Failed("the PDF has more than one cross-reference stream")
    if any(b"/Prev" in _head(b) for b in xref_streams):
        raise Failed("the PDF cross-reference stream points at a previous revision (/Prev)")


def _head(body: bytes) -> bytes:
    return body.partition(b"stream")[0]


def _stream(body: bytes, objects: dict[int, bytes], budget: _Budget) -> bytes | None:
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
        raw = budget.inflate(raw)
    return raw


def _expand_object_streams(objects: dict[int, bytes], budget: _Budget) -> None:
    """PDF 1.5 object streams (`/Type /ObjStm`): their objects are added to the table."""
    for body in list(objects.values()):
        head = _head(body)
        if b"/ObjStm" not in head:
            continue
        n = re.search(rb"/N\s+(\d+)", head)
        first = re.search(rb"/First\s+(\d+)", head)
        data = _stream(body, objects, budget)
        if not (n and first and data):
            continue
        numbers = data[: int(first.group(1))].split()
        offsets = [(int(numbers[i]), int(numbers[i + 1])) for i in range(0, len(numbers) - 1, 2)]
        base = int(first.group(1))
        for k, (number, offset) in enumerate(offsets[: int(n.group(1))]):
            end = offsets[k + 1][1] if k + 1 < len(offsets) else len(data) - base
            if number in objects:
                raise Failed("the PDF defines an object twice (incremental update)")
            objects[number] = data[base + offset : base + end]


def _pdf_string(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def _minimal_attachments(data: bytes) -> dict[str, bytes]:
    """Every file specification with an embedded file (`/EF`), by name. A name seen twice,
    a name other than the three expected ones, an `/EF` naming two streams, or an embedded
    file stream no accepted specification points at is refused."""
    budget = _Budget()
    objects = _objects(data)
    check_single_revision(data, objects)
    _expand_object_streams(objects, budget)
    found: dict[str, bytes] = {}
    referenced: set[int] = set()
    for body in objects.values():
        ef = re.search(rb"/EF\s*<<(.*?)>>", body, re.DOTALL)
        if ef is None:
            continue
        name_match = re.search(rb"/UF\s*\((.*?)(?<!\\)\)", body, re.DOTALL) or re.search(
            rb"/F\s*\((.*?)(?<!\\)\)", body, re.DOTALL
        )
        name = _pdf_string(name_match.group(1)) if name_match else ""
        if name not in ATTACHMENTS:
            raise Failed(f"the PDF embeds an unexpected file {name[:64]!r}")
        if name in found:
            raise Failed(f"the PDF embeds {name} more than once")
        targets = {int(m.group(1)) for m in re.finditer(_REF, ef.group(1))}
        if len(targets) != 1:
            raise Failed(f"the embedded {name} names more than one stream")
        (target,) = targets
        stream = _stream(objects.get(target, b""), objects, budget)
        if stream is None:
            raise Failed(f"the embedded {name} has no stream")
        found[name] = stream
        referenced.add(target)
    for number, body in objects.items():
        if re.search(rb"/Type\s*/EmbeddedFile\b", _head(body)) and number not in referenced:
            raise Failed("the PDF carries an embedded file outside the expected attachments")
    return found


def _pypdf_attachments(data: bytes) -> dict[str, bytes] | None:
    """Fallback reader (pypdf's own limits apply): the same refusals by name."""
    try:
        import io

        from pypdf import PdfReader
    except ImportError:
        return None
    reader = PdfReader(io.BytesIO(data))
    found: dict[str, bytes] = {}
    for name, contents in reader.attachments.items():
        if name not in ATTACHMENTS:
            raise Failed(f"the PDF embeds an unexpected file {name[:64]!r}")
        if len(contents) != 1:
            raise Failed(f"the PDF embeds {name} more than once")
        found[name] = contents[0]
    return found


def pdf_attachments(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"%PDF-"):
        raise Failed("not a PDF")
    if len(data) > MAX_PDF_BYTES:
        raise Failed("the PDF is larger than a rendition can be")
    found = _minimal_attachments(data)
    if not all(name in found for name in ATTACHMENTS):
        found = _pypdf_attachments(data) or found
    missing = [name for name in ATTACHMENTS if name not in found]
    if missing:
        raise Failed(f"the PDF does not embed {', '.join(missing)}")
    return found


# --- verification -------------------------------------------------------------------------------


def verify(
    snapshot: bytes, sig_file: dict[str, Any], keys: dict[str, bytes], *, allow_dev: bool = False
) -> list[str]:
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
    elif is_dev_key(str(kid), key) and not allow_dev:
        problems.append(
            f"signing key {kid!r} is a development key (the committed dev pair or a dev- "
            "kid); pass --allow-dev only for a report of a development stack"
        )
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
        parsed = loads(snapshot, "the snapshot")
    except Failed as exc:
        return [*problems, str(exc)]
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
    parser.add_argument(
        "--public-keys",
        "--keys",
        dest="keys",
        type=Path,
        required=True,
        help="the pinned public keys JSON (the public route's output or a {kid: key} map)",
    )
    parser.add_argument(
        "--allow-dev", action="store_true", help="accept the committed development key"
    )
    parser.add_argument("--quiet", action="store_true", help="print nothing on success")
    args = parser.parse_args(argv)
    try:
        keys = load_keys(args.keys.read_bytes())
        if args.pdf is not None:
            files = pdf_attachments(args.pdf.read_bytes())
            snapshot = files["snapshot.json"]
            sig_file = loads(files["manifest.sig.json"], "the embedded signature file")
            embedded = loads(files["manifest.json"], "the embedded manifest")
        else:
            if args.sig is None:
                parser.error("--snapshot needs --sig")
            snapshot = args.snapshot.read_bytes()
            sig_file = loads(args.sig.read_bytes(), "the signature file")
            embedded = None
        if not isinstance(sig_file, dict):
            raise Failed("the signature file is not a JSON object")
        problems = verify(snapshot, sig_file, keys, allow_dev=args.allow_dev)
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
        if args.pdf is not None:
            print(SCOPE_NOTE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
