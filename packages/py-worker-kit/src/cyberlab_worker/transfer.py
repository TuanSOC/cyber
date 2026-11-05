"""Evidence download (hash-verified) and result upload, both via presigned URLs only."""

import hashlib
import os
from pathlib import Path

import httpx
from cyberlab_jobs import PresignedPost

from cyberlab_worker.errors import JobFailed

CHUNK = 1024 * 1024
TIMEOUT = httpx.Timeout(30.0, read=120.0)


def download(
    url: str,
    dest: Path,
    *,
    expected_sha256: str,
    size_bytes: int,
    max_bytes: int,
    too_large_code: str,
) -> None:
    """Stream the exact evidence version to `dest`; refuse anything but the expected bytes."""
    if size_bytes > max_bytes:
        raise JobFailed(too_large_code)
    digest = hashlib.sha256()
    received = 0
    try:
        with httpx.stream("GET", url, timeout=TIMEOUT) as response:
            if response.status_code != 200:
                body = response.read()[:4096].decode("utf-8", "replace")
                code = "url_expired" if "expired" in body.lower() else "evidence_unavailable"
                raise JobFailed(code, f"HTTP {response.status_code}")
            with open(dest, "xb") as f:
                for chunk in response.iter_bytes(CHUNK):
                    received += len(chunk)
                    if received > size_bytes:
                        raise JobFailed("integrity_mismatch", "more bytes than recorded")
                    digest.update(chunk)
                    f.write(chunk)
    except httpx.HTTPError as exc:
        raise JobFailed("evidence_unavailable", type(exc).__name__) from exc
    if received != size_bytes or digest.hexdigest() != expected_sha256:
        raise JobFailed("integrity_mismatch", "sha256 or size differs from the evidence record")
    os.chmod(dest, 0o444)


def upload(
    post: PresignedPost,
    path: Path,
    *,
    filename: str = "result.ndjson.gz",
    content_type: str = "application/gzip",
) -> str:
    """POST the result with the policy fields; returns the stored object's version id.

    M6: the report renderer passes its artifact's file name and content type (the policy
    fixes the content type per format); the defaults are the analyzers' result stream."""
    try:
        with open(path, "rb") as f:
            response = httpx.post(
                post.url,
                data=post.fields,
                files={"file": (filename, f, content_type)},
                timeout=TIMEOUT,
            )
    except httpx.HTTPError as exc:
        raise JobFailed("result_upload_failed", type(exc).__name__) from exc
    version_id = response.headers.get("x-amz-version-id")
    if response.status_code not in (200, 201, 204) or not version_id:
        raise JobFailed("result_upload_failed", f"HTTP {response.status_code}")
    return str(version_id)
