"""Evidence download (hash-verified) and result upload, both via presigned URLs only."""

import hashlib
import os
from pathlib import Path

import httpx
from cyberlab_jobs import PcapJobV1, PresignedPost

from pcap_worker.errors import JobFailed

CHUNK = 1024 * 1024
TIMEOUT = httpx.Timeout(30.0, read=120.0)


def download(job: PcapJobV1, dest: Path) -> None:
    """Stream the exact evidence version to `dest`; refuse anything but the expected bytes."""
    if job.size_bytes > job.limits.max_bytes:
        raise JobFailed("capture_too_large")
    digest = hashlib.sha256()
    received = 0
    try:
        with httpx.stream("GET", job.evidence_url, timeout=TIMEOUT) as response:
            if response.status_code != 200:
                body = response.read()[:4096].decode("utf-8", "replace")
                code = "url_expired" if "expired" in body.lower() else "evidence_unavailable"
                raise JobFailed(code, f"HTTP {response.status_code}")
            with open(dest, "xb") as f:
                for chunk in response.iter_bytes(CHUNK):
                    received += len(chunk)
                    if received > job.size_bytes:
                        raise JobFailed("integrity_mismatch", "more bytes than recorded")
                    digest.update(chunk)
                    f.write(chunk)
    except httpx.HTTPError as exc:
        raise JobFailed("evidence_unavailable", type(exc).__name__) from exc
    if received != job.size_bytes or digest.hexdigest() != job.expected_sha256:
        raise JobFailed("integrity_mismatch", "sha256 or size differs from the evidence record")
    os.chmod(dest, 0o444)


def upload(post: PresignedPost, path: Path) -> str:
    """POST the result with the policy fields; returns the stored object's version id."""
    try:
        with open(path, "rb") as f:
            response = httpx.post(
                post.url,
                data=post.fields,
                files={"file": ("result.ndjson.gz", f, "application/gzip")},
                timeout=TIMEOUT,
            )
    except httpx.HTTPError as exc:
        raise JobFailed("result_upload_failed", type(exc).__name__) from exc
    version_id = response.headers.get("x-amz-version-id")
    if response.status_code not in (200, 201, 204) or not version_id:
        raise JobFailed("result_upload_failed", f"HTTP {response.status_code}")
    return str(version_id)
