import gzip
import hashlib
import json
import uuid
from pathlib import Path

from cyberlab_jobs.capture import CaptureFormat
from cyberlab_jobs.results import ResultHeader, ResultTrailer

from cyberlab_worker.result_writer import ResultWriter


def test_trailer_covers_every_prior_byte(tmp_path: Path) -> None:
    path = tmp_path / "r.ndjson.gz"
    header = ResultHeader(job_id=uuid.uuid4(), capture_format=CaptureFormat.PCAP, tool_versions={})
    with ResultWriter(path) as writer:
        writer.write(header)
        writer.write(header)

    lines = gzip.decompress(path.read_bytes()).splitlines(keepends=True)
    trailer = ResultTrailer.model_validate(json.loads(lines[-1]))
    assert trailer.line_count == 2
    assert trailer.sha256 == hashlib.sha256(b"".join(lines[:-1])).hexdigest()
    assert json.loads(lines[0])["kind"] == "header"
