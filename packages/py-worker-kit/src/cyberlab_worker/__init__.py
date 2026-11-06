"""Shared kit of the untrusted analysis workers (pcap, static, memory).

- `sandbox`: run tools as uid 10003 (seccomp, rlimits), safe output reads, kill-by-uid cleanup.
- `transfer`: hash-verified evidence download and size-capped result upload (presigned only).
- `result_writer`: gzip NDJSON with a hashed trailer; `Spool` for bounded-memory assembly.
- `parsing`: bounded JSON-lines reader and value helpers for attacker-influenced tool output.
- `iocs`: the IOC extractor over untrusted text (lifted from the static worker, M8).
- `apisets`: the M3 suspicious API sets, data only (lifted for the RE worker, M10 RT7).
"""
