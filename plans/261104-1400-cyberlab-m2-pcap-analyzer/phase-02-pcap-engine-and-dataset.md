---
phase: 2
title: "PCAP engine and dataset"
status: pending
priority: P1
effort: "18h"
dependencies: [1]
---

# Phase 2: PCAP engine and dataset

## Overview
Real analysis inside pcap-worker: capture metadata (capinfos/tshark), protocol hierarchy,
Zeek logs (conn, dns, http, ssl, x509, files, weird, notice), Suricata eve alerts, normalized
into the `pcap.v1` result stream. Plus the synthetic labeled dataset used by every later test.

## Requirements
- Functional: PCAP and PCAPNG; protocol statistics; source/destination IP statistics (top
  talkers by bytes/packets/flows); TCP/UDP conversations and flows (from conn.log); DNS
  (query, qtype, rcode, answers, TTL); HTTP (method, host, uri, status, UA, mime, sizes);
  TLS (version, SNI, cipher, JA3/JA3S from Suricata eve `tls` [RT9], cert subject/issuer/validity, validation
  status); JA4 out of M2; Suricata alerts (signature id/rev, category, severity, flow ref).
- Refuse compressed captures (gzip/zstd/lz4/xz magic) with `unsupported_capture_format` [RT13]; only raw pcap/pcapng.
- Non-functional: each tool run as uid 10003 via the phase-1 sandbox runner, `RLIMIT_CPU` + wall-clock timeout (no `RLIMIT_AS` until measured) [RT5],
  cwd in per-job tmpfs dir removed afterwards; tool failure of one engine → partial result
  with `engine_errors` (job still succeeds if Zeek succeeded); malformed capture → failed
  `unparseable_capture`.

## Architecture
- `pcap_worker/engines/{capinfos,tshark,zeek,suricata}.py`: each returns typed Python records,
  never raw tool text to the API. Zeek run: `zeek -C -r file LogAscii::use_json=T
  local policy/protocols/conn/community-id-logging "Site::local_nets += {...}"` [RT9].
  Suricata: `suricata -r file -l <job>/suri -k none --runmode single --set unix-command.enabled=no
  --set outputs.1.eve-log.community-id=yes --set app-layer.protocols.tls.ja3-fingerprints=yes`, eve types
  alert, tls, flow only; Lua disabled [RT8/RT13]. TShark: `HOME`/`XDG_CONFIG_HOME` = job dir.
- `pcap_worker/normalize.py`: zeek uid kept as `flow_ref`; suricata `flow_id` + `community_id`
  (enable `community-id` in both Zeek and Suricata) to join alerts to flows.
- Result stream `result.ndjson.gz`: line 1 `header` (schema_version, job_id, capture meta,
  tool versions, rule version, engine_errors, truncation flags), then `stats`, `flow`, `dns`,
  `http`, `tls`, `alert`, `finding` (phase 3), `ioc` (phase 3) lines; last line `trailer`
  (counts + sha256 of preceding bytes) so truncation is detectable by ingest.
- Caps from `JobLimits` applied in the worker (flows sorted by bytes desc when truncated; flag set).
- Dataset `apps/workers/pcap/dataset/`: `generate.py` (scapy, seed 1337, RFC 5737/1918/
  example domains only) → `normal_web`, `dns_traffic`, `tls_sessions`, `beacon`,
  `dns_anomalies`, `port_scan`, `mixed` + `labels.json` (ground truth per scenario);
  generated at test time (not committed as binaries); `make dataset` target for manual use.
- TLS scenarios carry real DER certificates (self-signed, expired, valid-chain) generated with `cryptography`
  over TLS 1.2 so Zeek x509/ssl logs and cert detectors are testable [RT9].
- Rules: `suricata-update` at image build (ET Open), snapshot sha256 + version written to
  `/etc/cyberlab/versions.json` and reported in every result header [RT13].
- Test-only Suricata rules (`tests/rules/local-test.rules`) mounted via `SURICATA_EXTRA_RULES`;
  production uses ET Open only.

## Related Code Files
- Create: `apps/workers/pcap/pcap_worker/{engines/*,normalize,result_writer,limits}.py`
- Create: `apps/workers/pcap/dataset/{generate.py,README.md}`, `tests/{unit,integration}/`
- Modify: `packages/py-jobs/cyberlab_jobs/results.py` (record models), worker Dockerfile.

## Implementation Steps
1. Worker Dockerfile: zeek/zeek:8.0 + apt tshark, suricata, suricata-update; `suricata-update`
   at build; uv + Python deps; non-root user 10002; tool versions baked into `/etc/cyberlab/versions.json`.
2. Engines + normalization + result writer; unit tests on small generated captures.
3. Dataset generator + labels; integration test running the full engine on each scenario
   inside the worker container (`docker compose --profile test run --rm pcap-worker-test`).
4. Malformed inputs: truncated pcap, random bytes, pcapng with exotic block, zero packets,
   huge snaplen → expected outcome per case, never a hang.

## Success Criteria
- [ ] All dataset scenarios parse (parsing success rate 100% on valid captures).
- [ ] Malformed captures produce `failed`/partial results within the timeout.
- [ ] Result stream validates against `cyberlab_jobs` models; trailer detects truncation.

## Risk Assessment
- Image size (~1 GB): built once, cached; only the worker uses it.
- Scapy-built TLS handshakes may not satisfy Zeek's parser → keep generator TCP-correct
  (3-way handshake, seq/ack), verify ssl.log appears in tests.
- ET Open drift between builds → rule version recorded; tests use local test rules only.
