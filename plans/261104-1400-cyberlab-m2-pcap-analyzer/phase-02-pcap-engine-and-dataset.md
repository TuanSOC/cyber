---
phase: 2
title: PCAP engine and dataset
status: completed
priority: P1
effort: 18h
dependencies:
  - 1
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

## Implementation Notes (2026-11-04)
- Engines, all run as the tool uid under seccomp:
  - **capinfos** `-T -M -S`: table output, parsed by column header.
  - **tshark** `-n -q -z io,phs`: protocol hierarchy, indentation turned into `eth:ip:tcp:http` paths.
  - **Zeek 8** with `engines/cyberlab.zeek`: community-id logging, validate-certs, hash-all-files, JSON logs, `ignore_checksums`, RFC 1918 local nets.
  - **Suricata 7** `-S <rules> --runmode single -k none`, eve community-id and JA3 enabled, unix socket off.
- What each engine contributes:
  - Zeek: flows (conn), DNS, HTTP, TLS. The leaf certificate comes from `cert_chain_fps[0]` joined to x509.log (sha256 fingerprint); `self_signed` means subject == issuer.
  - Suricata: alerts and JA3/JA3S, joined to Zeek through community id (alert `flow_ref` = Zeek uid).
- Capture handling:
  - A capture cut short mid-packet (capinfos exits non-zero but prints its numbers) is analyzed, with engine error `capture_cut_short`.
  - Bytes after a valid magic that are garbage give `unparseable_capture`.
  - A tshark/zeek/suricata failure or timeout becomes an engine error; the job still succeeds.
- Caps:
  - Flows truncated by bytes (largest kept), other kinds by order; each truncation is flagged.
  - Statistics (top talkers and ports, counts) are computed over every flow, before truncation.
- Budget: each tool gets `min(tool_timeout, remaining job time − 30 s)`.
- Measured:
  - ET Open snapshot (69 k lines) loads in about 40 s per job; Suricata peaks at about 605 MiB container memory (limit 2 GiB).
  - Tests and the pcap-worker-test service use `tests/rules/local-test.rules` (`SURICATA_RULES`); one test runs the shipped ET Open set (fires `ET USER_AGENTS` on the beacon).
- Dataset (`dataset/generate.py`, seed 1337, regenerated at test time, never committed as binaries):
  - Scenarios: normal_web, dns_traffic, tls_sessions (self-signed, expired, TLS 1.0, real DER certs from `cryptography`), beacon (12 × 60 s ± 0.8 s), dns_anomalies (30 random 45-char TXT labels, 20 NXDOMAIN), port_scan (vertical 1–120 + horizontal 25 hosts on 445), suspicious_http (IP-literal host, inert fake PE bytes), plus mixed.
  - `labels.json` holds ground truth for phase 3.
- Review fixes (3 High, 6 Medium, 3 Low; all applied):
  - **Bounded root reader (`JsonLines`):** bounded `readline`, giant or unterminated lines skipped in chunks, a 1 GiB per-file cap, a line cap reported as `truncated[<log>]`, per-record conversion errors (ValueError, OverflowError, TypeError, RecursionError) skipped and counted in `stats.counts.skipped_*`, FIFOs and symlinks read as empty.
  - **Memory bounded by job limits, not capture size:**
    - `conn.log` is read once; the largest `max_flows` flows are kept in a heap.
    - Statistics are accumulated over every flow read, capped at 100 k distinct keys (`truncated.stats_keys`).
    - Other kinds are spooled to root-owned temp files, because the header with its flags has to come first in the stream.
  - **Suricata eve:** `suricata-cyberlab.yaml` (via `--include`) limits eve to alert (no metadata) and tls, so alerts cannot be buried under flow or anomaly events. eve is read once.
  - **Correct pairing:** alert→flow and JA3→TLS pick the flow or event matching in time when a 5-tuple is reused (spans per community id, ±2 s).
  - **Community ID computed locally:** v1 is computed from the 5-tuple (tested equal to Zeek's), so the TLS↔JA3 join needs no map over every flow.
  - **Zeek is mandatory:** a Zeek failure or timeout fails the job (`zeek_failed` / `zeek_timeout`), except a fatal "truncated dump file" on a cut-short capture (`zeek_cut_short`, partial logs kept). Suricata is skipped (`suricata_skipped`) when the budget is gone.
  - **No leftovers between engines:** `kill_tool_processes()` runs after every engine.
  - **Contract hardened:** aware timestamps in 1970..2100 normalized to UTC, no IPv6 zone ids, counters ≤ 2^63−1, finite floats, `LINE_ADAPTER` covering every line kind.
  - **Stats split:** sources and destinations are separate (`top_sources` / `top_destinations`), each with bytes, packets and flows.
  - **Deterministic dataset:** Ed25519 keys derived from the seed (deterministic signatures); the real domain `exmaple.org` was replaced with `nonexistent.example.org`. `dataset/README.md` added.
  - **Tests:** hostile parser inputs (`tests/unit/test_parsers.py`), PCAPNG, community-id equality, determinism, cut-short flags, ja3s/validation_status, cap flags and byte ordering. 44 worker tests in total.
- The pcap-worker-test container also mounts `pyproject.toml` (the image copy goes stale). Formatting has to run outside it (`docker run … ruff format`) because its sources are mounted read-only.

## Risk Assessment
- Image size (~1 GB): built once, cached; only the worker uses it.
- Scapy-built TLS handshakes may not satisfy Zeek's parser → keep generator TCP-correct
  (3-way handshake, seq/ack), verify ssl.log appears in tests.
- ET Open drift between builds → rule version recorded; tests use local test rules only.
