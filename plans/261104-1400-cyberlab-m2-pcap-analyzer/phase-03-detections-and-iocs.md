---
phase: 3
title: Detections and IOCs
status: completed
priority: P1
effort: 10h
dependencies:
  - 2
---

# Phase 3: Detections and IOCs

## Overview
Explainable heuristics over normalized records, emitted as `finding` lines, plus IOC
extraction and a network timeline. Measured against the labeled dataset.

## Requirements
- Finding fields (requirement §5): id, source evidence, timestamp, src/dst IP (+ports),
  protocol, severity (info/low/medium/high), confidence (0–1), evidence_refs (zeek uids,
  suricata flow ids, community ids), detection_method (`heuristic:<name>@<version>` or
  `suricata:<sid>`), title, description with the measured values that triggered it.
- Detectors (each a pure function `records -> findings`, thresholds in one config dataclass):
  - `beaconing`: per (src, dst, dport, proto) with ≥ 8 connections: inter-arrival CV ≤ 0.15
    and small byte variance → finding with period, jitter, count.
  - `port_scan`: one src → ≥ 20 distinct dst ports (vertical) or ≥ 15 hosts on one port
    (horizontal) with mostly `S0/REJ/RSTO` conn states within 5 min.
  - `dns_anomaly`: long labels (> 50) / high-entropy subdomains (Shannon > 3.5 on ≥ 20 chars),
    NXDOMAIN burst ratio, TXT-heavy, many unique subdomains under one domain (tunneling-like).
  - `suspicious_traffic`: HTTP to IP literal, executable MIME over cleartext HTTP, TLS with
    self-signed/expired cert, TLS < 1.2, known protocol on non-standard port (Zeek service vs
    port), cleartext credentials (zeek `Notice` / http basic auth seen).
  - Suricata alerts are not findings; they stay alerts (linked by flow).
- IOCs (observables, not verdicts): IPs (external only), domains, URLs, JA3/JA4, cert sha1,
  file hashes from files.log; each with first/last seen and count, `source` field.
- Timeline: capture start/end, findings, alerts, first contact with each external host
  (bounded: top N), ordered by ts.

## Architecture
- `pcap_worker/detections/{base,beaconing,port_scan,dns_anomaly,suspicious}.py`, versioned names.
- `pcap_worker/iocs.py`, `pcap_worker/timeline.py`.
- Evaluation harness `tests/evaluation/test_detection_quality.py`: runs engine on dataset,
  compares to `labels.json`, writes `evaluation.json` (precision/recall per detector, latency
  per scenario) and asserts floors (precision ≥ 0.9, recall ≥ 0.9 on the synthetic set).

## Success Criteria
- [ ] Each detector has unit tests with positive and negative cases (normal_web yields no
      beaconing/scan findings).
- [ ] Precision/recall floors met; numbers recorded in TESTING.md.
- [ ] No finding text claims maliciousness; wording reviewed.

## Implementation Notes (2026-11-04)
- **Flow detectors** (`detections/flow_detectors.py`) observe every flow during the single conn.log pass, before the flow cap. Otherwise scans, whose zero-byte flows are dropped first, would be missed.
  - **Beaconing** (external destinations only, because internal periodic traffic such as resolvers, NTP and monitoring is the norm): at least 8 connections per (src, dst, dport, proto), mean interval ≥ 5 s, interval CV ≤ 0.15, size CV ≤ 0.25.
  - **Port scan**: vertical needs ≥ 20 ports on one target; horizontal needs ≥ 15 hosts on one port; both need ≥ 70% failed attempts (S0 / REJ / RST* / SH / OTH). Severity is high at ≥ 100 targets.
  - State is capped at 50 k keys per detector (`truncated.detector_state`).
- **Record detectors** (`record_detectors.py`):
  - **DNS** per (src, registered domain = last two labels; no public-suffix list): tunneling-like if ≥ 10 queries with first labels of ≥ 40 chars or ≥ 20 chars with entropy ≥ 3.5, otherwise an NXDOMAIN burst if ≥ 10 NXDOMAIN and ratio ≥ 0.5.
  - **Suspicious traffic**: http_to_ip_literal, executable_over_http (by MIME), tls_self_signed, tls_expired_certificate, tls_legacy_version (SSLv2/3, TLS 1.0/1.1), service_on_nonstandard_port. One finding per (type, src, dst, port) with an occurrence count.
- **Finding records:**
  - Stable `finding_id` (uuid5 of job, method, type and endpoints), `detection_method` `heuristic:<name>@<version>`, up to 50 evidence refs (Zeek uids), and up to 20 attributes holding the measured values.
  - Capped at `max_findings`, sorted by severity, then confidence.
  - Wording describes behaviour with benign explanations; a test asserts no "malicious" claims.
  - Suricata alerts stay alerts, not findings.
- **IOCs** (`iocs.py`): external IPs, domains (DNS, HTTP host, SNI), URLs, JA3/JA3S, leaf cert sha256, transferred file md5/sha1/sha256 (Zeek files.log). Each has first/last seen, count and source; capped at the per-kind limit.
- **Timeline** (`run.py`): capture start/end, findings, Suricata alerts of severity ≤ 2 (up to 1 000), first contact with up to 100 external hosts; capped at the per-kind limit.
- **Contract additions:** `FindingRecord`, `IocRecord`, `TimelineEvent` in `cyberlab_jobs.results`.
- **Evaluation** (`tests/evaluation/test_detection_quality.py`, `EVALUATION_OUT` writes JSON) on the synthetic dataset with local test rules:
  - Parsing success 100%.
  - Precision and recall 1.0 for beaconing (1 TP), port_scan (2), dns_anomaly (1), suspicious_traffic (5), on individual scenarios and on mixed.
  - No false positives on normal_web or dns_traffic.
  - Latency about 1.2–1.4 s per scenario (ET Open adds about 40 s).
  - These are synthetic-data numbers, so they prove the detectors behave as specified, not real-world quality.
- **First evaluation run:** caught a beaconing false positive on resolver traffic (30 DNS queries at a fixed 1.7 s interval), which led to the external-destination rule.

## Risk Assessment
- Overfitting to synthetic data → thresholds documented, detectors kept simple, metrics
  reported honestly as "synthetic dataset" only.
