---
phase: 3
title: "Detections and IOCs"
status: pending
priority: P1
effort: "10h"
dependencies: [2]
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

## Risk Assessment
- Overfitting to synthetic data → thresholds documented, detectors kept simple, metrics
  reported honestly as "synthetic dataset" only.
