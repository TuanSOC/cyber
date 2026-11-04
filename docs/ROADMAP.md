# Roadmap

| Milestone | Scope | Notes |
|---|---|---|
| **M1 — Foundation** ✅ | Monorepo, Compose, auth, orgs/RBAC, investigations, evidence with integrity + custody, audit, dashboard shell | this release |
| **M2 — PCAP Analyzer** ✅ | Isolated pcap-worker (Zeek 8, TShark, Suricata 7 + ET Open) behind versioned job/result contracts; trusted ingest into tenant tables; flows, DNS/HTTP/TLS, alerts, heuristic findings (beaconing, scans, DNS anomalies, suspicious traffic), IOCs, timeline; analyzer UI; synthetic labeled dataset with precision/recall | Deferred from M2: OpenSearch (Postgres suffices at this scale), nonce CSP and storage quotas (→ M3), JA4, per-org fair scheduling |
| **M3 — Malware static analysis** | Nonce-based CSP, per-org storage quotas; hashes, PE/ELF metadata, sections, imports/exports, strings, entropy, packer indicators, YARA, capa, FLOSS, suspicious API indicators; ClamAV scan of uploads | never "malicious" from imports/entropy alone |
| **M4 — Threat intelligence** | Provider interfaces (VirusTotal, AbuseIPDB, URLhaus, OTX, MalwareBazaar, MISP, ATT&CK), cache, rate limits, encrypted API keys (server-side only), historical enrichment; Integrations page | reputation never sole evidence |
| **M5 — AI Analyst** | Provider abstraction (Claude, Gemini), structured JSON output that separates observed evidence / interpretation / hypothesis / confidence / next step, citations to findings; no command execution, no host access | prompt-injection tests |
| **M6 — Reports** | Investigation reports with evidence citations, timeline, ATT&CK mapping | |
| Later | Memory forensics (Volatility 3), disk forensics (TSK, Plaso), reverse engineering (Ghidra headless, radare2), analyst notes, IOC collections, invitations/MFA/SSO, backups, retention policies | |
| Gated | Dynamic analysis (CAPE) in disposable, network-isolated VMs | not enabled until isolation is tested |
