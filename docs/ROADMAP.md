# Roadmap

| Milestone | Scope | Notes |
|---|---|---|
| **M1 — Foundation** ✅ | Monorepo, Compose, auth, orgs/RBAC, investigations, evidence with integrity + custody, audit, dashboard shell | this release |
| **M2 — PCAP Analyzer** | Celery workers + versioned job schema; TShark, Zeek, Suricata in isolated worker images reading evidence by version; normalized findings (id, evidence ref, timestamp, src/dst, protocol, severity, confidence, detection method); protocol/host statistics, DNS/HTTP/TLS metadata, flows, beaconing indicators, IOC extraction, network timeline; OpenSearch for findings; anonymized PCAP test set | also: strict nonce-based CSP, move file-type identification into workers, storage quotas |
| **M3 — Malware static analysis** | Hashes, PE/ELF metadata, sections, imports/exports, strings, entropy, packer indicators, YARA, capa, FLOSS, suspicious API indicators; ClamAV scan of uploads | never "malicious" from imports/entropy alone |
| **M4 — Threat intelligence** | Provider interfaces (VirusTotal, AbuseIPDB, URLhaus, OTX, MalwareBazaar, MISP, ATT&CK), cache, rate limits, encrypted API keys (server-side only), historical enrichment; Integrations page | reputation never sole evidence |
| **M5 — AI Analyst** | Provider abstraction (Claude, Gemini), structured JSON output that separates observed evidence / interpretation / hypothesis / confidence / next step, citations to findings; no command execution, no host access | prompt-injection tests |
| **M6 — Reports** | Investigation reports with evidence citations, timeline, ATT&CK mapping | |
| Later | Memory forensics (Volatility 3), disk forensics (TSK, Plaso), reverse engineering (Ghidra headless, radare2), analyst notes, IOC collections, invitations/MFA/SSO, backups, retention policies | |
| Gated | Dynamic analysis (CAPE) in disposable, network-isolated VMs | not enabled until isolation is tested |
