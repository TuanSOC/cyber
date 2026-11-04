# Synthetic PCAP dataset

Generated, never captured: RFC 5737 / RFC 1918 / `2001:db8::/32` addresses and `example.*`
names only; certificates are generated Ed25519 test certificates; the "executable" in
`suspicious_http` is inert filler bytes behind an `MZ` marker. Deterministic for a given seed.

    docker compose --profile test run --rm --no-deps pcap-worker-test python -m dataset.generate /work/ds

| Scenario | Content | Ground truth (`labels.json`) |
|---|---|---|
| normal_web | DNS + 3 HTTP page loads + 2 TLS sessions (CA-signed cert) | none (negative case) |
| dns_traffic | A/AAAA/MX/TXT lookups, 2 NXDOMAIN | none |
| tls_sessions | self-signed, expired and TLS 1.0 sessions | 3 suspicious_traffic |
| beacon | 12 HTTP POSTs every 60 s ± 0.8 s | beaconing |
| dns_anomalies | 30 random 45-char TXT labels under one domain, 20 NXDOMAIN | dns_anomaly |
| port_scan | vertical (120 ports) + horizontal (25 hosts on 445) | 2 port_scan |
| suspicious_http | IP-literal Host, executable MIME over cleartext HTTP | 2 suspicious_traffic |
| mixed | all of the above, time-shifted | union |
