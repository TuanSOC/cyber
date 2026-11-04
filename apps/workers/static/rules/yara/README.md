# YARA rules (baked into the image at /opt/yara/rules)

Placeholder. Curated, licence-compatible rule files (`*.yar`) are added here later; each
source must be pinned (upstream commit or release) with its licence noted next to the file.

- Evaluated with yara-python (no yara CLI in the image), with a per-scan timeout.
- Rule severity defaults to `low`; only an allowlist of rules may raise it (plan RT11).
- The baked rules are also evaluated on the benign samples to catch false positives.
- Test-only rules (e.g. the CyberLab test marker) live with the tests, not here.
