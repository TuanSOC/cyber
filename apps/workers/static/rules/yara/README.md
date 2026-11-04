# YARA rules (baked into the image at /opt/yara/rules)

| File | Source | Licence |
|------|--------|---------|
| `cyberlab_baseline.yar` | written in-house for CyberLab | same as this repository |

No third-party rules are vendored (licensing). External rulesets (e.g. YARA-Forge,
signature-base) can be mounted over `/opt/yara/rules` (`*.yar` / `*.yara`, read-only); pin the
upstream release and note its licence next to the mount in your deployment.

- Evaluated with yara-python inside the tool-uid probe (no yara CLI in the image), with a
  per-scan timeout. A file that fails to compile is dropped (`yara_rule_error`), the rest run.
- Namespaces are `image.<file stem>` for rules here and `test.<file stem>` for the test-only
  directory (`STATIC_YARA_TEST_RULES`, used by the test container only).
- Rule severity defaults to `low`; only rules on the allowlist in
  `static_worker/detections/signatures.py` may raise it (up to the allowlisted level). The
  allowlist is keyed on the rule file's sha256 + rule name: editing `cyberlab_baseline.yar`
  means updating `BASELINE_SHA256` (a unit test compares), and a mounted file that reuses the
  name inherits nothing. Test-rule entries apply only when `STATIC_YARA_TEST_RULES` is set.
- The baked rules are evaluated on the benign samples too (evaluation harness: zero hits).
- Test-only rules (the CyberLab test marker) live in `tests/rules/yara/`, not here.
