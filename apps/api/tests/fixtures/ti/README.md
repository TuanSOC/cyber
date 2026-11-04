# Threat-intel provider fixtures (M4)

Recorded-*style* HTTP response bodies for the lookup-only adapters in
`app/modules/threat_intel/providers/`. **Every file is synthetic**: nothing was captured from a
live API, no real keys, no customer data, no real sample hashes.

## Provenance

Bodies are handcrafted to match the public response shapes documented by each provider
(checked 2026-11-04) and the field lists in `plans/reports/researcher-261105-m4-providers.md`:

| Dir | Shaped after |
|---|---|
| `virustotal/` | VirusTotal API v3 reference: IP address, Domain, URL and File objects (`GET /api/v3/{ip_addresses,domains,urls,files}/{id}`), and the "Errors" page (`{"error":{"code","message"}}`, `NotFoundError`, `WrongCredentialsError`, `ForbiddenError`, `QuotaExceededError`, `TooManyRequestsError`, `TransientError`) |
| `abuseipdb/` | AbuseIPDB APIv2 docs: `GET /api/v2/check` (verbose), the error format (`{"errors":[{"detail","status"}]}`) and the `X-RateLimit-*` / `Retry-After` headers on 429 |
| `urlhaus/` | URLhaus API docs (`urlhaus-api.abuse.ch`): `POST /v1/url/`, `/v1/host/`, `/v1/payload/` and their `query_status` values |
| `malwarebazaar/` | MalwareBazaar API docs (`bazaar.abuse.ch/api/`): `POST /api/v1/` `query=get_info` and its `query_status` values |
| `otx/` | AlienVault/LevelBlue OTX DirectConnect v1: `GET /api/v1/indicators/{IPv4,domain,url,file}/{value}/general`; errors in Django REST Framework form (`{"detail": ...}`) |
| `misp/` | MISP OpenAPI: `POST /attributes/restSearch` (`{"response":{"Attribute":[...]}}`), `GET /servers/getVersion`, and MISP's CakePHP error body (`{"name","message","url"}`) |

Values used:

- IPs only from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; ASN 64500 (documentation range).
- Domains, URLs and emails only under `example.com/.net/.org`. Provider hosts (e.g. `urlhaus.abuse.ch`)
  appear only where the real response carries its own reference/permalink.
- Hashes are md5/sha1/sha256 of the ASCII strings `cyberlab-fixture-hit`, `cyberlab-fixture-not-found`,
  `cyberlab-fixture-hostile`. Family names (`ExampleBot`, `FixtureStealer`), engine and vendor names
  (`Engine000`, `ExampleSandbox`, `FixtureIntel`, ...) are invented.
- Key-echo bodies contain the sentinel `CYBERLAB-TEST-SENTINEL-KEY-0000000000000000` (also
  `manifest.json` → `sentinel_key`). Configure that as the provider key so the key-placement test
  can assert it never leaks out of the auth header.

## Layout and naming

`<provider>/<ioc_type>_<case>.json`, where the file-name `ioc_type` is `ip`, `domain`, `url`, `file`
(any hash) or `email`; shared bodies use `error_<status>.json`, `malformed.txt`, `deep_nesting.txt`.
MISP uses `attributes_*` for the restSearch responses (`attributes_hit.json` is the IP hit) and
`get_version.json` for verify.

| Case | Meaning |
|---|---|
| `*_hit` | Rich hit: tags, families, detections, first/last seen |
| `*_not_found` / `*_no_results` / `*_hash_not_found` / `*_quiet` / `attributes_not_found` | The provider's real not-found form (VT/OTX 404, abuse.ch `query_status`, OTX 200 with `pulse_info.count: 0`, MISP empty `Attribute`, AbuseIPDB score 0 + 0 reports) |
| `*_hostile` | A hit whose strings carry HTML/script, `javascript:`/`data:` URLs, NUL/BEL/ANSI/CRLF, bidi overrides and isolates, zero-width chars, a lone UTF-16 surrogate, wrong value types, invalid ATT&CK ids (OTX/MISP: only `T1055` / `T1059.001` are valid), and non-numeric MISP `event_id`s. Expect sanitizing, not rejection |
| `*_huge` | One per provider: hundreds of tags/rows and a ~2.5 KB string with a trailing `<script>`, written compactly (all six ≈ 59 KB). Expect caps |
| `url_spoofed_reference` (URLhaus) | `urlhaus_reference` on a look-alike host; must be dropped (RT19) |
| `error_*` | 401/403 (incl. key echo), 422 (AbuseIPDB), 429, 5xx, abuse.ch 200-with-error bodies |
| `malformed.txt` | Hit body truncated at 2/3: invalid JSON |
| `deep_nesting.txt` | Valid JSON nested 3000 arrays deep. CPython 3.14's `json` accepts it, so the adapter must enforce its own depth cap; `.txt` so naive tooling does not choke |

Timeout and 2 MiB oversize cases have no file: the manifest marks them with `"file": null` and a
`simulate` hint, and the test handler raises `httpx.ReadTimeout` or builds the body itself.

## manifest.json

`providers.<provider>` holds `base_url`, `auth_header`, `notes` (shape uncertainties) and `cases`.
Each case is one line:

```json
{"file": "ip_hit.json", "http_status": 200, "headers": {"Content-Type": "application/json"},
 "ioc_type": "ip", "ioc_value": "192.0.2.10",
 "request": {"method": "GET", "path": "/api/v3/ip_addresses/192.0.2.10"}, "expect": "found"}
```

- `ioc_type` uses the app's `IocType` values (`ip`, `domain`, `url`, `email`, `file_md5`, `file_sha1`,
  `file_sha256`); `null` for MISP verify cases.
- `request.form` is the abuse.ch form body; MISP sends `request_body_template` with `value` filled in.
- `expect` is the intended outcome: `found`, `found_sanitized`, `found_capped`, `found_reference_dropped`,
  `not_found`, `auth`, `rate_limited`, `quota_exhausted`, `bad_request`, `invalid_input`, `unavailable`,
  `parse_error`, `timeout`, `oversize`, `verified`. Map these to `ProviderResult.status` /
  `ProviderError` kinds in the test.
- 429 cases exist with and without `Retry-After` where the provider can send it.

## Adding a case

1. Write the body under `<provider>/` using the naming rule and only documentation values (above).
   Keep it small; never paste a live response without scrubbing keys, hostnames, IPs and hashes.
2. Add a one-line entry under `providers.<provider>.cases` in `manifest.json` (unique key
   `<ioc_type>_<case>`), with the HTTP status, any rate-limit headers and the `expect` outcome.
3. Check that it parses: `python -m json.tool <file>` (not for `malformed.txt` and
   `deep_nesting.txt`), and keep the directory under 400 KB.
