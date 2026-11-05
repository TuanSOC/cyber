# Researcher report: M6 report rendering, signing, TLP (2026-11-06)

Scope: how to export professional investigation reports (PDF, HTML, Markdown, DOCX) from untrusted evidence text in an isolated, no-network worker; immutability and signing; TLP 2.0; DFIR report structure; accessibility. Versions and CVE ids come from web sources read on 2026-11-06. **Phase 1 re-verifies every version and CVE id against PyPI and OSV before pinning.**

## Recommendation

**WeasyPrint (≥ 70.0, BSD-3) in a dedicated `report-renderer` container with `network_mode: none`**, rendering one Jinja2-autoescaped HTML template. Not Chromium, Playwright or Gotenberg.

Why not Chromium:
- Its renderer sandbox needs a custom seccomp profile with user namespaces plus `--ipc=host`, which conflicts with `cap_drop: [ALL]` and the default seccomp profile. The alternative, `--no-sandbox`, removes the sandbox altogether.
- It ships a JS engine. Every month brings high-severity V8, Blink or Skia CVEs.
- The image is 1–2 GB.
- It stamps a CreationDate, so the output is not reproducible, and it makes no PDF/UA or PDF/A claim.

Why not Gotenberg: it puts the same Chromium behind an HTTP API, and it had several 2026 SSRF fixes in its deny-list (CVE-2026-27018, -42595, -45741).

Why not browser print-to-PDF (`window.print`): the output depends on the browser and is not reproducible. It also cannot be signed or archived server-side, and the TLP marking cannot be guaranteed. Keep it only as a "quick print" of the viewer.

Why WeasyPrint:
- It has no JS engine.
- Every resource load goes through one choke point, `URLFetcher`, which can deny everything.
- It produces native `pdf/a-3a` (tagged, allows embedded files), `pdf/ua-1` and `pdf/ua-2`.
- It accepts `attachments=`, so `snapshot.json` can be embedded in the PDF.
- It is reproducible with a fixed `pdf_identifier` and fixed `dcterms.created` / `dcterms.modified` meta.
- Debian dependencies: `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`.

## WeasyPrint facts

- **Versions:** 70.0 (2026-09-08), 69.0 (2026-06), 68.0 (2026-01). Needs Python ≥ 3.10 and Pango ≥ 1.44. `pydyf` is the PDF writer.
- **CVEs** (pin ≥ 70.0):
  - CVE-2025-68616 (fixed in 68.0): the default fetcher followed redirects without re-checking the policy (SSRF);
  - CVE-2026-49452 (fixed in 69.0): with `presentational_hints=True`, HTML attribute values were injected into CSS;
  - CVE-2026-55073 (fixed in 70.0): the `xmp_metadata` and `stylesheets` arguments bypassed a custom fetcher (local file read, SSRF).
  - Lesson: `write_pdf` options are constants, never derived from data; keep `presentational_hints=False`.
- **Fetcher:** 68.0 added the `URLFetcher` class (`allowed_protocols`, `timeout`, `allow_redirects`, `fail_on_errors`; subclass `fetch`). Raising `FatalURLFetchingError` aborts the render.
- **Upstream security note:** a small crafted document can use a lot of CPU and RAM, and `file://` can read local files. Upstream recommends timeouts, memory limits, a non-root user and a container.
- **Reproducibility:** "reproducible PDF generation" since 55.0. No documented `SOURCE_DATE_EPOCH`, so a CI test must render twice and compare bytes.

Sources: https://doc.courtbouillon.org/weasyprint/stable/changelog.html, https://doc.courtbouillon.org/weasyprint/stable/api_reference.html, https://osv.dev/vulnerability/CVE-2026-55073, https://tracker.debian.org/weasyprint

## Templating and text hygiene

- **Jinja2 ≥ 3.1.6:** `SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)`.
  - The sandbox protects against untrusted templates. Our templates are trusted, so here it is a cheap extra.
  - A CI lint bans `|safe`, `Markup(`, `autoescape false` and `{% raw %}` with data in the report templates.
- **Never interpolate evidence into CSS:** no `<style>`, `style=""`, `url()`, `class` or `id`. Severity and TLP map to a fixed allow-listed class set.
- **Neutralize, don't strip silently:** make bidi overrides, zero-width and control characters visible (for example `⟨U+202E⟩`).
- **Defang** URLs, domains and IPs. Evidence is never rendered as `<a href>`.
- **Cap and wrap:** per-string caps with a `…[truncated n]` marker; `overflow-wrap: anywhere` on code and IOC cells.
- **AI and analyst text:** render it as plain text with paragraphs, never as Markdown or HTML. If Markdown is ever needed: markdown-it-py with HTML off, then nh3 with an allow-list.

## DOCX and Markdown

- **DOCX:** python-docx 1.2.0 (MIT) escapes by construction through lxml.
  - Strip XML-invalid control characters first.
  - No hyperlinks or fields built from evidence.
  - Never docxtpl or Jinja over untrusted data inside DOCX.
- **Markdown:**
  - backslash-escape ASCII punctuation;
  - evidence goes in fenced code blocks whose fence is longer than any backtick run in the content;
  - escape `|` in tables;
  - neutralize leading `#`, `>`, `-`, `=` and digit-dot;
  - no raw HTML and no links.
- **Pandoc:** avoid it. If it is ever used, run it with `--sandbox`.

## Immutability and signing

- **Snapshot hash:** a canonical JSON snapshot (sorted keys, UTF-8, no whitespace; RFC 8785-like) → SHA-256.
- **Signature:** a detached Ed25519 signature (`cryptography`) over a small signed manifest. The key stays outside the renderer.
- **PDF/A-3a:** embeds `snapshot.json` and `manifest.json`. The footer prints the short sha256 and the version.
- **Optional:** PAdES via pyHanko 0.35.x (MIT) with ECDSA P-256 or RSA, because reader support for EdDSA in PDF signatures is limited. Deferred for M6.

## TLP 2.0 (FIRST)

- **Labels:** `TLP:RED`, `TLP:AMBER+STRICT`, `TLP:AMBER`, `TLP:GREEN`, `TLP:CLEAR`. Capitals, no spaces, never translated.
- **Colours** (text on a black #000000 background):
  - RED #FF2B2B;
  - AMBER and AMBER+STRICT #FFC000;
  - GREEN #33FF00;
  - CLEAR #FFFFFF.
- **Marking:** the label goes in the header and footer of every page, ≥ 12 pt, right-aligned recommended. In WeasyPrint that is `@page { @top-right {…} @bottom-right {…} }`.

Source: https://www.first.org/tlp/

## Report structure (NIST SP 800-61r2 §3.2.5 practice; r3 has no template)

1. Cover (TLP, case id, report version, snapshot sha256)
2. Executive summary
3. Scope and methodology (tools and versions)
4. Timeline (UTC)
5. Findings and technical analysis (ATT&CK)
6. IOCs (defanged)
7. Impact
8. Root cause
9. Actions taken
10. Recommendations
11. Appendices: evidence inventory with hashes, chain of custody, AI disclaimer, citations, glossary

## Accessibility

- **WeasyPrint `pdf/ua-1` or `pdf/a-3a`** gives a tagged structure tree, provided the template has:
  - `<html lang>` and a `<title>`;
  - real headings;
  - `<th scope>` on table headers;
  - alt text;
  - DOM order equal to reading order.
- **Validation:** veraPDF (Java, about 300 MB). It runs locally or as a one-off container, never in the renderer image.
- **Chromium:** tagged output and an outline, but no PDF/UA claim.

## Hardening list (renderer)

1. **Pinned options:** WeasyPrint ≥ 70.0 pinned by hash. Render with `HTML(string=…, base_url=None)` and only constant `write_pdf` options: `presentational_hints=False`, no `stylesheets` or `xmp_metadata` from data.
2. **Deny-all `URLFetcher`:** allow only `file:` under the read-only `/app/assets` (realpath checked) and image `data:` URIs within caps. Everything else raises a fatal error, so the render fails closed.
3. **Fonts:** bundled (Noto Sans / Noto Sans Mono); fontconfig points only there.
4. **Container:**
   - `network_mode: none`, `read_only`, tmpfs `/tmp` (`noexec`, size cap);
   - `cap_drop: [ALL]`, `no-new-privileges`, a non-root uid;
   - `mem_limit` about 1 GB, `pids_limit` 64, `cpus` 1, the default seccomp profile.
5. **Limits:** a hard time limit per render, the render in a subprocess with `RLIMIT_AS` / `RLIMIT_CPU`, one task per child.
6. **Input and output caps:** findings, IOCs and table rows, per-string length; a page-count and size check after rendering.
7. **Escaping:** autoescape, `StrictUndefined`, the `|safe` lint, visible bidi and control characters.
8. **Signing:** hash and sign outside the renderer; embed the snapshot as a PDF/A-3 attachment.
9. **TLP marking:** `@page` margin boxes in the FIRST colours, ≥ 12 pt.
10. **CI:**
    - render twice and compare bytes;
    - hostile-fixture fuzz (`</style>`, `url(file:///etc/passwd)`, U+202E, MB-long strings, `<img src=http://…>` as text);
    - veraPDF locally.
