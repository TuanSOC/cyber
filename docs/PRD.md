# CyberLab AI — Product Requirements (Milestone 1)

CyberLab AI is a defensive investigation platform: analysts upload evidence, run specialized analysis engines, correlate findings and produce reports. The full vision is in `requirement.txt`; this document covers **Milestone 1 (foundation)**, which is what is built today.

## Goal of M1

A deployable, secure base that later analysis engines (PCAP, malware, TI, AI analyst) plug into:

- multi-tenant organizations with role-based access,
- investigation (case) management,
- evidence intake with integrity guarantees and a chain of custody,
- a complete audit trail.

## Personas

| Persona | Needs in M1 |
|---|---|
| **SOC / IR analyst** | Open a case, upload captures/dumps/samples, prove later that the evidence was not altered, see who touched it. |
| **Team lead / org admin** | Manage members and roles, review the audit log, archive closed cases. |
| **Viewer (manager, auditor)** | Read cases and evidence, download for review, no changes. |

## User stories (all delivered)

1. As a new user I register and become the owner of a new organization.
2. As an owner/admin I add existing users by email with a role (owner/admin/analyst/viewer), change roles, remove members.
3. As an analyst I create an investigation (`CASE-00001`, title, severity, description) and move it through `open → in progress → closed → archived` (reopen allowed; archived is read-only).
4. As an analyst I upload evidence of any type up to 2 GiB; the platform stores it untouched and shows MD5/SHA-1/SHA-256.
5. As any member I download evidence; the download is recorded in the chain of custody.
6. As an analyst I re-verify evidence at any time; a mismatch or missing content is flagged and recorded.
7. As an admin I review a filterable audit log of every change in my organization.
8. As any user I can see which modules are planned (PCAP, malware, forensics, memory, RE, TI, AI analyst, reports, integrations) — they show no fake data.

## Non-goals for M1 (explicitly deferred)

| Item | When |
|---|---|
| PCAP / malware / memory / disk / RE analysis engines, Celery workers, OpenSearch | M2+ (see ROADMAP) |
| Threat-intel providers, AI analyst, reports | M4–M6 |
| Dynamic analysis sandbox | Later, gated on isolation testing |
| Malware scanning of uploads (ClamAV) | M3 |
| Email verification, MFA, invitation acceptance flow | Later |
| Per-org storage quotas, data-retention/expiry policy, backup/restore | Later |
| Strict nonce-based CSP | M2 |

## Success criteria (M1 definition of done)

- `pnpm dev` starts the full stack; `pnpm verify` passes (lint, types, API + web tests, build, contract drift, headers, Playwright golden path on dev and the prod-like stack).
- Golden path works in a browser: register → case → upload → hashes → verify → download → custody → audit.
- Tenant isolation, RBAC, session and evidence-integrity properties are covered by automated tests (see TESTING.md).
- Nothing is claimed production-ready; known gaps are listed in THREAT_MODEL.md.

## Later milestones

M2–M6 are delivered (see ROADMAP). M5 adds the AI analyst: evidence-cited explanations of normalized findings that never give verdicts, never use tools and are never acted on automatically. It is opt-in per organization with a privacy acknowledgement (evidence excerpts go to the chosen provider; internal names are pseudonymized by default), provider keys are bring-your-own, and Gemini is limited to paid-tier keys. Details: [AI_ANALYST.md](AI_ANALYST.md).

M6 adds reports and the remaining case management ([REPORTS.md](REPORTS.md)). User stories:

1. As an analyst I write notes on a case, edit them (every version is kept) and delete them (the history stays readable); only the author or an admin changes a note.
2. As an analyst I build IOC collections from job IOCs or typed values (normalized and deduplicated) and export them as CSV, JSON or a STIX 2.1 bundle, marked with the case TLP.
3. As an analyst I close, reopen or archive a case with a reason, and the change appears in its history and timeline.
4. As an analyst I set the case TLP and mark a case or an evidence item "do not send to AI / TI"; AI runs and TI enrichments for it are then refused. Only an admin lowers a TLP or lifts an exclusion.
5. As an analyst I confirm, suspect or reject ATT&CK techniques for a case, from suggestions (capa, findings, verified AI) or by id, and see them as a tactic matrix.
6. As an analyst I export the case timeline as CSV or JSON.
7. As an analyst I write a report (executive summary, scope, methodology, impact, root cause, actions, recommendations, lessons learned), choose the evidence, findings, IOCs, ATT&CK mappings, notes and verified AI runs it includes, preview it, and finalize it into a signed, immutable version with a change note; a later finalize creates the next version.
8. As a reader I download the PDF, HTML or Markdown of a version, follow every `[Cn]` citation to the row it rests on, and see whether the signature and hash are valid; an external recipient verifies a PDF offline with the published public key.
9. As an analyst I produce an `external` version in which internal hosts, IPs and users are pseudonymized consistently, after reviewing the preview and stating the distribution.
