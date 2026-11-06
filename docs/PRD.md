# CyberLab AI — Product Requirements

CyberLab AI is a defensive investigation platform: analysts upload evidence, run specialized analysis engines, correlate findings and produce reports. The full vision is in `requirement.txt`. This document describes the **current scope** (M1–M7, see [ROADMAP.md](ROADMAP.md) for status) and what is explicitly out of it.

## Goal

A secure, multi-tenant investigation platform on a single node:

- multi-tenant organizations with role-based access and a complete audit trail;
- investigation (case) management with notes, IOC collections, status history, TLP and ATT&CK mapping;
- evidence intake with integrity guarantees and a chain of custody;
- isolated analysis engines (PCAP, static malware analysis), threat-intel enrichment and an evidence-cited AI analyst whose output is never a verdict;
- signed, evidence-cited reports;
- operability: backup and restore, data retention with legal hold, cross-case correlation, org-wide search and runtime metrics.

## Personas

| Persona | Needs |
|---|---|
| **SOC / IR analyst** | Open a case, upload captures/dumps/samples, prove later that the evidence was not altered, see who touched it, analyze captures and samples, enrich IOCs, pivot across cases, write a signed report. |
| **Team lead / org admin** | Manage members and roles, review the audit log, archive closed cases, configure integrations, set the retention policy and legal holds, watch job failure rates. |
| **Viewer (manager, auditor)** | Read cases, evidence and reports, download for review, no changes. |
| **Operator** | Deploy, back up and restore the stack, rotate secrets, scrape metrics. |

## User stories

### M1 foundation (delivered)

1. As a new user I register and become the owner of a new organization.
2. As an owner/admin I add existing users by email with a role (owner/admin/analyst/viewer), change roles, remove members.
3. As an analyst I create an investigation (`CASE-00001`, title, severity, description) and move it through `open → in progress → closed → archived` (reopen allowed; archived is read-only).
4. As an analyst I upload evidence of any type up to 2 GiB; the platform stores it untouched and shows MD5/SHA-1/SHA-256.
5. As any member I download evidence; the download is recorded in the chain of custody.
6. As an analyst I re-verify evidence at any time; a mismatch or missing content is flagged and recorded.
7. As an admin I review a filterable audit log of every change in my organization.
8. As any user I can see which modules are planned (PCAP, malware, forensics, memory, RE, TI, AI analyst, reports, integrations) — they show no fake data.

## Non-goals (current scope)

| Item | Status |
|---|---|
| Memory forensics (Volatility 3) | in progress (M8: foundation only; [MEMORY_ANALYSIS.md](MEMORY_ANALYSIS.md)) |
| Disk forensics (TSK, Plaso, Autopsy), reverse engineering (Ghidra, radare2) | Later |
| Dynamic analysis (sandbox execution) | designed and gated, not enabled ([SANDBOX_SECURITY.md](SANDBOX_SECURITY.md)) |
| OpenSearch | deferred; Postgres search until the revisit criteria in ARCHITECTURE are met |
| TCP stream reassembly, file carving, JA4, Mach-O, Detect It Easy | Later |
| Platform API keys / service accounts, MFA, SSO, invitations, email verification | Later |
| Per-case access control (RBAC is org-wide) | Later |
| Online backup (PITR, replication), multi-node / high availability | Later |
| Live verification of AI models and TI providers | procedure exists (`pnpm live:run`); not run (needs keys and budget) |
| Production readiness | not claimed; see the known gaps in THREAT_MODEL.md (for example the unpatched MinIO image until the image decision) |

Delivered since M1 and no longer deferred: Celery workers and the analysis pipeline (M2), ClamAV scanning of uploads ≤ 64 MiB, the nonce CSP and storage quotas (M3), threat intel (M4), the AI analyst (M5), reports and case management (M6), backup / restore and data retention (M7).

## Success criteria (each milestone)

- `pnpm dev` starts the full stack; `pnpm verify` and `pnpm verify:prod` pass (lint, types, API, worker and web tests, build, contract drift, headers, Playwright on dev and the prod-like stack; since M7 the restore drill).
- The milestone's golden path works in a browser (M1: register → case → upload → hashes → verify → download → custody → audit).
- Tenant isolation, RBAC, session and evidence-integrity properties are covered by automated tests (see TESTING.md); metrics are labelled synthetic when they are.
- Nothing is claimed production-ready; known gaps are listed in THREAT_MODEL.md.

## Later milestones

M2–M6 are delivered and M7 is pending its gate (see ROADMAP). M5 adds the AI analyst: evidence-cited explanations of normalized findings that never give verdicts, never use tools and are never acted on automatically. It is opt-in per organization with a privacy acknowledgement (evidence excerpts go to the chosen provider; internal names are pseudonymized by default), provider keys are bring-your-own, and Gemini is limited to paid-tier keys. Details: [AI_ANALYST.md](AI_ANALYST.md).

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

M7 adds platform operations ([ARCHITECTURE.md](ARCHITECTURE.md#platform-operations-m7), [DEPLOYMENT.md](DEPLOYMENT.md#backup-and-restore-m7)). User stories:

1. As an operator I back up the whole platform in a short maintenance window and restore it onto an empty stack, and the restore proves that every evidence hash, report signature, retention lock, legal hold and tenant boundary survived.
2. As an operator I keep the backup as a TLP:RED asset and the secrets separately encrypted, as the backup tells me.
3. As an org admin I set how long TI history, AI runs and the bulk data of closed cases are kept, preview exactly what a run would delete, and know that a shorter policy, turning deletion on or releasing a hold takes effect only after 7 days.
4. As an org admin I place a legal hold on a case or the whole org with a reason; nothing it covers is purged, and case evidence is also locked in the object store.
5. As an analyst I see when evidence bytes were purged by policy, while its hashes, custody and findings stay.
6. As an analyst I see where an IOC, a hash or a JA3 of a job was also seen in my org, and which cases share observables with mine.
7. As an analyst I search cases, evidence, findings, alerts, notes and observables of my org from one box, without my query being logged.
8. As an org admin I see my org's job failure rate, latency and parse success; as an operator I scrape platform-wide metrics with a token.
9. As an auditor I can see who viewed an evidence item's details or custody chain, and which uploads have a name that does not match their content.
