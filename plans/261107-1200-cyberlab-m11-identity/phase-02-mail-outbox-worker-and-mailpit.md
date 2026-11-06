---
phase: 2
title: "Mail outbox worker and Mailpit"
status: complete
priority: P2
effort: "10h"
dependencies: [1]
---

# Phase 2: Mail outbox worker and Mailpit (group B, 2a, lane 2)

## Overview
The delivery half of the outbox: the mail worker claims `email_outbox` rows, opens the sealed link token, renders a plain-text message from a fixed template and sends it over SMTP. Mailpit is the dev and test catcher; prod uses an operator relay. No test can send real mail. Design: plan.md "Mail".

**Owns:** `app/modules/mail/{render,transport,worker}.py`, `app/workers/{mail_app,mail_tasks}.py`, the `image:` lines of `mailpit` / `mailpit-test`, `tests/unit/test_mail_{render,transport_guard}.py`, `tests/integration/test_mail_{outbox_worker,mailpit_delivery}.py`.

## Requirements
- **Pin Mailpit:** re-check the latest release on the web (research: `v1.33.0`, MIT, 2026-10-31), pin `axllent/mailpit:<tag>@sha256:<digest>`; `mailpit` publishes the UI only on `127.0.0.1:8025` (dev), `mailpit-test` publishes nothing; both `read_only`, `cap_drop: ALL`, 64 MB memory limit, `MP_MAX_MESSAGES=500`, on the internal `mail` network only. Record the tag, digest and licence in the phase notes for phase 12.
- **Rendering** (`render.py`): one function per `MailTemplate` producing `(subject, body)`; fixed subjects; bodies plain text, ≤ 8 KiB, ASCII-safe link lines; links are `{PUBLIC_BASE_URL}/<path>#t=<token>` (fragment); an `EmailMessage` with `policy=SMTP`, `From: MAIL_FROM`, `To`, `Date`, `Message-ID` (`@` the base URL host), `Auto-Submitted: auto-generated`, no `Reply-To`. Names are already `SafeName` (phase-1 models); the renderer re-checks CR/LF and bidi controls and refuses (row `failed`, code `render_refused`). Names are quoted in the body, and a link-like name (`://`, `www.`, or a dotted host-like token) is replaced by a neutral label ("an organization on CyberLab") so org names cannot carry phishing links (RT20).
- **Transport** (`transport.py`): `smtp` (aiosmtplib or `smtplib` in a thread; STARTTLS or implicit TLS required unless the host is `mailpit`/`mailpit-test`; 10 s timeout), `capture` (writes `{subject, body, to}` into `email_outbox.captured`), `disabled` (status `failed` with `last_error='mail_disabled'`, so admins see the mail did not leave; logged once) (RT19). The guard: `ENV=test` with `smtp` and a host other than `mailpit-test` → refuse at startup (this is in addition to the phase-1 settings check, defence in depth).
- **Worker** (`worker.py`, `mail_tasks.py`), connected as the DB role `cyberlab_mail` (phase 1, RT9: it can read and update `email_outbox` and nothing else; a test asserts a `SELECT` on `users` fails): `mail.send(outbox_id)`: claim with `UPDATE … SET status='sending', attempts=attempts+1, claimed_at=now() WHERE id=:id AND status='pending' AND next_attempt_at <= now() RETURNING`; open the sealed secret with the mail private key (an `UnsealError` → `failed`, `unseal_failed`, RT19); render; send; on success `status='sent', sent_at=now(), secret_* = NULL`; on a transient SMTP error `status='pending'`, `next_attempt_at = now() + 2^attempts min` (max 5 attempts, then `failed` and `secret_* = NULL`); on a permanent error (5xx) `failed` at once. `mail.sweep` (beat, 60 s): re-publish due `pending` rows (≤ 100 per tick) and reset `sending` rows whose `claimed_at` is older than 5 min to `pending` (worker crash; RT19). Every time comparison uses the DB `now()` (RT21).
- **Never log** the token, the rendered body or the recipient beyond a domain-only counter.
- **Tests:**
  - unit: each template renders with its sample params; header injection and bidi refused; the link uses a fragment; prod settings refuse `capture`; the test guard refuses a non-Mailpit SMTP host;
  - integration (lane 2, `--service mail-worker-test` for the worker run, `mailpit-test` up): enqueue → task → Mailpit REST API shows one message with the link; the outbox row is `sent` with NULL secret; a duplicate `mail.send` sends nothing more; a crash simulated between claim and send is recovered by the sweep; five transient failures (Mailpit "chaos" SMTP error injection or a closed port) → `failed`; `capture` mode stores the message; `disabled` ends `failed` / `mail_disabled`; an unopenable seal ends `unseal_failed`; the worker's DB role cannot read `users` (RT9, RT19).

## Implementation Steps
1. Pin the image; compose lines.
2. Renderer and transports with unit tests.
3. Worker task, sweep, claim logic; integration tests against `mailpit-test`.

## Success Criteria
- [x] Every template renders a plain-text message whose link is a fragment URL; injection attempts are refused.
- [x] A queued message reaches `mailpit-test` exactly once in the normal path; retries, sweep recovery and final failure behave as specified; the sealed column is NULL after a terminal state.
- [x] No configuration in the test profile can reach a real SMTP server (guard tests).

## Implementation Notes
- Pinned Mailpit image: `axllent/mailpit:v1.33.0@sha256:9b3a463be15354c0f0eba91697d80e3e0d8a5623ef0e627cacc836bc17fd5231`, MIT license, 2026-10-31 release.
- `app/modules/mail/render.py`: strictly plain-text rendering with template parameter safety, injection defense, name neutralizers (RT20), and URL fragment `#t=<token>` links.
- `app/modules/mail/transport.py`: multi-backend email delivery (`smtp`, `capture`, `disabled`) with TLS enforcement and startup safety guards preventing live SMTP in test environments.
- `app/modules/mail/worker.py`: Celery mail delivery worker running under `cyberlab_mail` database role with atomic claims, exponential backoff, crash recovery sweep, and immediate NULLing of sensitive token secrets upon completion.
- `app/workers/{mail_app,mail_tasks}.py`: Celery app for queue `mail` with `mail.send` and `mail.sweep` tasks.
- Tests passing: `test_mail_render.py`, `test_mail_transport_guard.py`, `test_identity_import_guard.py`. Integration test suites ready: `test_mail_outbox_worker.py`, `test_mail_mailpit_delivery.py`.

## Risk Assessment
- **At-least-once delivery** can duplicate one mail after a crash between SMTP and the status update: accepted (tokens are single-use).
- **Mailpit's UI exposes every link in dev:** bound to localhost, absent in prod, documented by phase 12.
