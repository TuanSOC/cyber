# SPEC: Milestone 11 - Phase 2: Mail Outbox Worker & Mailpit Delivery

## 1. Context & Objectives

In **Milestone 11 (Identity & Access)**, Phase 1 established the database schema (`email_outbox`, migration `0019_m11_identity`), templates specification (`MailTemplate`), sealing mechanism for link tokens (`cyberlab.mail.v1`), and outbox enqueue functions.

**Phase 2 Objective:** Implement the outbox delivery worker and Mailpit integration:
1. **Renderer (`render.py`):** Deterministic, strictly plain-text rendering with template parameter safety, injection defense, name neutralizers, and URL fragment `#t=<token>` links.
2. **Transport (`transport.py`):** Multi-backend email delivery (`smtp`, `capture`, `disabled`) with TLS enforcement and startup safety guards preventing live SMTP in test environments.
3. **Worker (`worker.py`, `mail_tasks.py`, `mail_app.py`):** Celery mail delivery worker running under the least-privileged `cyberlab_mail` database role with atomic claims, exponential backoff, crash recovery sweep, and immediate NULLing of sensitive token secrets upon completion.
4. **Service Pinning & Network Isolation:** Pin Mailpit container images (`axllent/mailpit:v1.33.0`) with immutable digests, non-root, read-only rootfs, and confined to the internal `mail` network.
5. **Comprehensive Testing:** Unit and integration test suites proving anti-injection, error recovery, unseal handling, and role isolation.

---

## 2. Architecture & Security Invariants

### 2.1 Least-Privilege Role Separation
* The mail worker runs as dedicated PostgreSQL user `cyberlab_mail`.
* `cyberlab_mail` can SELECT/UPDATE `email_outbox` only; attempts to query `users`, `organizations`, or any other table must fail with `permission denied`.
* The mail worker environment (`x-mail-env`) has `PROCESS_ROLE=mail`. `Settings` enforces this role, refuses JWT secrets, MinIO credentials, and any unsealing keys other than `MAIL_SEAL_PRIVATE_KEYS_FILE`.

### 2.2 Template & Phishing Defenses
* **Plain text only:** No HTML, no multipart/alternative, no remote assets, no tracking pixels.
* **URL fragment links:** Secrets are passed strictly in the fragment (`#t=<token>`), preventing them from leaking via HTTP referrers, proxies, or server request logs.
* **Header injection prevention:** Subject and recipient headers strictly checked for `\r` and `\n`.
* **Phishing mitigation (RT20):** Any organization name or user name containing URL/domain indicators (`://`, `www.`, or dotted host tokens) is sanitized to a neutral label ("an organization on CyberLab").

### 2.3 Secret Lifecycle & Atomic Sweeps
* The worker atomically claims due rows:
  ```sql
  UPDATE email_outbox
  SET status='sending', attempts=attempts+1, claimed_at=now()
  WHERE id=:id AND status='pending' AND next_attempt_at <= now()
  RETURNING ...
  ```
* Once sent, `status='sent'`, `sent_at=now()`, and `secret_epk`, `secret_nonce`, `secret_ct`, `secret_kid` are immediately set to `NULL`.
* On transient errors: `status='pending'`, exponential backoff: `next_attempt_at = now() + (2 ^ attempts) * interval '1 minute'` (up to 5 attempts, then `failed`).
* Sweep job (`mail.sweep` every 60s): Recovers stalled `sending` rows older than 5 minutes back to `pending`.

---

## 3. Component Breakdown & Implementation Plan

### 3.1 Template Renderer (`apps/api/app/modules/mail/render.py`)
* Functions mapping each `MailTemplate` to `(subject, body: str)`.
* Enforce size cap (`<= 8 KiB`).
* Validate headers with Python `email.message.EmailMessage(policy=email.policy.SMTP)`.
* Sanitize names and format date/time and parameters cleanly.

### 3.2 Transports (`apps/api/app/modules/mail/transport.py`)
* Base transport interface `MailTransport`.
* `SmtpTransport`:
  - `aiosmtplib` / `smtplib` connection with 10s timeout.
  - Require STARTTLS or implicit TLS for non-local addresses.
  - Safety guard: Raise error if `ENV=test` and `SMTP_HOST != 'mailpit-test'`.
* `CaptureTransport`: Writes payload `{subject, body, to}` into `email_outbox.captured` (used in unit/integration tests).
* `DisabledTransport`: Marks status as `failed` with `last_error='mail_disabled'`.

### 3.3 Worker & Delivery Loop (`apps/api/app/modules/mail/worker.py`)
* `claim_outbox_item(session, outbox_id)` -> `EmailOutbox | None`
* `process_outbox_item(outbox_id)`:
  - Load private keys via `app.modules.mail.unseal`.
  - Open sealed link token (if template requires one).
  - Render message.
  - Send via active transport.
  - Update status and clear secrets in one transaction.
* `sweep_stalled_outbox(session)`: Recover zombie rows and re-publish due pending rows.

### 3.4 Celery App & Tasks (`apps/api/app/workers/mail_app.py`, `mail_tasks.py`)
* Dedicated Celery application configured with broker ACL user `mail` and queue `mail`.
* Tasks:
  - `mail.send`: Dispatches single delivery.
  - `mail.sweep`: Beat schedule task every 60 seconds.

### 3.5 Compose & Infra Integration
* Check and pin `axllent/mailpit:v1.33.0` with sha256 digest in `docker-compose.yml`.
* Ensure mail worker service `mail-worker` and test service `mail-worker-test` are configured with `PROCESS_ROLE=mail`, `cyberlab_mail` DB credentials, and `mail` network.

---

## 4. Files to Create & Modify

| File | Action | Description |
|---|:---:|---|
| `apps/api/app/modules/mail/render.py` | Create | Template renderers, anti-injection checks, URL fragment generator |
| `apps/api/app/modules/mail/transport.py` | Create | SMTP, capture, and disabled transports with test guards |
| `apps/api/app/modules/mail/worker.py` | Create | Outbox claim, unseal, deliver, status updates, retry math, sweep |
| `apps/api/app/workers/mail_app.py` | Create | Celery worker app instance for mail processing |
| `apps/api/app/workers/mail_tasks.py` | Create | Celery task bindings (`mail.send`, `mail.sweep`) |
| `docker-compose.yml` | Modify | Pin mailpit images with sha256 digest |
| `apps/api/tests/unit/test_mail_render.py` | Create | Unit tests for rendering, length caps, bidi/header injection, name neutralization |
| `apps/api/tests/unit/test_mail_transport_guard.py` | Create | Tests for SMTP test-profile guard and capture behavior |
| `apps/api/tests/integration/test_mail_outbox_worker.py` | Create | Integration tests for worker claims, unseal failures, retries, sweeps |
| `apps/api/tests/integration/test_mail_mailpit_delivery.py` | Create | End-to-end integration tests delivering to Mailpit REST API |

---

## 5. Verification Steps

1. **Unit Tests:**
   - Execute `pytest tests/unit/test_mail_render.py`
   - Execute `pytest tests/unit/test_mail_transport_guard.py`
2. **Integration Tests:**
   - Execute `pytest tests/integration/test_mail_outbox_worker.py`
   - Execute `pytest tests/integration/test_mail_mailpit_delivery.py`
3. **Role Isolation Check:**
   - Verify that the mail worker connecting as `cyberlab_mail` cannot select from `users`.
4. **Linting & Types:**
   - Run `ruff check app/modules/mail app/workers/mail_* tests/*mail*`
   - Run `mypy app/modules/mail app/workers/mail_*`

