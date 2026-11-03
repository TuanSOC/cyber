---
phase: 8
title: "Frontend investigations evidence audit pages"
status: pending
priority: P1
effort: "10h"
dependencies: [6, 7]
---

# Phase 8: Frontend investigations evidence audit pages

## Overview
Real pages for Investigations (list/detail/edit), Evidence (upload w/ progress, detail, hashes, verify, download, archive, custody chain), Audit log, and Overview counts.

## Requirements
- Functional:
  - Overview: open-investigations total (`GET investigations?status=open&limit=1` → `total`) + recent investigations; recent audit for admin+. No org-wide evidence count in M1. [RT#13]
  - Investigations list: TanStack Table, server pagination, search `q`, filters status/severity, sort; "New investigation" dialog.
  - Investigation detail: header (case no., title, status, severity, created by/at), status control (valid transitions only), Evidence tab.
  - Evidence tab: upload dropzone (queue, uploads one at a time), per-file progress + cancel; paginated list (filename, size, type, SHA256 short + copy, uploaded by/at, status).
  - Evidence detail: all hashes (copy), detected type, Verify → result badge (ok/mismatch/missing), Download, Archive, custody timeline.
  - Audit log (admin+): filters action/actor/date range, pagination, expandable JSON details.
- Non-functional: every list server-paginated with the shared `{items, total}` envelope. [RT#13]

## Architecture
- Upload via `XMLHttpRequest` (upload progress): `POST /api/v1/orgs/{org}/investigations/{inv}/evidence?filename=…`, body = `File`, `Content-Type: application/octet-stream`, `X-CSRF-Token`. `xhr.abort()` cancels (server cleans temp + slot). [RT#12]
- No `/config/public` endpoint: server rejects oversize immediately via Content-Length (Caddy/API 413) → UI shows "File exceeds limit". [RT#13]
- Error states: 413 too large, 429 too many concurrent uploads (wait + retry), 403, 409 archived case.
- 401 mid-upload → refresh then prompt user to retry (never auto-resend multi-GB).
- Download: plain `<a href="/api/v1/.../download">` (same-origin cookie, GET → no CSRF).
- Shared `DataTable` (TanStack Table + shadcn Table) for investigations / evidence / audit / members, one pagination contract.
- Formatting utils: bytes, timestamps (UTC + local tooltip), hash truncation.

## Related Code Files
- Create: `apps/web/app/(app)/o/[orgId]/investigations/{page.tsx,[invId]/page.tsx}`
- Create: `apps/web/app/(app)/o/[orgId]/evidence/[evidenceId]/page.tsx`
- Create: `apps/web/app/(app)/o/[orgId]/settings/audit/page.tsx`
- Create: `apps/web/components/{data-table.tsx,evidence-uploader.tsx,hash-display.tsx,custody-timeline.tsx,status-select.tsx}`
- Create: `apps/web/lib/{upload.ts,format.ts}`
- Modify: `apps/web/app/(app)/o/[orgId]/page.tsx` (overview counts), `apps/web/lib/nav.ts`, `packages/contracts/*` (regen)

## Implementation Steps
1. Generic `DataTable` with server pagination props.
2. Investigations list + create dialog + detail + status control.
3. Uploader (queue, progress, cancel, error states).
4. Evidence list + detail + verify/download/archive + custody timeline.
5. Audit page (hidden for analyst/viewer; backend 403 anyway).
6. Overview counts.
7. `tsc`, `eslint`, `next build`.

## Success Criteria
- [ ] Manual: create case → upload 2 files (one >100 MB) w/ progress → SHA256 matches `certutil -hashfile <file> SHA256` → verify ok → download identical → custody shows uploaded/verified_ok/downloaded.
- [ ] Cancel mid-upload → no evidence row, UI recovers.
- [ ] Viewer: no upload/verify/archive controls; audit not in nav.
- [ ] Typecheck/lint/build green.

## Risk Assessment
- Large uploads go Caddy → api directly (not through Next) → no Next body limits.

## Security Considerations
- Filenames/descriptions rendered as text, truncated with tooltip.
- Backend authoritative for every action.
