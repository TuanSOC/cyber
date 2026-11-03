---
phase: 7
title: "Frontend shell and auth pages"
status: pending
priority: P1
effort: "9h"
dependencies: [4]
---

# Phase 7: Frontend shell and auth pages

## Overview
Dark dashboard shell (12-item sidebar, org switcher, user menu), typed API client from OpenAPI, client-side auth guard, auth pages, org/member settings, gateway security headers.

## Requirements
- Functional:
  - `/login`, `/register`.
  - `/o/[orgId]/...` app area (UUID only, no slugs) [RT#13] with sidebar: Overview, Investigations, PCAP Analyzer, Malware Lab, Forensics, Memory Analysis, Reverse Engineering, Threat Intelligence, AI Analyst, Reports, Integrations, Settings.
  - Unbuilt modules → `PlannedModule` page ("Planned — Milestone N", short description). Zero fake data.
  - Overview (this phase): welcome + quick links only; counts added in phase 8. [RT#13]
  - Settings → Organization (name), Members (list/add/change role/remove per RBAC).
  - `/` → last-used org (localStorage, try/catch) else the org the user created (earliest membership); org name shown prominently in header. [RT#15]
- Non-functional: no tokens in JS (only `cl_csrf`); same-origin `/api/v1`; auto refresh on 401.

## Architecture
- **Contracts (offline, no running stack)** [RT#14]: `pnpm gen:contracts` = `docker compose --profile test run --rm api-test uv run python -m app.scripts.dump_openapi > packages/contracts/openapi.json` then `openapi-typescript packages/contracts/openapi.json -o packages/contracts/src/schema.d.ts`. Both files committed.
- `apps/web/lib/api.ts`: `openapi-fetch`, `credentials: "include"`; middleware adds `X-CSRF-Token` from `cl_csrf` (Path=/) on mutations; on 401 → single-flight `POST /auth/refresh` → retry once; refresh `stale_refresh` → just retry (other tab rotated); refresh failure → redirect `/login?next=…`. [RT#1, RT#7]
- **Client-side guard** [RT#1]: `app/(app)/layout.tsx` is a client component using `useMe()` (React Query). Loading → skeleton; unauthenticated after refresh attempt → `router.replace('/login')`. No server-side cookie check (auth cookie is Path=/api by design). Backend remains the real enforcement.
- Role from `me.memberships` drives UI (hide/disable); backend enforces.
- UI kit: shadcn (Button, Input, Form, Table, Dialog, DropdownMenu, Badge, Sonner, Sheet). Forms: react-hook-form + zod.
- Theme: dark only; severity tokens `--sev-low/medium/high/critical` + `SeverityBadge`.
- **Gateway security headers (moved here from phase 9)** [RT#10] in Caddyfile:
  - CSP: `default-src 'self'; script-src 'self' 'unsafe-inline' {dev: 'unsafe-eval'}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' {dev: ws:}; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.
  - `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, minimal `Permissions-Policy`.
  - Nonce-based strict CSP → M2 hardening (ROADMAP).

## Related Code Files
- Create: `apps/api/app/scripts/dump_openapi.py`
- Create: `packages/contracts/{openapi.json,src/schema.d.ts,src/index.ts}`
- Create: `apps/web/lib/{api.ts,csrf.ts,query-client.tsx,nav.ts,roles.ts,use-me.ts,last-org.ts}`
- Create: `apps/web/app/(auth)/{login,register}/page.tsx`
- Create: `apps/web/app/(app)/layout.tsx`, `apps/web/app/(app)/o/[orgId]/{layout.tsx,page.tsx}`, `.../settings/{page.tsx,members/page.tsx}`, `.../[module]/page.tsx` (planned modules via `nav.ts`)
- Create: `apps/web/components/{app-sidebar.tsx,org-switcher.tsx,user-menu.tsx,planned-module.tsx,severity-badge.tsx}`, `components/ui/*`
- Modify: `infra/caddy/Caddyfile` (headers), root `package.json` (`gen:contracts`)

## Implementation Steps
1. `dump_openapi` script + `gen:contracts`; typed client with CSRF + refresh middleware.
2. Auth pages (zod mirrors backend rules); generic errors; 429 message with retry time.
3. Client guard layout + sidebar from `nav.ts` (`{key,label,icon,milestone,href}`).
4. Org switcher + `/` redirect logic + prominent org name.
5. Settings: org name (admin+), members table + add/role/remove dialogs; disabled per role.
6. Caddy headers; check pages hydrate with CSP in both dev and prod (`pnpm prod:up`).
7. `tsc --noEmit`, `eslint`, `next build`.

- Client contract notes from phase 3 review: read `cl_csrf` from `document.cookie` at request time (rotates on every refresh); on `stale_refresh` retry once after ~300 ms then give up (never loop); treat 403 `csrf_failed` on logout as already logged out; all errors share `{"error":{"code","message"}}` incl. 404/405/429/503.

## Success Criteria
- [ ] Register → lands in new org overview; reload keeps session; after 15 min access expiry, next action auto-refreshes; logout → `/login`.
- [ ] Two tabs open, access expired, both act → neither tab logged out.
- [ ] Viewer sees no member-management actions.
- [ ] All 12 nav items render; planned ones show milestone label, no fake numbers.
- [ ] No CSP violations in console (dev + prod); headers present via `curl -I`.
- [ ] Typecheck/lint/build green.

## Risk Assessment
- Client guard flashes skeleton before redirect → acceptable.
- Contracts drift → `verify` regenerates + `git diff --exit-code` (phase 9).

## Security Considerations
- No `dangerouslySetInnerHTML`; evidence-derived strings rendered as text.
- `'unsafe-inline'` scripts weaken CSP vs XSS → mitigated by React escaping + httpOnly auth cookies; strict nonce CSP planned (THREAT_MODEL).
