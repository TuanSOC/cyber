---
phase: 5
title: "Investigations"
status: pending
priority: P1
effort: "4h"
dependencies: [4]
---

# Phase 5: Investigations

## Overview
Case management CRUD (no delete) with status lifecycle, per-org case numbers, search/filter/pagination.

## Requirements
- Functional:
  - `GET /orgs/{org_id}/investigations?q=&status=&severity=&sort=created_at|-created_at|severity&limit=&offset=` → `{items, total}`.
  - `POST /orgs/{org_id}/investigations` {title, description?, severity}.
  - `GET /orgs/{org_id}/investigations/{id}` → incl. evidence count, created_by display name.
  - `PATCH /orgs/{org_id}/investigations/{id}` {title?, description?, severity?, status?}.
- Non-functional: case number `CASE-{n:05d}` unique per org; validated status transitions; writes audited; commit before respond.

## Architecture
- Case number: in create txn `UPDATE organizations SET next_case_number = next_case_number + 1 WHERE id=:org RETURNING next_case_number - 1` (row lock serializes concurrent creates).
- Transitions: `open → in_progress → closed → archived`; `closed → in_progress` (reopen); `archived` terminal in M1. Invalid → 409.
- `q`: `title ILIKE '%' || :q || '%' ESCAPE '\'` with `%`, `_`, `\` escaped. No trigram index in M1. [RT#13]
- Pagination: offset, `limit` default 25, max 100 (same envelope as all lists). [RT#13]
- Notes, timeline, IOC collections, ATT&CK mapping → later milestones (ROADMAP).

## Related Code Files
- Create: `apps/api/app/modules/investigations/{schemas,repository,service,router}.py`
- Create: `apps/api/tests/integration/test_investigations.py`

## Implementation Steps
1. Schemas: `InvestigationCreate/Update/Out`; list returns `Page[InvestigationOut]` (from `core/pagination.py`, phase 4).
2. Repository w/ filters (always also `WHERE organization_id = :org` — defense in depth with RLS).
3. Service: create (case number), update (transition validation, audit diff of changed fields), explicit commit.
4. Router with `require("investigation.read|write")`.
5. Tests: create/list/filter/search/paginate; 10 concurrent creates → distinct case numbers; invalid transition 409; viewer PATCH 403; other-org id → 404; LIKE wildcards escaped.

## Success Criteria
- [ ] Tests green incl. concurrency.
- [ ] OpenAPI shows typed models incl. `Page[...]`.

## Risk Assessment
- Offset pagination slow at huge volumes → acceptable for M1; revisit with OpenSearch in M2.

## Security Considerations
- Lookup by id within tenant session → cross-org UUID guess returns 404.
