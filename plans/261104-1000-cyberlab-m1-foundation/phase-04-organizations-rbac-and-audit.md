---
phase: 4
title: "Organizations RBAC and audit"
status: pending
priority: P1
effort: "6h"
dependencies: [3]
---

# Phase 4: Organizations RBAC and audit

## Overview
Org endpoints, membership management, the `require()` permission dependency (single tenant session per request), and the audit read endpoint.

## Requirements
- Functional:
  - `GET /orgs` (my orgs), `POST /orgs` (creator = owner), `GET|PATCH /orgs/{org_id}`.
  - Org delete + ownership transfer: NOT in M1 (owner can promote another member to owner via PATCH role).
  - `GET /orgs/{org_id}/members`, `POST /orgs/{org_id}/members` (email of existing user + role), `PATCH /orgs/{org_id}/members/{member_id}` (role), `DELETE /orgs/{org_id}/members/{member_id}`.
  - `GET /orgs/{org_id}/audit-logs?action=&actor_id=&from=&to=&limit=&offset=` → `{items, total}`. [RT#13]
- Non-functional: every mutation audited in same transaction; commit before responding.

## Architecture

### Permission matrix (`core/rbac.py`)
| Permission | owner | admin | analyst | viewer |
|---|---|---|---|---|
| org.read | ✓ | ✓ | ✓ | ✓ |
| org.update | ✓ | ✓ | | |
| members.read | ✓ | ✓ | ✓ | ✓ |
| members.manage | ✓ | ✓ (not owners) | | |
| investigation.read | ✓ | ✓ | ✓ | ✓ |
| investigation.write | ✓ | ✓ | ✓ | |
| evidence.read (incl. download, custody) | ✓ | ✓ | ✓ | ✓ |
| evidence.write (upload, verify, archive) | ✓ | ✓ | ✓ | |
| audit.read | ✓ | ✓ | | |

### `require()` — one tenant session, membership checked inside it [RT#2]
```python
def require(perm: Permission):
    async def dep(org_id: UUID, user = Depends(current_user)) -> AsyncIterator[OrgContext]:
        async with tenant_session(org_id, user.id) as s:
            m = await members_repo.get(s, org_id, user.id)   # RLS allows: org = app.org_id
            if m is None: raise NotFound()                   # non-member: don't leak org existence
            if perm not in ROLE_PERMS[m.role]: raise Forbidden()
            yield OrgContext(org_id=org_id, user=user, role=m.role, session=s)
    return dep
```
- Handlers use `ctx.session`; mutations call `await ctx.session.commit()` explicitly before returning (commit rule, phase 2). Read-only handlers need no commit.
- Long-running evidence routes (phase 6) use `authorize(org_id, user, perm)` — same check in a short session that closes immediately — instead of `require()`.

### Membership rules
- Org must keep ≥1 owner; admin cannot promote to/demote/remove owners; user cannot change own role.
- Owner-count check race-free: `SELECT id FROM organizations WHERE id = :org FOR UPDATE` before counting owners in PATCH/DELETE member. [RT#15]
- Adding by email needs no acceptance in M1 (known gap, THREAT_MODEL; mitigated in UI by prominent org name + deterministic default org, phase 7). [RT#15]

### Audit read
- Repository list with filters, offset pagination `{items, total}`, ordered `occurred_at desc, id desc`. `limit` ≤ 100.

## Related Code Files
- Create: `apps/api/app/core/rbac.py`, `apps/api/app/core/pagination.py` (generic `Page[T] = {items, total}`, `limit` ≤ 100, reused by all lists) [RT#13]
- Create: `apps/api/app/modules/organizations/{schemas,repository,service,router}.py`
- Create: `apps/api/app/modules/audit/{schemas,router}.py`; Modify: `apps/api/app/modules/audit/repository.py` (list)
- Create: `apps/api/tests/integration/{test_orgs_members.py,test_rbac.py,test_audit.py}`

## Implementation Steps
1. RBAC table + `require()` + `authorize()` helper.
2. Org service/router (`GET /orgs` via `tenant_session(None, user.id)`).
3. Member service with owner rules + `FOR UPDATE`.
4. Audit list repository + router.
5. Audit calls on org/member mutations.
6. Tests:
   - owner GET own org route → 200 (regression for RT#2).
   - non-member of org B → every `/orgs/B/...` 404.
   - viewer POST member 403; admin remove owner 403; last-owner demotion 409.
   - concurrent demotion of two owners (`asyncio.gather`) → exactly one succeeds, org keeps ≥1 owner.
   - parametrized RBAC matrix × representative endpoints.
   - audit rows after each mutation, visible only in own org; pagination + filters.

## Success Criteria
- [ ] Matrix test covers every (role, permission) pair.
- [ ] Concurrency test for owner rule passes.
- [ ] Lint/type/test green.

## Risk Assessment
- Handlers forgetting `commit()` → tests assert persisted state via a separate session.

## Security Considerations
- 404-vs-403 centralized in `require()`/`authorize()`.
- Audit immutable + same-txn write → successful action ⇒ audit row.
