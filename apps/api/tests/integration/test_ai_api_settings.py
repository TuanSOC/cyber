"""AI settings routes (M5 phase 7): off by default, opt-in with privacy acknowledgement,
re-acknowledgement when the disclosure widens (RT22), CIDR / suffix lists, budgets within
the ceilings (RT9), audit without values, and the usage route."""

import uuid
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import (
    API,
    AiSent,
    capture_ai_sends,
    enable_ai,
    put_settings,
    request_run,
    set_usage,
    tenant_of,
    use_fake_builder,
)
from tests.ai_helpers import seed_job
from tests.factories import add_member, login, make_user, register, unique_email


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> AiSent:
    use_fake_builder(monkeypatch)
    return capture_ai_sends(monkeypatch)


async def _audit(org_id: uuid.UUID, prefix: str = "ai.") -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.action.startswith(prefix))
            .order_by(AuditLog.occurred_at, AuditLog.id)
        )
        return list(rows)


async def test_defaults_are_off_and_readable_by_viewers(sent: AiSent) -> None:
    owner = await register()
    viewer_email = unique_email("viewer")
    await add_member(owner.org_id, await make_user(viewer_email), MemberRole.VIEWER)
    viewer = await login(viewer_email)
    response = await viewer.get(f"{API}/{owner.org_id}/ai/settings")
    assert response.status_code == 200
    body = response.json()
    assert body["ai_enabled"] is False and body["platform_ai_enabled"] is True
    assert body["privacy_ack_at"] is None and body["updated_at"] is None
    assert body["pseudonymize_internal"] is True and body["include_ti"] is True
    assert body["include_strings"] is False and body["include_case_text"] is False
    assert body["internal_cidrs"] == [] and body["internal_suffixes"] == []
    assert (body["daily_token_budget"], body["run_token_cap"], body["incident_token_cap"]) == (
        1_000_000,
        100_000,
        600_000,
    )
    assert body["ceilings"] == {
        "daily_token_budget": 20_000_000,
        "run_token_cap": 200_000,
        "incident_token_cap": 2_000_000,
    }
    assert "pseudonym" in body["privacy_notice"] and "refusal_fallback" not in body
    denied = await put_settings(viewer, owner.org_id, include_ti=False)
    assert denied.status_code == 403


async def test_turning_ai_on_requires_the_privacy_acknowledgement(sent: AiSent) -> None:
    owner = await register()
    refused = await put_settings(owner.client, owner.org_id, ai_enabled=True)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "privacy_not_acknowledged"
    assert (await owner.client.get(f"{API}/{owner.org_id}/ai/settings")).json()[
        "ai_enabled"
    ] is False
    on = await put_settings(owner.client, owner.org_id, ai_enabled=True, acknowledge_privacy=True)
    assert on.status_code == 200, on.text
    body = on.json()
    assert body["ai_enabled"] is True and body["privacy_ack_by"] == str(owner.user_id)
    assert body["privacy_ack_at"] is not None and body["updated_at"] is not None
    actions = sorted(a.action for a in await _audit(owner.org_id))
    assert actions == ["ai.enabled", "ai.settings_updated"]

    off = await put_settings(owner.client, owner.org_id, ai_enabled=False)
    assert off.status_code == 200 and off.json()["ai_enabled"] is False
    assert [a.action for a in await _audit(owner.org_id, "ai.disabled")] == ["ai.disabled"]


@pytest.mark.parametrize(
    "widening",
    [{"include_strings": True}, {"include_case_text": True}, {"pseudonymize_internal": False}],
)
async def test_widening_the_disclosure_needs_a_new_acknowledgement(
    sent: AiSent, widening: dict[str, bool]
) -> None:
    owner = await register()
    first = await put_settings(
        owner.client, owner.org_id, ai_enabled=True, acknowledge_privacy=True
    )
    first_ack = first.json()["privacy_ack_at"]
    refused = await put_settings(owner.client, owner.org_id, **widening)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "privacy_not_acknowledged"
    accepted = await put_settings(owner.client, owner.org_id, acknowledge_privacy=True, **widening)
    assert accepted.status_code == 200
    [(name, value)] = widening.items()
    assert accepted.json()[name] is value
    later = datetime.fromisoformat(accepted.json()["privacy_ack_at"])
    assert later > datetime.fromisoformat(first_ack)
    # Narrowing back never needs one.
    narrowed = await put_settings(owner.client, owner.org_id, **{name: not value})
    assert narrowed.status_code == 200 and narrowed.json()[name] is (not value)


async def test_cidr_and_suffix_lists(sent: AiSent) -> None:
    owner = await register()
    saved = await put_settings(
        owner.client,
        owner.org_id,
        internal_cidrs=["10.20.0.0/16", " 192.168.7.9/24 ", "10.20.0.0/16", "fd00:abcd::/32"],
        internal_suffixes=["Corp.Acme-Corp.NET", ".internal.acme.com", "corp.acme-corp.net"],
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["internal_cidrs"] == ["10.20.0.0/16", "192.168.7.0/24", "fd00:abcd::/32"]
    assert body["internal_suffixes"] == ["corp.acme-corp.net", "internal.acme.com"]
    for bad in (
        {"internal_cidrs": ["10.0.0.0/33"]},
        {"internal_cidrs": ["not-a-cidr"]},
        {"internal_cidrs": [f"10.{i}.0.0/16" for i in range(51)]},
        {"internal_suffixes": ["not a suffix!"]},
        {"internal_suffixes": [f"s{i}.acme.com" for i in range(51)]},
    ):
        refused = await put_settings(owner.client, owner.org_id, **bad)
        assert refused.status_code == 422, bad
        assert "acme" not in refused.text and "not-a-cidr" not in refused.text
    [entry] = await _audit(owner.org_id, "ai.settings_updated")
    assert entry.details["changed"] == ["internal_cidrs", "internal_suffixes"]
    assert entry.details["internal_cidrs_count"] == 3
    assert entry.details["internal_suffixes_count"] == 2
    assert "10.20" not in str(entry.details) and "acme" not in str(entry.details)


async def test_budgets_stay_within_the_ceilings(sent: AiSent) -> None:
    owner = await register()
    ok = await put_settings(
        owner.client,
        owner.org_id,
        daily_token_budget=20_000_000,
        run_token_cap=50_000,
        incident_token_cap=300_000,
    )
    assert ok.status_code == 200
    assert (ok.json()["daily_token_budget"], ok.json()["run_token_cap"]) == (20_000_000, 50_000)
    for field, value in (
        ("daily_token_budget", 20_000_001),
        ("run_token_cap", 200_001),
        ("incident_token_cap", 2_000_001),
    ):
        above = await put_settings(owner.client, owner.org_id, **{field: value})
        assert above.status_code == 422
        assert above.json()["error"]["code"] == "budget_above_ceiling"
    zero = await put_settings(owner.client, owner.org_id, run_token_cap=0)
    assert zero.status_code == 422 and zero.json()["error"]["code"] == "validation_error"
    unknown = await put_settings(owner.client, owner.org_id, refusal_fallback=True)
    assert unknown.status_code == 422  # no such setting (RT10)


async def test_default_provider_is_set_and_cleared(sent: AiSent) -> None:
    owner = await register()
    url = f"{API}/{owner.org_id}/ai/settings"
    chosen = await put_settings(owner.client, owner.org_id, default_provider="anthropic")
    assert chosen.json()["default_provider"] == "anthropic"
    kept = await put_settings(owner.client, owner.org_id, include_ti=False)
    assert kept.json()["default_provider"] == "anthropic"
    cleared = await put_settings(owner.client, owner.org_id, default_provider=None)
    assert cleared.json()["default_provider"] is None
    assert (await owner.client.get(url)).json()["include_ti"] is False
    bad = await put_settings(owner.client, owner.org_id, default_provider="openai")
    assert bad.status_code == 422


async def test_analysts_cannot_change_settings(sent: AiSent) -> None:
    owner = await register()
    email = unique_email("analyst")
    await add_member(owner.org_id, await make_user(email), MemberRole.ANALYST)
    analyst = await login(email)
    denied = await put_settings(analyst, owner.org_id, ai_enabled=True, acknowledge_privacy=True)
    assert denied.status_code == 403


async def test_usage_sums_today_per_provider(sent: AiSent) -> None:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    empty = (await owner.client.get(f"{API}/{owner.org_id}/ai/usage")).json()
    assert empty["providers"] == [] and empty["total_tokens"] == 0
    assert empty["remaining_tokens"] == empty["daily_token_budget"] == 1_000_000
    tenant = await tenant_of(owner)
    job_a = await seed_job(tenant)
    job_b = await seed_job(tenant)
    first = await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_a))
    second = await request_run(
        owner.client, owner.org_id, task="ioc_correlation", job_id=str(job_b)
    )
    await set_usage(owner.org_id, first.json()["run"]["id"], 1200)
    await set_usage(owner.org_id, second.json()["run"]["id"], 300)
    usage = (await owner.client.get(f"{API}/{owner.org_id}/ai/usage")).json()
    [mock] = usage["providers"]
    assert mock["provider"] == "mock" and mock["runs"] == 2
    assert mock["usage"]["input_tokens"] == 1500 and mock["usage"]["total_tokens"] == 1500
    assert mock["cost_micros"] == 1500
    assert usage["total_tokens"] == 1500 and usage["remaining_tokens"] == 1_000_000 - 1500


@pytest.mark.parametrize(
    ("start", "widening"),
    [
        ({"include_ti": False}, {"include_ti": True}),
        (
            {"internal_cidrs": ["10.20.0.0/16", "10.30.0.0/16"]},
            {"internal_cidrs": ["10.30.0.0/16"]},
        ),
        ({"internal_suffixes": ["corp.acme.net"]}, {"internal_suffixes": []}),
    ],
)
async def test_re_ack_when_less_is_pseudonymized_or_ti_is_included(
    sent: AiSent, start: dict[str, Any], widening: dict[str, Any]
) -> None:
    owner = await register()
    first = await put_settings(
        owner.client, owner.org_id, ai_enabled=True, acknowledge_privacy=True, **start
    )
    assert first.status_code == 200, first.text
    refused = await put_settings(owner.client, owner.org_id, **widening)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "privacy_not_acknowledged"
    accepted = await put_settings(owner.client, owner.org_id, acknowledge_privacy=True, **widening)
    assert accepted.status_code == 200
    [(name, value)] = widening.items()
    assert accepted.json()[name] == value


async def test_adding_internal_entries_needs_no_new_acknowledgement(sent: AiSent) -> None:
    owner = await register()
    await put_settings(owner.client, owner.org_id, ai_enabled=True, acknowledge_privacy=True)
    more = await put_settings(
        owner.client,
        owner.org_id,
        internal_cidrs=["10.20.0.0/16"],
        internal_suffixes=["corp.acme.net"],
        include_ti=False,
    )
    assert more.status_code == 200, more.text
    same = await put_settings(owner.client, owner.org_id, internal_cidrs=["10.20.0.0/16"])
    assert same.status_code == 200
