"""AI provider routes (M5 phase 7): catalog, write-only sealed keys, terms and Gemini
paid-tier acknowledgements (RT5), model allowlist, availability, verify queueing,
concurrency and the sentinel-key leak scan."""

import asyncio
import base64
import logging
import uuid

import pytest
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai import service_providers
from app.modules.ai.contracts import AiProviderName
from app.modules.ai.models import AiProviderConfig
from app.modules.ai.seal import SealedKey
from app.modules.ai.unseal import UnsealError, open_sealed
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import API, AiSent, capture_ai_sends, put_provider
from tests.ai_helpers import AI_SENTINEL_KEY, new_ai_seal_keys
from tests.factories import add_member, csrf, login, make_user, register, unique_email


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> AiSent:
    return capture_ai_sends(monkeypatch)


async def _config(org_id: uuid.UUID, provider: str = "mock") -> AiProviderConfig:
    async with tenant_session(org_id, None) as s:
        row = await s.scalar(
            select(AiProviderConfig).where(
                AiProviderConfig.organization_id == org_id, AiProviderConfig.provider == provider
            )
        )
    assert row is not None
    return row


async def _audit(org_id: uuid.UUID, prefix: str = "integration.ai") -> list[AuditLog]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == org_id, AuditLog.action.startswith(prefix))
            .order_by(AuditLog.occurred_at, AuditLog.id)
        )
        return list(rows)


def _entry(body: dict[str, object], provider: str) -> dict[str, object]:
    items = body["items"]
    assert isinstance(items, list)
    return next(i for i in items if i["name"] == provider)


async def _enable(client: object, org_id: uuid.UUID, key: str = AI_SENTINEL_KEY) -> None:
    response = await put_provider(
        client,  # type: ignore[arg-type]
        org_id,
        api_key=key,
        enabled=True,
        acknowledge_terms=True,
    )
    assert response.status_code == 200, response.text


async def test_catalog_and_viewer_sees_status_without_secrets(sent: AiSent) -> None:
    owner = await register()
    viewer_email = unique_email("viewer")
    await add_member(owner.org_id, await make_user(viewer_email), MemberRole.VIEWER)
    viewer = await login(viewer_email)

    listing = await viewer.get(f"{API}/{owner.org_id}/ai/providers")
    assert listing.status_code == 200
    body = listing.json()
    assert body["platform_ai_enabled"] is True and body["total"] == 3
    assert [i["name"] for i in body["items"]] == ["anthropic", "gemini", "mock"]
    anthropic = _entry(body, "anthropic")
    assert anthropic["available"] is True and anthropic["unavailable_reason"] is None
    assert anthropic["default_model"] == "claude-sonnet-5"
    models = anthropic["models"]
    assert isinstance(models, list)
    assert [m["id"] for m in models] == ["claude-sonnet-5", "claude-opus-5-5"]
    assert models[0]["price"] == {
        "input": 2.0,
        "output": 10.0,
        "cache_read": 0.2,
        "cache_write": 2.5,
    }
    assert anthropic["configured"] is False and anthropic["key_last4"] is None
    assert anthropic["platform_key"] is False and anthropic["tos_note"]
    gemini = _entry(body, "gemini")
    assert gemini["available"] is False
    assert gemini["unavailable_reason"] == "gemini_billing_required"
    assert gemini["requires_paid_tier_ack"] is True
    assert _entry(body, "mock")["available"] is True  # test env: AI_MOCK_ENABLED

    await _enable(owner.client, owner.org_id)
    seen = await viewer.get(f"{API}/{owner.org_id}/ai/providers")
    mock = _entry(seen.json(), "mock")
    assert mock["configured"] is True and mock["enabled"] is True
    assert mock["key_last4"] == AI_SENTINEL_KEY[-4:]
    assert mock["verify_status"] == "unverified" and mock["terms_ack_at"] is not None
    assert AI_SENTINEL_KEY not in seen.text and AI_SENTINEL_KEY[:-4] not in seen.text
    for column in ("key_ct", "key_epk", "key_nonce", "key_kid", "api_key"):
        assert column not in seen.text
    denied = await put_provider(viewer, owner.org_id, enabled=False)
    assert denied.status_code == 403


async def test_enabling_requires_terms_acknowledgement(sent: AiSent) -> None:
    owner = await register()
    refused = await put_provider(owner.client, owner.org_id, api_key=AI_SENTINEL_KEY, enabled=True)
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"]["code"] == "terms_not_acknowledged"
    listing = (await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).json()
    assert _entry(listing, "mock")["configured"] is False  # nothing was stored

    stored = await put_provider(owner.client, owner.org_id, api_key=AI_SENTINEL_KEY)
    assert stored.status_code == 200 and stored.json()["enabled"] is False
    again = await put_provider(owner.client, owner.org_id, enabled=True)
    assert again.json()["error"]["code"] == "terms_not_acknowledged"
    ok = await put_provider(owner.client, owner.org_id, enabled=True, acknowledge_terms=True)
    assert ok.status_code == 200 and ok.json()["enabled"] is True
    config = await _config(owner.org_id)
    assert config.terms_ack_by == owner.user_id and config.terms_ack_at is not None
    actions = sorted(a.action for a in await _audit(owner.org_id))
    assert actions == [
        "integration.ai_key_set",
        "integration.ai_terms_acknowledged",
        "integration.ai_updated",
    ]
    off = await put_provider(owner.client, owner.org_id, enabled=False)
    on = await put_provider(owner.client, owner.org_id, enabled=True)
    assert (off.status_code, on.status_code) == (200, 200)


async def test_gemini_needs_billing_and_a_paid_tier_attestation(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    unavailable = await put_provider(
        owner.client, owner.org_id, "gemini", api_key=AI_SENTINEL_KEY, acknowledge_terms=True
    )
    assert unavailable.status_code == 422
    assert unavailable.json()["error"]["code"] == "provider_unavailable"

    monkeypatch.setattr(get_settings(), "gemini_billing_enabled", True)
    no_attestation = await put_provider(
        owner.client,
        owner.org_id,
        "gemini",
        api_key=AI_SENTINEL_KEY,
        enabled=True,
        acknowledge_terms=True,
    )
    assert no_attestation.status_code == 422
    assert no_attestation.json()["error"]["code"] == "paid_tier_not_acknowledged"
    attested = await put_provider(
        owner.client,
        owner.org_id,
        "gemini",
        api_key=AI_SENTINEL_KEY,
        enabled=True,
        acknowledge_terms=True,
        acknowledge_paid_tier=True,
    )
    assert attested.status_code == 200, attested.text
    assert attested.json()["paid_tier_ack_at"] is not None and attested.json()["enabled"] is True
    config = await _config(owner.org_id, "gemini")
    assert config.paid_tier_ack_by == owner.user_id
    [ack] = await _audit(owner.org_id, "integration.ai_terms_acknowledged")
    assert ack.details == {"provider": "gemini", "acknowledged": ["terms", "paid_tier"]}


async def test_first_configuration_requires_a_key(sent: AiSent) -> None:
    owner = await register()
    for body in ({"enabled": False}, {"acknowledge_terms": True}, {"model": "mock-1"}):
        response = await put_provider(owner.client, owner.org_id, **body)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "api_key_required"


async def test_platform_key_covers_a_provider_outside_prod(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "ai_platform_provider", AiProviderName.MOCK)
    owner = await register()
    enabled = await put_provider(owner.client, owner.org_id, enabled=True, acknowledge_terms=True)
    assert enabled.status_code == 200, enabled.text
    body = enabled.json()
    assert body["platform_key"] is True and body["configured"] is False
    assert body["enabled"] is True and body["verify_queued"] is False
    assert sent.verifies == []
    monkeypatch.setattr(get_settings(), "env", "prod")
    listing = (await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).json()
    assert all(i["platform_key"] is False for i in listing["items"])


async def test_an_org_sets_its_own_request_limit_within_the_ceiling(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-minute limit the worker's token bucket uses (`limits.per_minute`): an org may
    set its own, never above the ceiling (`AI_CEILINGS.per_minute`, else the catalog's)."""
    owner = await register()
    await _enable(owner.client, owner.org_id)
    listed = _entry((await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).json(), "mock")
    assert listed["default_limits"] == {"per_minute": 600}
    assert listed["ceilings"] == {"per_minute": 6000} and listed["limits"] is None
    lowered = await put_provider(owner.client, owner.org_id, limits={"per_minute": 5})
    assert lowered.status_code == 200, lowered.text
    assert lowered.json()["limits"] == {"per_minute": 5}
    assert (await _config(owner.org_id)).limits == {"per_minute": 5}
    *_, updated = await _audit(owner.org_id, "integration.ai_updated")
    assert updated.details["changed"] == ["limits"]
    assert updated.details["limits"] == {"per_minute": 5}

    settings = get_settings()
    ceilings = settings.ai_ceilings.model_copy(update={"per_minute": {AiProviderName.MOCK: 4}})
    monkeypatch.setattr(settings, "ai_ceilings", ceilings)
    above = await put_provider(owner.client, owner.org_id, limits={"per_minute": 5})
    assert above.status_code == 422 and above.json()["error"]["code"] == "limit_above_ceiling"
    shown = _entry((await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).json(), "mock")
    assert shown["ceilings"] == {"per_minute": 4}
    # The stored 5 is shown as applied: capped by the lowered ceiling.
    assert shown["limits"] == {"per_minute": 4}
    assert (await _config(owner.org_id)).limits == {"per_minute": 5}
    for bad in ({"per_minute": 0}, {"per_minute": "x"}, {"per_day": 5}):
        invalid = await put_provider(owner.client, owner.org_id, limits=bad)
        assert invalid.status_code == 422, bad
    reset = await put_provider(owner.client, owner.org_id, limits={})
    assert reset.status_code == 200 and reset.json()["limits"] is None
    assert (await _config(owner.org_id)).limits == {}


async def test_model_allowlist(sent: AiSent) -> None:
    owner = await register()
    bad = await put_provider(
        owner.client, owner.org_id, "anthropic", api_key=AI_SENTINEL_KEY, model="gpt-4o"
    )
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "model_not_allowed"
    cross = await put_provider(
        owner.client, owner.org_id, api_key=AI_SENTINEL_KEY, model="claude-opus-5-5"
    )
    assert cross.json()["error"]["code"] == "model_not_allowed"
    ok = await put_provider(
        owner.client, owner.org_id, "anthropic", api_key=AI_SENTINEL_KEY, model="claude-opus-5-5"
    )
    assert ok.status_code == 200 and ok.json()["model"] == "claude-opus-5-5"
    reset = await put_provider(owner.client, owner.org_id, "anthropic", model=None)
    assert reset.status_code == 200 and reset.json()["model"] is None
    [updated, *_] = await _audit(owner.org_id, "integration.ai_updated")
    assert updated.details["changed"] == ["model"]


async def test_sentinel_key_never_leaks(
    sent: AiSent, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    owner = await register()
    texts: list[str] = []
    first = await put_provider(
        owner.client,
        owner.org_id,
        api_key=f"  {AI_SENTINEL_KEY}  ",  # stripped
        enabled=True,
        acknowledge_terms=True,
    )
    assert first.status_code == 200 and first.json()["key_last4"] == AI_SENTINEL_KEY[-4:]
    texts.append(first.text)
    for bad in (
        AI_SENTINEL_KEY * 7,  # over 256 characters
        AI_SENTINEL_KEY + "é",  # not ASCII
        AI_SENTINEL_KEY[:5],  # too short
        "CYBERLAB-AI-SENTINEL\x01KEY",  # control character
    ):
        response = await put_provider(owner.client, owner.org_id, api_key=bad)
        texts.append(response.text)
        assert response.status_code == 422, bad
        assert response.json()["error"]["code"] == "validation_error"
    # A 422 of a business rule with the key in the body never echoes it either.
    rule = await put_provider(
        owner.client, owner.org_id, "anthropic", api_key=AI_SENTINEL_KEY, model="nope"
    )
    assert rule.status_code == 422
    texts.append(rule.text)
    texts.append((await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).text)
    texts.append((await owner.client.get(f"{API}/{owner.org_id}/audit-logs")).text)
    texts.append(
        (
            await owner.client.post(
                f"{API}/{owner.org_id}/ai/providers/mock/verify", headers=csrf(owner.client)
            )
        ).text
    )

    config = await _config(owner.org_id)
    assert config.key_ct is not None
    ciphertexts = (config.key_ct.hex(), base64.b64encode(config.key_ct).decode())
    captured = capsys.readouterr()
    for blob in (*texts, caplog.text, captured.out, captured.err):
        assert AI_SENTINEL_KEY not in blob
        assert AI_SENTINEL_KEY[:12] not in blob
        for ct in ciphertexts:
            assert ct not in blob
    async with tenant_session(owner.org_id, owner.user_id) as s:
        for table in ("ai_provider_configs", "ai_org_settings", "ai_runs", "audit_logs"):
            dump = (
                await s.execute(
                    text(f"SELECT coalesce(string_agg(t::text, ''), '') FROM {table} t")
                )
            ).scalar_one()
            assert AI_SENTINEL_KEY not in dump and AI_SENTINEL_KEY[:20] not in dump, table
    # The verify messages carry ids and the key version only.
    assert sent.verifies and all(v[:2] == (owner.org_id, "mock") for v in sent.verifies)


async def test_sealed_key_opens_only_with_the_ai_private_key(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = new_ai_seal_keys("test-ai-route")
    monkeypatch.setattr(get_settings(), "ai_seal_public_keys", {keys.kid: keys.public_b64})
    monkeypatch.setattr(get_settings(), "ai_seal_active_kid", keys.kid)
    owner = await register()
    await _enable(owner.client, owner.org_id)
    config = await _config(owner.org_id)
    assert config.key_kid == keys.kid and config.key_version == 1
    sealed = SealedKey(
        config.key_kid or "",
        config.key_version,
        config.key_epk or b"",
        config.key_nonce or b"",
        config.key_ct or b"",
        config.key_last4 or "",
    )
    assert open_sealed(sealed, owner.org_id, "mock", keys.private_keys).get_secret_value() == (
        AI_SENTINEL_KEY
    )
    with pytest.raises(UnsealError):
        open_sealed(sealed, uuid.uuid4(), "mock", keys.private_keys)
    with pytest.raises(UnsealError):
        open_sealed(sealed, owner.org_id, "anthropic", keys.private_keys)


async def test_replace_bumps_version_and_remove_keeps_it(sent: AiSent) -> None:
    owner = await register()
    await _enable(owner.client, owner.org_id, key="first-key-1111")
    assert (await _config(owner.org_id)).key_version == 1
    replaced = await put_provider(owner.client, owner.org_id, api_key="second-key-2222")
    assert replaced.status_code == 200 and replaced.json()["key_last4"] == "2222"
    assert replaced.json()["verify_status"] == "unverified"
    assert replaced.json()["verify_queued"] is True
    assert (await _config(owner.org_id)).key_version == 2
    assert [v[2] for v in sent.verifies] == [1, 2]

    url = f"{API}/{owner.org_id}/ai/providers/mock/key"
    removed = await owner.client.delete(url, headers=csrf(owner.client))
    assert removed.status_code == 204
    config = await _config(owner.org_id)
    assert (config.key_ct, config.key_last4, config.enabled) == (None, None, False)
    assert config.key_version == 2  # the version floor stays (RT18)
    again = await owner.client.delete(url, headers=csrf(owner.client))
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "provider_not_configured"
    no_key = await put_provider(owner.client, owner.org_id, enabled=True)
    assert no_key.json()["error"]["code"] == "api_key_required"
    third = await put_provider(owner.client, owner.org_id, api_key="third-key-3333")
    assert third.status_code == 200
    assert (await _config(owner.org_id)).key_version == 3

    keyed = [(a.action, a.details) for a in await _audit(owner.org_id, "integration.ai_key")]
    assert [a for a, _ in keyed] == [
        "integration.ai_key_set",
        "integration.ai_key_replaced",
        "integration.ai_key_removed",
        "integration.ai_key_set",
    ]
    assert keyed[1][1] == {
        "provider": "mock",
        "key_last4": "2222",
        "key_kid": get_settings().ai_seal_active_kid,
        "key_version": 2,
    }


async def test_mock_is_unavailable_in_prod(sent: AiSent, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = await register()
    await _enable(owner.client, owner.org_id)
    monkeypatch.setattr(get_settings(), "env", "prod")
    entry = _entry((await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).json(), "mock")
    assert entry["available"] is False and entry["unavailable_reason"] == "prod_mock"
    put = await put_provider(owner.client, owner.org_id, enabled=False)
    assert put.status_code == 422 and put.json()["error"]["code"] == "provider_unavailable"
    verify = await owner.client.post(
        f"{API}/{owner.org_id}/ai/providers/mock/verify", headers=csrf(owner.client)
    )
    assert verify.json()["error"]["code"] == "provider_unavailable"
    removed = await owner.client.delete(
        f"{API}/{owner.org_id}/ai/providers/mock/key", headers=csrf(owner.client)
    )
    assert removed.status_code == 204  # a key can always be removed


async def test_ai_disabled_platform_marks_everything_unavailable(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    monkeypatch.setattr(get_settings(), "ai_enabled", False)
    body = (await owner.client.get(f"{API}/{owner.org_id}/ai/providers")).json()
    assert body["platform_ai_enabled"] is False
    assert {i["unavailable_reason"] for i in body["items"]} == {"ai_disabled_platform"}
    put = await put_provider(owner.client, owner.org_id, "anthropic", api_key=AI_SENTINEL_KEY)
    assert put.json()["error"]["code"] == "provider_unavailable"


async def test_verify_is_queued_and_rate_limited(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    url = f"{API}/{owner.org_id}/ai/providers/mock/verify"
    unconfigured = await owner.client.post(url, headers=csrf(owner.client))
    assert unconfigured.status_code == 409
    assert unconfigured.json()["error"]["code"] == "provider_not_configured"
    saved = await put_provider(
        owner.client, owner.org_id, api_key=AI_SENTINEL_KEY, acknowledge_terms=True
    )
    assert saved.json()["verify_queued"] is True  # the save's check counts against the limit
    sent.verifies.clear()
    for _ in range(service_providers.VERIFY_PER_10MIN - 1):
        ok = await owner.client.post(url, headers=csrf(owner.client))
        assert ok.status_code == 202 and ok.json() == {"provider": "mock", "status": "queued"}
    limited = await owner.client.post(url, headers=csrf(owner.client))
    assert limited.status_code == 429
    assert len(sent.verifies) == service_providers.VERIFY_PER_10MIN - 1
    assert {v for v in sent.verifies} == {(owner.org_id, "mock", 1)}
    rotated = await put_provider(owner.client, owner.org_id, api_key="rotated-key-9999")
    assert rotated.status_code == 200 and rotated.json()["verify_queued"] is False
    same = await put_provider(owner.client, owner.org_id, enabled=True)
    assert same.status_code == 200 and same.json()["verify_queued"] is False

    async def broken(*_: object) -> bool:
        return False

    monkeypatch.setattr(service_providers, "send_verify", broken)
    other = await put_provider(
        owner.client, owner.org_id, "anthropic", api_key="anthropic-key-1234"
    )
    assert other.status_code == 200 and other.json()["verify_queued"] is False
    failed = await owner.client.post(
        f"{API}/{owner.org_id}/ai/providers/anthropic/verify", headers=csrf(owner.client)
    )
    assert failed.status_code == 503 and failed.json()["error"]["code"] == "broker_unavailable"


async def test_concurrent_puts_serialize(sent: AiSent) -> None:
    owner = await register()
    responses = await asyncio.gather(
        *(
            put_provider(owner.client, owner.org_id, api_key=f"concurrent-key-{i:04d}")
            for i in range(5)
        )
    )
    assert [r.status_code for r in responses] == [200] * 5, [r.text for r in responses]
    assert (await _config(owner.org_id)).key_version == 5
    actions = sorted(a.action for a in await _audit(owner.org_id, "integration.ai_key"))
    assert actions == ["integration.ai_key_replaced"] * 4 + ["integration.ai_key_set"]


async def test_unknown_provider_is_a_validation_error(sent: AiSent) -> None:
    owner = await register()
    response = await put_provider(owner.client, owner.org_id, "openai", api_key=AI_SENTINEL_KEY)
    assert response.status_code == 422
    assert AI_SENTINEL_KEY not in response.text


async def test_a_new_gemini_key_needs_a_new_paid_tier_attestation(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "gemini_billing_enabled", True)
    owner = await register()
    attested = await put_provider(
        owner.client,
        owner.org_id,
        "gemini",
        api_key="gemini-key-1111",
        enabled=True,
        acknowledge_terms=True,
        acknowledge_paid_tier=True,
    )
    assert attested.status_code == 200, attested.text
    # An enabled config: the replacement key must come with its own attestation.
    refused = await put_provider(owner.client, owner.org_id, "gemini", api_key="gemini-key-2222")
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "paid_tier_not_acknowledged"
    assert (await _config(owner.org_id, "gemini")).key_last4 == "1111"  # nothing changed
    # Disabled with the new key: the attestation is cleared, so enabling asks again.
    swapped = await put_provider(
        owner.client, owner.org_id, "gemini", api_key="gemini-key-3333", enabled=False
    )
    assert swapped.status_code == 200, swapped.text
    assert swapped.json()["paid_tier_ack_at"] is None and swapped.json()["enabled"] is False
    again = await put_provider(owner.client, owner.org_id, "gemini", enabled=True)
    assert again.json()["error"]["code"] == "paid_tier_not_acknowledged"
    ok = await put_provider(
        owner.client, owner.org_id, "gemini", enabled=True, acknowledge_paid_tier=True
    )
    assert ok.status_code == 200 and ok.json()["paid_tier_ack_at"] is not None
    replaced = [a.details for a in await _audit(owner.org_id, "integration.ai_key_replaced")]
    assert replaced == [
        {
            "provider": "gemini",
            "key_last4": "3333",
            "key_kid": get_settings().ai_seal_active_kid,
            "key_version": 2,
            "paid_tier_ack_cleared": True,
        }
    ]
    # Replacing the key together with a fresh attestation keeps the provider enabled.
    rotated = await put_provider(
        owner.client, owner.org_id, "gemini", api_key="gemini-key-4444", acknowledge_paid_tier=True
    )
    assert rotated.status_code == 200 and rotated.json()["enabled"] is True
    assert rotated.json()["paid_tier_ack_at"] is not None
