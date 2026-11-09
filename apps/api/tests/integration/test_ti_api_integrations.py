"""Integrations and TI settings routes (M4 phase 5): catalog, write-only sealed keys, terms
acknowledgement, MISP URL binding, limits, verify queueing, concurrency."""

import asyncio
import base64
import logging
import uuid

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.modules.threat_intel import service_integrations
from app.modules.threat_intel.models import TiProviderConfig
from app.modules.threat_intel.seal import SealedKey
from app.modules.threat_intel.unseal import UnsealError, open_sealed
from tests.factories import add_member, csrf, login, make_user, register, unique_email
from tests.identity_helpers import session_id_of, set_step_up
from tests.integration.seed import Tenant
from tests.ti_api_helpers import API, Sent, capture_sends, enable, put_integration
from tests.ti_helpers import SENTINEL_KEY, assert_key_absent, new_seal_keys

MISP_URL = "https://misp.acme-corp.net"


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    return capture_sends(monkeypatch)


async def _config(org_id: uuid.UUID, provider: str = "mock") -> TiProviderConfig:
    async with tenant_session(org_id, None) as s:
        row = await s.scalar(
            select(TiProviderConfig).where(
                TiProviderConfig.organization_id == org_id, TiProviderConfig.provider == provider
            )
        )
    assert row is not None
    return row


async def _audit(org_id: uuid.UUID, prefix: str = "integration.") -> list[AuditLog]:
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


async def test_catalog_and_viewer_sees_status_without_secrets(sent: Sent) -> None:
    owner = await register()
    viewer_email = unique_email("viewer")
    await add_member(owner.org_id, await make_user(viewer_email), MemberRole.VIEWER)
    viewer = await login(viewer_email)

    empty = await viewer.get(f"{API}/{owner.org_id}/integrations")
    assert empty.status_code == 200
    body = empty.json()
    assert body["ti_enabled"] is True
    names = [i["name"] for i in body["items"]]
    assert names == ["virustotal", "abuseipdb", "urlhaus", "malwarebazaar", "otx", "misp", "mock"]
    vt = _entry(body, "virustotal")
    assert vt["configured"] is False and vt["enabled"] is False and vt["key_last4"] is None
    assert vt["default_limits"] == {"per_minute": 4, "per_day": 500}
    assert vt["ceilings"] == {"per_minute": 4, "per_day": 500}
    assert vt["available"] is True and vt["tos_note"] and vt["privacy_note"]
    assert _entry(body, "misp")["needs_base_url"] is True
    assert _entry(body, "mock")["available"] is True  # test env: TI_MOCK_ENABLED

    await enable(owner.client, owner.org_id)
    seen = await viewer.get(f"{API}/{owner.org_id}/integrations")
    mock = _entry(seen.json(), "mock")
    assert mock["configured"] is True and mock["enabled"] is True
    assert mock["key_last4"] == SENTINEL_KEY[-4:]
    assert mock["verify_status"] == "unverified" and mock["terms_ack_at"] is not None
    assert SENTINEL_KEY not in seen.text and SENTINEL_KEY[:-4] not in seen.text
    for column in ("key_ct", "key_epk", "key_nonce", "key_kid", "api_key"):
        assert column not in seen.text
    # Viewers read, never write.
    denied = await put_integration(viewer, owner.org_id, enabled=False)
    assert denied.status_code == 403


async def test_enabling_requires_terms_acknowledgement(sent: Sent) -> None:
    owner = await register()
    refused = await put_integration(owner.client, owner.org_id, api_key=SENTINEL_KEY, enabled=True)
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"]["code"] == "terms_not_acknowledged"
    listing = (await owner.client.get(f"{API}/{owner.org_id}/integrations")).json()
    assert _entry(listing, "mock")["configured"] is False  # nothing was stored

    # Key first (disabled), then acknowledge + enable.
    stored = await put_integration(owner.client, owner.org_id, api_key=SENTINEL_KEY)
    assert stored.status_code == 200 and stored.json()["enabled"] is False
    assert stored.json()["terms_ack_at"] is None
    again = await put_integration(owner.client, owner.org_id, enabled=True)
    assert again.json()["error"]["code"] == "terms_not_acknowledged"
    ok = await put_integration(owner.client, owner.org_id, enabled=True, acknowledge_terms=True)
    assert ok.status_code == 200 and ok.json()["enabled"] is True
    config = await _config(owner.org_id)
    assert config.terms_ack_by == owner.user_id and config.terms_ack_at is not None
    actions = [a.action for a in await _audit(owner.org_id)]
    assert actions[0] == "integration.key_set"
    # Same transaction (same occurred_at): order-independent.
    assert sorted(actions[1:]) == ["integration.terms_acknowledged", "integration.updated"]
    # Acknowledged once: disabling and re-enabling needs no new acknowledgement.
    off = await put_integration(owner.client, owner.org_id, enabled=False)
    on = await put_integration(owner.client, owner.org_id, enabled=True)
    assert (off.status_code, on.status_code) == (200, 200)


async def test_first_configuration_requires_a_key(sent: Sent) -> None:
    owner = await register()
    for body in ({"enabled": False}, {"limits": {"per_minute": 1}}, {"acknowledge_terms": True}):
        response = await put_integration(owner.client, owner.org_id, **body)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "api_key_required"


async def test_sentinel_key_never_leaks(
    sent: Sent, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    owner = await register()
    texts: list[str] = []

    first = await put_integration(
        owner.client,
        owner.org_id,
        api_key=f"  {SENTINEL_KEY}  ",  # stripped
        enabled=True,
        acknowledge_terms=True,
    )
    assert first.status_code == 200
    assert first.json()["key_last4"] == SENTINEL_KEY[-4:]
    texts.append(first.text)
    for bad in (
        SENTINEL_KEY * 7,  # over 256 characters
        SENTINEL_KEY + "é",  # not ASCII
        SENTINEL_KEY + "\n",  # stripped: a valid, re-entered key
        SENTINEL_KEY[:5],  # too short
        "CYBERLAB-TEST-SENTINEL\x01KEY",  # control character
    ):
        response = await put_integration(owner.client, owner.org_id, api_key=bad)
        texts.append(response.text)
        if bad.strip() == SENTINEL_KEY:
            assert response.status_code == 200
        else:
            assert response.status_code == 422, bad
            assert response.json()["error"]["code"] == "validation_error"
    texts.append((await owner.client.get(f"{API}/{owner.org_id}/integrations")).text)
    texts.append((await owner.client.get(f"{API}/{owner.org_id}/audit-logs")).text)
    texts.append(
        (
            await owner.client.post(
                f"{API}/{owner.org_id}/integrations/mock/verify", headers=csrf(owner.client)
            )
        ).text
    )

    config = await _config(owner.org_id)
    assert config.key_ct is not None
    ciphertexts = (config.key_ct.hex(), base64.b64encode(config.key_ct).decode())
    captured = capsys.readouterr()
    for text in (*texts, caplog.text, captured.out, captured.err):
        assert SENTINEL_KEY not in text
        assert SENTINEL_KEY[:12] not in text
        for ct in ciphertexts:
            assert ct not in text
    await assert_key_absent(Tenant(owner.org_id, owner.user_id, uuid.uuid4()), SENTINEL_KEY)
    # The verify message carries ids only.
    assert sent.verifies and all(v == (owner.org_id, "mock") for v in sent.verifies)


async def test_replace_bumps_version_and_remove_keeps_it(sent: Sent) -> None:
    owner = await register()
    await enable(owner.client, owner.org_id, key="first-key-1111")
    assert (await _config(owner.org_id)).key_version == 1
    replaced = await put_integration(owner.client, owner.org_id, api_key="second-key-2222")
    assert replaced.status_code == 200 and replaced.json()["key_last4"] == "2222"
    assert replaced.json()["verify_status"] == "unverified"
    assert (await _config(owner.org_id)).key_version == 2
    assert len(sent.verifies) == 2

    url = f"{API}/{owner.org_id}/integrations/mock/key"
    await set_step_up(session_id_of(owner.client), seconds_ago=0)
    removed = await owner.client.delete(url, headers=csrf(owner.client))
    assert removed.status_code == 204
    config = await _config(owner.org_id)
    assert (config.key_ct, config.key_last4, config.enabled) == (None, None, False)
    assert config.key_version == 2  # the version floor stays (RT18)
    entry = _entry((await owner.client.get(f"{API}/{owner.org_id}/integrations")).json(), "mock")
    assert entry["configured"] is False and entry["key_last4"] is None
    await set_step_up(session_id_of(owner.client), seconds_ago=0)
    again = await owner.client.delete(url, headers=csrf(owner.client))
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "integration_not_configured"
    no_key = await put_integration(owner.client, owner.org_id, enabled=True)
    assert no_key.json()["error"]["code"] == "api_key_required"
    third = await put_integration(owner.client, owner.org_id, api_key="third-key-3333")
    assert third.status_code == 200
    assert (await _config(owner.org_id)).key_version == 3

    audits = await _audit(owner.org_id)
    keyed = [(a.action, a.details) for a in audits if a.action.startswith("integration.key")]
    assert [a for a, _ in keyed] == [
        "integration.key_set",
        "integration.key_replaced",
        "integration.key_removed",
        "integration.key_set",
    ]
    assert keyed[1][1] == {
        "provider": "mock",
        "key_last4": "2222",
        "key_kid": get_settings().ti_seal_active_kid,
        "key_version": 2,
    }


async def test_limits_may_only_be_lowered(sent: Sent) -> None:
    owner = await register()
    await enable(owner.client, owner.org_id, provider="virustotal", key="vt-key-00001234")
    lowered = await put_integration(
        owner.client, owner.org_id, "virustotal", limits={"per_minute": 2, "per_day": 100}
    )
    assert lowered.status_code == 200
    assert lowered.json()["limits"] == {"per_minute": 2, "per_day": 100}
    for limits in ({"per_minute": 5}, {"per_day": 501}):
        above = await put_integration(owner.client, owner.org_id, "virustotal", limits=limits)
        assert above.status_code == 422
        assert above.json()["error"]["code"] == "limit_above_ceiling"
    reset = await put_integration(owner.client, owner.org_id, "virustotal", limits={})
    assert reset.json()["limits"] is None
    zero = await put_integration(owner.client, owner.org_id, "virustotal", limits={"per_day": 0})
    assert zero.status_code == 422


async def test_misp_url_is_bound_to_the_key(sent: Sent, monkeypatch: pytest.MonkeyPatch) -> None:
    keys = new_seal_keys("test-misp")
    monkeypatch.setattr(get_settings(), "ti_seal_public_keys", {keys.kid: keys.public_b64})
    monkeypatch.setattr(get_settings(), "ti_seal_active_kid", keys.kid)
    owner = await register()

    missing = await put_integration(owner.client, owner.org_id, "misp", api_key=SENTINEL_KEY)
    assert missing.json()["error"]["code"] == "misp_url_required"
    for url in (
        "http://misp.acme-corp.net",
        "https://admin:hunter2@misp.acme-corp.net",
        "https://misp.local",
        "https://10.1.2.3",
        "https://misp.acme-corp.net/?x=1",
    ):
        bad = await put_integration(
            owner.client, owner.org_id, "misp", api_key=SENTINEL_KEY, base_url=url
        )
        assert bad.status_code == 422, url
        assert bad.json()["error"]["code"] == "misp_url_invalid"
        assert "hunter2" not in bad.text and SENTINEL_KEY not in bad.text
    not_misp = await put_integration(owner.client, owner.org_id, base_url=MISP_URL)
    assert not_misp.json()["error"]["code"] == "base_url_not_supported"

    saved = await put_integration(
        owner.client, owner.org_id, "misp", api_key=SENTINEL_KEY, base_url=f"{MISP_URL}/"
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["base_url"] == MISP_URL and saved.json()["verify_queued"] is True
    assert sent.verifies == [(owner.org_id, "misp")]

    moved = await put_integration(
        owner.client, owner.org_id, "misp", base_url="https://misp2.acme-corp.net"
    )
    assert moved.status_code == 422
    assert moved.json()["error"]["code"] == "key_required_for_url_change"
    # Same URL again (normalized) is not a change: nothing to verify, nothing queued.
    same = await put_integration(owner.client, owner.org_id, "misp", base_url=MISP_URL)
    assert same.status_code == 200 and same.json()["verify_queued"] is False
    empty = await put_integration(owner.client, owner.org_id, "misp")
    assert empty.status_code == 200 and empty.json()["verify_queued"] is False
    assert len(sent.verifies) == 1

    config = await _config(owner.org_id, "misp")
    sealed = SealedKey(
        config.key_kid or "",
        config.key_version,
        config.key_epk or b"",
        config.key_nonce or b"",
        config.key_ct or b"",
        config.key_last4 or "",
    )
    opened = open_sealed(sealed, owner.org_id, "misp", MISP_URL, keys.private_keys)
    assert opened.get_secret_value() == SENTINEL_KEY
    with pytest.raises(UnsealError):
        open_sealed(sealed, owner.org_id, "misp", "https://evil.acme-corp.net", keys.private_keys)

    rebound = await put_integration(
        owner.client,
        owner.org_id,
        "misp",
        api_key=SENTINEL_KEY,
        base_url="https://misp2.acme-corp.net",
    )
    assert (
        rebound.status_code == 200 and rebound.json()["base_url"] == "https://misp2.acme-corp.net"
    )
    assert (await _config(owner.org_id, "misp")).key_version == 2


async def test_mock_is_unavailable_in_prod(sent: Sent, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = await register()
    await enable(owner.client, owner.org_id)
    monkeypatch.setattr(get_settings(), "env", "prod")
    entry = _entry((await owner.client.get(f"{API}/{owner.org_id}/integrations")).json(), "mock")
    assert entry["available"] is False and entry["configured"] is True
    put = await put_integration(owner.client, owner.org_id, enabled=False)
    assert put.status_code == 422 and put.json()["error"]["code"] == "provider_unavailable"
    verify = await owner.client.post(
        f"{API}/{owner.org_id}/integrations/mock/verify", headers=csrf(owner.client)
    )
    assert verify.json()["error"]["code"] == "provider_unavailable"
    # The key can still be removed.
    await set_step_up(session_id_of(owner.client), seconds_ago=0)
    removed = await owner.client.delete(
        f"{API}/{owner.org_id}/integrations/mock/key", headers=csrf(owner.client)
    )
    assert removed.status_code == 204


async def test_ti_disabled_marks_everything_unavailable(
    sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    monkeypatch.setattr(get_settings(), "ti_enabled", False)
    body = (await owner.client.get(f"{API}/{owner.org_id}/integrations")).json()
    assert body["ti_enabled"] is False
    assert all(i["available"] is False for i in body["items"])
    put = await put_integration(owner.client, owner.org_id, "otx", api_key=SENTINEL_KEY)
    assert put.json()["error"]["code"] == "provider_unavailable"


async def test_verify_is_queued_and_rate_limited(
    sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    url = f"{API}/{owner.org_id}/integrations/mock/verify"
    unconfigured = await owner.client.post(url, headers=csrf(owner.client))
    assert unconfigured.status_code == 409
    assert unconfigured.json()["error"]["code"] == "integration_not_configured"
    enabled = await enable(owner.client, owner.org_id)
    assert enabled["verify_queued"] is True  # the save's check counts against the limit
    sent.verifies.clear()
    for _ in range(service_integrations.VERIFY_PER_10MIN - 1):
        ok = await owner.client.post(url, headers=csrf(owner.client))
        assert ok.status_code == 202 and ok.json() == {"provider": "mock", "status": "queued"}
    limited = await owner.client.post(url, headers=csrf(owner.client))
    assert limited.status_code == 429
    assert len(sent.verifies) == service_integrations.VERIFY_PER_10MIN - 1
    # Limit spent: a key save still succeeds, but queues no check.
    saved = await put_integration(owner.client, owner.org_id, api_key="rotated-key-9999")
    assert saved.status_code == 200, saved.text
    assert saved.json()["key_last4"] == "9999" and saved.json()["verify_queued"] is False
    assert len(sent.verifies) == service_integrations.VERIFY_PER_10MIN - 1
    # Saves without a new key never queue one (no flood of the enrich queue).
    for _ in range(3):
        same = await put_integration(owner.client, owner.org_id, enabled=True)
        assert same.status_code == 200 and same.json()["verify_queued"] is False

    async def broken(*_: object) -> bool:
        return False

    monkeypatch.setattr(service_integrations, "send_verify", broken)
    otx = await enable(owner.client, owner.org_id, provider="otx", key="otx-key-12345678")
    assert otx["configured"] is True  # a lost verify publish never fails the save
    assert otx["verify_queued"] is False
    failed = await owner.client.post(
        f"{API}/{owner.org_id}/integrations/otx/verify", headers=csrf(owner.client)
    )
    assert failed.status_code == 503 and failed.json()["error"]["code"] == "broker_unavailable"


async def test_concurrent_puts_serialize(sent: Sent) -> None:
    owner = await register()
    responses = await asyncio.gather(
        *(
            put_integration(owner.client, owner.org_id, api_key=f"concurrent-key-{i:04d}")
            for i in range(5)
        )
    )
    assert [r.status_code for r in responses] == [200] * 5, [r.text for r in responses]
    config = await _config(owner.org_id)
    assert config.key_version == 5
    actions = sorted(a.action for a in await _audit(owner.org_id, "integration.key"))
    assert actions == ["integration.key_replaced"] * 4 + ["integration.key_set"]


async def test_unknown_provider_is_a_validation_error(sent: Sent) -> None:
    owner = await register()
    response = await put_integration(owner.client, owner.org_id, "shodan", api_key=SENTINEL_KEY)
    assert response.status_code == 422
    assert SENTINEL_KEY not in response.text


async def test_ti_settings(sent: Sent) -> None:
    owner = await register()
    viewer_email = unique_email("viewer")
    await add_member(owner.org_id, await make_user(viewer_email), MemberRole.VIEWER)
    viewer = await login(viewer_email)
    url = f"{API}/{owner.org_id}/ti/settings"

    assert (await viewer.get(url)).json() == {"excluded_suffixes": [], "updated_at": None}
    body = {"excluded_suffixes": ["Corp.Acme-Corp.NET", ".internal.acme.com", "corp.acme-corp.net"]}
    saved = await owner.client.put(url, json=body, headers=csrf(owner.client))
    assert saved.status_code == 200
    assert saved.json()["excluded_suffixes"] == ["corp.acme-corp.net", "internal.acme.com"]
    assert (await viewer.get(url)).json()["excluded_suffixes"] == saved.json()["excluded_suffixes"]
    denied = await viewer.put(url, json=body, headers=csrf(viewer))
    assert denied.status_code == 403
    for bad in (["not a suffix!"], ["a..b"], [f"s{i}.acme.com" for i in range(51)]):
        refused = await owner.client.put(
            url, json={"excluded_suffixes": bad}, headers=csrf(owner.client)
        )
        assert refused.status_code == 422, bad
    [entry] = await _audit(owner.org_id, "ti.settings_updated")
    assert entry.details["added"] == ["corp.acme-corp.net", "internal.acme.com"]
    cleared = await owner.client.put(
        url, json={"excluded_suffixes": []}, headers=csrf(owner.client)
    )
    assert cleared.json()["excluded_suffixes"] == []
