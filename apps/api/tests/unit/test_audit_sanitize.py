"""audit.sanitize drops secret-looking keys at any depth (M4: provider API keys)."""

import pytest

from app.modules.audit.service import sanitize


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "new_password",
        "token",
        "refresh_token",
        "client_secret",
        "api_key",
        "apiKey",
        "api-key",
        "APIKEY",
        "authorization",
        "Authorization",
        "auth_key",
        "Auth-Key",
        "x-apikey",
        "X-OTX-API-KEY",
        "key",
        "provider_key",
        "misp_key",
    ],
)
def test_sensitive_keys_are_dropped(key: str) -> None:
    assert sanitize({key: "SENTINEL", "provider": "otx"}) == {"provider": "otx"}


@pytest.mark.parametrize("key", ["key_last4", "key_kid", "key_version", "ioc_key"])
def test_key_metadata_is_allowlisted(key: str) -> None:
    assert sanitize({key: "v"}) == {key: "v"}


@pytest.mark.parametrize("key", ["keys", "keyword", "monkey_business", "keyring", "provider"])
def test_ordinary_keys_survive(key: str) -> None:
    assert sanitize({key: "v"}) == {key: "v"}


def test_nested_dicts_and_lists_of_dicts_are_sanitized() -> None:
    details = {
        "provider": "misp",
        "changed": {"api_key": "SENTINEL", "enabled": True, "deeper": {"Authorization": "x"}},
        "items": [{"auth_key": "SENTINEL", "ioc_key": "abc"}, {"name": "ok"}, "plain"],
        "tuple": ({"x-apikey": "SENTINEL"},),
    }
    cleaned = sanitize(details)
    assert "SENTINEL" not in repr(cleaned)
    assert cleaned == {
        "provider": "misp",
        "changed": {"enabled": True, "deeper": {}},
        "items": [{"ioc_key": "abc"}, {"name": "ok"}, "plain"],
        "tuple": [{}],
    }


def test_empty_details() -> None:
    assert sanitize(None) == {} and sanitize({}) == {}
