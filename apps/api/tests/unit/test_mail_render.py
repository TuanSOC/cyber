"""Unit tests for mail template rendering and safety defenses (M11 phase 2)."""

from datetime import datetime, timezone

import pytest

from app.modules.mail.render import (
    MAX_BODY_BYTES,
    RenderRefusedError,
    render_mail,
    render_template_body,
)
from app.modules.mail.templates import MailTemplate


def test_invite_template_renders_fragment_link() -> None:
    msg = render_mail(
        MailTemplate.INVITE.value,
        {
            "org_name": "ACME Defense",
            "inviter_name": "Alice Analyst",
            "role": "analyst",
            "expires_at": datetime(2026, 12, 1, 12, 0, tzinfo=timezone.utc),
        },
        token="tok_abc123xyz",
        to_email="bob@example.com",
        from_email="noreply@cyberlab.invalid",
        public_base_url="https://cyberlab.local:8443",
    )
    assert msg["From"] == "noreply@cyberlab.invalid"
    assert msg["To"] == "bob@example.com"
    assert msg["Subject"] == "You are invited to an organization on CyberLab"
    assert msg["Auto-Submitted"] == "auto-generated"
    assert "Reply-To" not in msg
    assert "@cyberlab.local" in msg["Message-ID"]

    body = msg.get_content()
    assert '"ACME Defense"' in body
    assert '"Alice Analyst"' in body
    assert "https://cyberlab.local:8443/invite#t=tok_abc123xyz" in body
    assert len(body.encode("utf-8")) <= MAX_BODY_BYTES


def test_invite_template_neutralizes_phishing_org_name() -> None:
    # RT20: link-like names replaced with neutral label
    for link_like in ("https://phish.example", "www.evil.com", "login.portal.ru"):
        body = render_template_body(
            MailTemplate.INVITE,
            {
                "org_name": link_like,
                "inviter_name": "Alice Analyst",
                "role": "viewer",
                "expires_at": datetime(2026, 12, 1, 12, 0, tzinfo=timezone.utc),
            },
            token="tok_safe_token",
            public_base_url="https://cyberlab.local",
        )
        assert "an organization on CyberLab" in body
        assert link_like not in body


def test_all_templates_render_successfully() -> None:
    ts = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)

    samples = [
        (MailTemplate.EMAIL_VERIFY, {"display_name": "Dave"}, "tok_verify"),
        (MailTemplate.PASSWORD_RESET, {"display_name": "Dave"}, "tok_reset"),
        (MailTemplate.PASSWORD_CHANGED, {"display_name": "Dave"}, None),
        (MailTemplate.MFA_ENABLED, {"display_name": "Dave"}, None),
        (MailTemplate.MFA_DISABLED, {"display_name": "Dave"}, None),
        (MailTemplate.MFA_LOCKED, {"display_name": "Dave"}, None),
        (MailTemplate.RECOVERY_CODE_USED, {"display_name": "Dave", "remaining": 5}, None),
        (MailTemplate.MFA_RESET_BY_OPERATOR, {"display_name": "Dave"}, None),
        (
            MailTemplate.SSO_ACCOUNT_LINKED,
            {"display_name": "Dave", "org_name": "SecOps", "issuer_host": "idp.example.com"},
            None,
        ),
        (
            MailTemplate.API_KEY_CREATED,
            {
                "org_name": "SecOps",
                "key_name": "ingest-key",
                "creator_name": "Admin",
                "role": "analyst",
                "expires_at": ts,
            },
            None,
        ),
        (
            MailTemplate.NEW_OWNER_SECURITY_CHANGE,
            {"org_name": "SecOps", "actor_name": "Admin", "change": "security_policy"},
            None,
        ),
    ]

    for tmpl, params, token in samples:
        msg = render_mail(
            tmpl.value,
            params,
            token=token,
            to_email="user@example.com",
            from_email="noreply@cyberlab.local",
            public_base_url="https://cyberlab.local",
        )
        assert msg["Subject"]
        assert len(msg.get_content().encode("utf-8")) <= MAX_BODY_BYTES


def test_render_refuses_crlf_injection() -> None:
    with pytest.raises(RenderRefusedError, match="CR or LF characters"):
        render_mail(
            MailTemplate.PASSWORD_CHANGED.value,
            {"display_name": "Alice\r\nBcc: evil@attacker.com"},
            to_email="alice@example.com",
            from_email="noreply@cyberlab.local",
        )


def test_render_refuses_bidi_controls() -> None:
    # \u202E is Right-to-Left Override (RLO)
    with pytest.raises(RenderRefusedError, match="bidi control character"):
        render_mail(
            MailTemplate.PASSWORD_CHANGED.value,
            {"display_name": "Alice\u202Efdp.exe"},
            to_email="alice@example.com",
            from_email="noreply@cyberlab.local",
        )


def test_render_refuses_non_ascii_token() -> None:
    with pytest.raises(RenderRefusedError, match="ASCII-safe"):
        render_template_body(
            MailTemplate.EMAIL_VERIFY,
            {"display_name": "Alice"},
            token="token_with_unicode_\u2603",
        )
