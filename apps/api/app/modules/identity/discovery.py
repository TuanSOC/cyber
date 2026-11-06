"""OIDC discovery and JWKS cache (M11; phase 1 stub, phase 7 implements it).

`refresh_jwks_if_unknown_kid(session, config, kid)` (FROZEN, RT17), called by the phase-8
callback when an ID token's `kid` is not in the cached JWKS: refetches the JWKS through the
egress proxy at most once per minute per org, stores it on the row and returns True when
`kid` is now present. Until phase 7 it returns False (the callback then refuses the token).
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.identity.models import OrgIdpConfig


async def refresh_jwks_if_unknown_kid(
    session: AsyncSession, config: OrgIdpConfig, kid: str
) -> bool:
    return False
