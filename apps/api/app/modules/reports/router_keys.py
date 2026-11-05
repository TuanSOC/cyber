"""`GET /api/v1/report-signing-keys` (M6 phase 1, implemented; RT22).

Unauthenticated on purpose: the recipient of an external PDF has no account and verifies
the embedded signature with these public keys (`scripts/verify_report.py`). Public keys
only, no org, rate-limited per client IP. The keys are listed in DEPLOYMENT too.
"""

from fastapi import APIRouter, Request, Response

from app.core import rate_limit
from app.core.client_ip import ip_key
from app.core.config import get_settings
from app.core.signing import load_public_keys, public_key_b64
from app.modules.reports.schemas import SigningKeyOut, SigningKeysOut

router = APIRouter(tags=["reports"])

KEYS_PER_IP_PER_MIN = 60


@router.get("/report-signing-keys", response_model=SigningKeysOut)
async def report_signing_keys(request: Request, response: Response) -> SigningKeysOut:
    await rate_limit.hit(f"report-keys:{ip_key(request)}", KEYS_PER_IP_PER_MIN, 60)
    settings = get_settings()
    keys = load_public_keys(settings.report_signing_public_keys)
    response.headers["Cache-Control"] = "public, max-age=300"
    return SigningKeysOut(
        keys=[
            SigningKeyOut(
                kid=kid,
                public_key=public_key_b64(key),
                active=kid == settings.report_signing_active_kid,
            )
            for kid, key in sorted(keys.items())
        ]
    )
