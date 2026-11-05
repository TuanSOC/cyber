import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)


class AppError(Exception):
    """Base for errors rendered as {"error": {"code", "message"}}."""

    status_code = 500
    code = "internal_error"
    message = "Internal server error"

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        headers: dict[str, str] | None = None,
        clear_auth_cookies: bool = False,
        extra: dict[str, object] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.headers = headers or {}
        self.clear_auth_cookies = clear_auth_cookies
        # M6: fixed, non-sensitive detail fields next to code / message (e.g. `reason`).
        self.extra = extra or {}
        super().__init__(self.message)


class Unauthorized(AppError):
    status_code = 401
    code = "unauthorized"
    message = "Authentication required"


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"
    message = "You do not have permission to perform this action"


class NotFound(AppError):
    status_code = 404
    code = "not_found"
    message = "Resource not found"


class Conflict(AppError):
    status_code = 409
    code = "conflict"
    message = "Request conflicts with the current state"


class Gone(AppError):
    status_code = 410
    code = "gone"
    message = "The resource is no longer available"


# --- M7 (frozen in phase 1; raised by phases 3, 4 and 6) ------------------------------------


class EvidencePurged(Gone):
    """Download and verify of evidence whose bytes were purged by retention (tombstoned):
    the metadata, hashes and custody stay."""

    code = "evidence_purged"
    message = "The evidence bytes were purged by the retention policy; hashes and custody remain"


class LegalHoldActive(Conflict):
    code = "legal_hold_active"
    message = "A legal hold covers this data"


class PolicyFloor(AppError):
    status_code = 422
    code = "policy_floor"
    message = "A retention value is below the minimum allowed"


class RetentionAcknowledgementRequired(AppError):
    status_code = 422
    code = "retention_acknowledgement_required"
    message = "Enforcing a retention policy needs acknowledge_destruction"


class SearchQueryInvalid(AppError):
    status_code = 422
    code = "search_query_invalid"
    message = "The search query is too short, too long or invalid"


class TooManyRequests(AppError):
    status_code = 429
    code = "rate_limited"
    message = "Too many requests, try again later"

    def __init__(self, retry_after: int) -> None:
        super().__init__(headers={"Retry-After": str(max(retry_after, 1))})


_HTTP_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    410: "gone",
    413: "payload_too_large",
    415: "unsupported_media_type",
}


def error_body(code: str, message: str, **extra: object) -> dict[str, object]:
    return {"error": {"code": code, "message": message, **extra}}


def register_error_handlers(app: FastAPI) -> None:
    """Every error leaves the API in the same {"error": {...}} envelope."""
    # Imported lazily: cookie helpers depend on settings, errors must not.
    from app.core.cookies import clear_auth_cookies

    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        response = JSONResponse(
            error_body(exc.code, exc.message, **getattr(exc, "extra", {})),
            status_code=exc.status_code,
            headers=exc.headers,
        )
        if exc.clear_auth_cookies:
            clear_auth_cookies(response)
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # loc/msg/type only: submitted values (passwords, ...) are never echoed back.
        details = [
            {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        return JSONResponse(
            error_body("validation_error", "Request validation failed", details=details),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else code.replace("_", " ")
        return JSONResponse(
            error_body(code, message), status_code=exc.status_code, headers=exc.headers
        )

    @app.exception_handler(RedisError)
    async def _redis_down(_: Request, exc: RedisError) -> JSONResponse:
        # Fail closed: rate limits / token denylist cannot be checked without Redis.
        log.error("redis unavailable: %s", exc)
        return JSONResponse(
            error_body("service_unavailable", "Service temporarily unavailable"),
            status_code=503,
            headers={"Retry-After": "5"},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
        return JSONResponse(error_body("internal_error", "Internal server error"), status_code=500)
