import ipaddress
import logging

from starlette.requests import HTTPConnection

USER_AGENT_MAX = 512
UNKNOWN_IP_KEY = "unknown"

log = logging.getLogger(__name__)


def client_ip(conn: HTTPConnection) -> str | None:
    """Client address as seen by uvicorn.

    uvicorn runs with --proxy-headers and only the gateway can reach the api, so this is
    already the X-Forwarded-For client set by Caddy. Non-IP values (test clients) -> None.
    """
    host = conn.client.host if conn.client else None
    if host is None:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def ip_key(conn: HTTPConnection) -> str:
    """Rate-limit key part. Requests without a usable address share one explicit bucket."""
    ip = client_ip(conn)
    if ip is None:
        log.warning("request without a usable client address; using shared rate-limit bucket")
        return UNKNOWN_IP_KEY
    return ip


def user_agent(conn: HTTPConnection) -> str | None:
    value = conn.headers.get("user-agent")
    return value[:USER_AGENT_MAX] if value else None
