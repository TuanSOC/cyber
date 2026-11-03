import pytest
from pydantic import ValidationError

from app.core.config import Settings

BASE = {
    "database_url": "postgresql+asyncpg://cyberlab_app:s3cret@postgres/cyberlab",
    "redis_url": "redis://redis:6379/0",
    "jwt_secret": "x" * 48,
    "minio_endpoint": "minio:9000",
    "minio_access_key": "cyberlab-api",
    "minio_secret_key": "s3cret-minio",
}


def test_prod_requires_secure_cookies() -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings(**BASE, env="prod", cookie_secure=False)


def test_prod_rejects_placeholder_secrets() -> None:
    values = {**BASE, "jwt_secret": "change-me-at-least-32-characters-long-secret"}
    with pytest.raises(ValidationError, match="jwt_secret"):
        Settings(**values, env="prod", cookie_secure=True)


def test_prod_accepts_real_values() -> None:
    assert Settings(**BASE, env="prod", cookie_secure=True).env == "prod"


def test_dev_allows_insecure_cookies() -> None:
    assert Settings(**BASE, env="dev", cookie_secure=False).cookie_secure is False


def test_jwt_secret_minimum_length() -> None:
    with pytest.raises(ValidationError):
        Settings(**{**BASE, "jwt_secret": "short"})
