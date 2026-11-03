"""Test factories: real rows / real API calls, no mocks."""

import uuid
from dataclasses import dataclass
from itertools import count
from typing import Any

from httpx import ASGITransport, AsyncClient

from app.core.cookies import CSRF_COOKIE
from app.core.security import hash_password
from app.core.tenancy import tenant_session
from app.main import app
from app.modules.organizations.models import MemberRole, OrganizationMember
from app.modules.users.models import User

PASSWORD = "correct horse battery staple"
BASE_URL = "http://api.test"
_seq = count(1)


def new_client(ip: str = "10.0.0.1") -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, client=(ip, 40000)), base_url=BASE_URL)


def csrf(client: AsyncClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get(CSRF_COOKIE) or ""}


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}{next(_seq)}@example.com"


@dataclass(frozen=True)
class Registered:
    client: AsyncClient
    user_id: uuid.UUID
    org_id: uuid.UUID
    email: str
    body: dict[str, Any]


async def register(
    client: AsyncClient | None = None,
    *,
    email: str | None = None,
    password: str = PASSWORD,
    org_name: str = "Acme IR",
) -> Registered:
    client = client or new_client()
    email = email or unique_email()
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "display_name": email.split("@")[0],
            "organization_name": org_name,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return Registered(
        client=client,
        user_id=uuid.UUID(body["user"]["id"]),
        org_id=uuid.UUID(body["memberships"][0]["organization_id"]),
        email=email,
        body=body,
    )


async def make_user(email: str | None = None, password: str = PASSWORD) -> uuid.UUID:
    async with tenant_session(None, None) as session:
        user = User(
            email=email or unique_email(),
            password_hash=hash_password(password),
            display_name="member",
        )
        session.add(user)
    return user.id


async def add_member(org_id: uuid.UUID, user_id: uuid.UUID, role: MemberRole) -> None:
    async with tenant_session(org_id, user_id) as session:
        session.add(OrganizationMember(organization_id=org_id, user_id=user_id, role=role))


async def login(email: str, password: str = PASSWORD, ip: str = "10.0.0.1") -> AsyncClient:
    client = new_client(ip)
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return client
