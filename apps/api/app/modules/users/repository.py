import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.users.models import User


async def get_by_email(session: AsyncSession, email: str) -> User | None:
    # email is citext: comparison is case-insensitive in the database.
    return (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()


async def get_active(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    stmt = select(User).where(User.id == user_id, User.is_active.is_(True))
    return (await session.execute(stmt)).scalar_one_or_none()
