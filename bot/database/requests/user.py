from typing import Sequence
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bot.database.models.user import User


async def upsert_user(
    session: AsyncSession,
    telegram_id: int,
    full_name: str,
    username: str | None = None,
) -> User:
    """
    Создает пользователя, если его нет в базе, или обновляет его данные
    (username, full_name) при их изменении в Telegram.
    """
    stmt = select(User).where(User.telegram_id == telegram_id)
    user = await session.scalar(stmt)

    if user is not None:
        changed = False
        if user.username != username:
            user.username = username
            changed = True
        if user.full_name != full_name:
            user.full_name = full_name
            changed = True
        if changed:
            await session.commit()
            await session.refresh(user)
        return user

    new_user = User(
        telegram_id=telegram_id,
        username=username,
        full_name=full_name,
    )
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    return new_user


async def get_user_by_tg_id(
    session: AsyncSession,
    telegram_id: int,
) -> User | None:
    """
    Возвращает пользователя по его telegram_id.
    """
    stmt = select(User).where(User.telegram_id == telegram_id)
    return await session.scalar(stmt)


async def get_total_users_count(session: AsyncSession) -> int:
    """
    Возвращает общее количество зарегистрированных пользователей.
    """
    stmt = select(func.count()).select_from(User)
    count = await session.scalar(stmt)
    return count or 0


async def get_all_users(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[User]:
    """
    Возвращает список пользователей с поддержкой пагинации.
    """
    stmt = select(User).order_by(User.id.desc()).limit(limit).offset(offset)
    result = await session.scalars(stmt)
    return result.all()
