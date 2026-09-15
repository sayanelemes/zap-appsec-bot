from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from bot.database.models.dialog import DialogMessage


async def save_dialog_message(
    session: AsyncSession,
    user_id: int,
    role: str,
    content: str,
) -> DialogMessage:
    """
    Сохраняет реплику диалога (роль 'user' или 'model') в базу данных.
    """
    msg = DialogMessage(
        user_id=user_id,
        role=role,
        content=content,
    )
    session.add(msg)
    await session.commit()
    await session.refresh(msg)
    return msg


async def get_dialog_history(
    session: AsyncSession,
    user_id: int,
    limit: int = 10,
) -> list[DialogMessage]:
    """
    Возвращает последние N сообщений диалога пользователя в хронологическом порядке (от старых к новым).
    """
    stmt = (
        select(DialogMessage)
        .where(DialogMessage.user_id == user_id)
        .order_by(DialogMessage.id.desc())
        .limit(limit)
    )
    result = await session.scalars(stmt)
    messages = list(result.all())
    # Разворачиваем, чтобы история шла в естественном порядке диалога (старые -> новые)
    messages.reverse()
    return messages


async def clear_dialog_history(
    session: AsyncSession,
    user_id: int,
) -> int:
    """
    Очищает всю историю сообщений пользователя и возвращает количество удаленных записей.
    """
    stmt = (
        delete(DialogMessage)
        .where(DialogMessage.user_id == user_id)
    )
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount or 0
