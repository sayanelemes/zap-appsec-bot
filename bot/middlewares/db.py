from typing import Any, Awaitable, Callable
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class DbSessionMiddleware(BaseMiddleware):
    """
    Middleware для автоматического внедрения асинхронной сессии SQLAlchemy (AsyncSession)
    в аргументы каждого вызываемого хэндлера.
    
    Сессия передается под ключом 'session':
    async def handler(message: Message, session: AsyncSession): ...
    """

    def __init__(self, session_pool: async_sessionmaker[AsyncSession]) -> None:
        super().__init__()
        self.session_pool = session_pool

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        async with self.session_pool() as session:
            data["session"] = session
            return await handler(event, data)
