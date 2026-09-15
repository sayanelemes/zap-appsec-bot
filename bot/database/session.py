import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger(__name__)


def create_engine(url: str, echo: bool = False) -> AsyncEngine:
    """
    Создает асинхронный движок SQLAlchemy.
    Автоматически адаптирует параметры под SQLite или PostgreSQL.
    """
    is_sqlite = url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}

    return create_async_engine(
        url=url,
        echo=echo,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def create_session_pool(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """
    Создает фабрику сессий с параметром expire_on_commit=False.
    """
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def check_db_connection(engine: AsyncEngine) -> bool:
    """
    Проверяет доступность базы данных при запуске приложения.
    """
    from sqlalchemy import text

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Подключение к базе данных успешно установлено.")
        return True
    except Exception as e:
        logger.error("Ошибка подключения к базе данных: %s", e)
        raise
