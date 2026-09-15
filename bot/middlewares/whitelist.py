import logging
from typing import Any, Awaitable, Callable
from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from bot.config.config import settings

logger = logging.getLogger(__name__)


class WhitelistMiddleware(BaseMiddleware):
    """
    Middleware для проверки доступа пользователей (Admin & Whitelist Hardening).
    Если задан список ALLOWED_USERS или ADMIN_IDS, пользователи, не входящие в эти списки,
    блокируются с информативным сообщением.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user")
        if not user:
            return await handler(event, data)

        cfg = settings
        if not cfg:
            return await handler(event, data)

        # Если задан список администраторов или пользователей, проверяем доступ
        has_restrictions = bool(cfg.ADMIN_IDS) or bool(cfg.ALLOWED_USERS)
        if has_restrictions and not cfg.is_user_allowed(user.id):
            logger.warning(
                "Доступ запрещен (Whitelist): user_id=%s username=@%s",
                user.id,
                user.username,
            )
            if isinstance(event, Message):
                await event.answer(
                    "⛔ <b>Доступ ограничен.</b>\n\n"
                    "Данный бот развернут в режиме защищенного периметра (Private AppSec Auditor).\n"
                    f"Ваш Telegram ID: <code>{user.id}</code> не найден в списке доверенных лиц."
                )
            elif isinstance(event, CallbackQuery):
                await event.answer("⛔ Доступ ограничен политикой безопасности.", show_alert=True)
            return None

        return await handler(event, data)
