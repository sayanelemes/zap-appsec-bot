import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, Tuple
from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject


class ThrottlingMiddleware(BaseMiddleware):
    """
    Middleware для ограничения частоты запросов (Rate Limiting / Антиспам).
    Защищает бота от флуда командами и кликов по кнопкам.
    """

    def __init__(self, rate_limit: float = 0.5) -> None:
        super().__init__()
        self.rate_limit = rate_limit
        # Хранилище: user_id -> (последнее_время_запроса, было_ли_предупреждение)
        self._user_timestamps: Dict[int, Tuple[float, bool]] = {}

    def _cleanup_old_records(self, now: float) -> None:
        """Очищает устаревшие записи, если словарь превышает 5000 элементов."""
        if len(self._user_timestamps) > 5000:
            threshold = now - (self.rate_limit * 10)
            self._user_timestamps = {
                uid: val
                for uid, val in self._user_timestamps.items()
                if val[0] > threshold
            }

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        # Извлекаем пользователя из события (Message или CallbackQuery)
        user = data.get("event_from_user")
        if not user:
            return await handler(event, data)

        now = time.monotonic()
        user_id = user.id

        if user_id in self._user_timestamps:
            last_time, warned = self._user_timestamps[user_id]
            delta = now - last_time

            if delta < self.rate_limit:
                # Всегда удаляем спам-сообщения от пользователя, чтобы чат не засорялся
                if isinstance(event, Message):
                    try:
                        await event.delete()
                    except Exception:
                        pass

                # Если спам продолжается, но предупреждение уже было - молча игнорируем
                if not warned:
                    self._user_timestamps[user_id] = (now, True)
                    if isinstance(event, Message):
                        try:
                            warn_msg = await event.answer("⚠️ <b>Слишком быстро!</b> Пожалуйста, подождите секунду.", parse_mode="HTML")
                            async def _auto_delete(msg: Message) -> None:
                                await asyncio.sleep(2.0)
                                try:
                                    await msg.delete()
                                except Exception:
                                    pass
                            asyncio.create_task(_auto_delete(warn_msg))
                        except Exception:
                            pass
                    elif isinstance(event, CallbackQuery):
                        await event.answer("⚠️ Не кликайте так часто!", show_alert=False)
                return None

        # Разрешаем выполнение и сохраняем текущее время
        self._user_timestamps[user_id] = (now, False)
        self._cleanup_old_records(now)

        return await handler(event, data)
