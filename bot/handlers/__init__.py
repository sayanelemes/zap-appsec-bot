from aiogram import Router
from aiogram.types import Message

from bot.handlers.ai_chat import ai_router
from bot.handlers.common import common_router
from bot.handlers.errors import errors_router
from bot.handlers.zap_scan import zap_router
from bot.keyboards.reply import get_main_menu_keyboard


def get_root_router() -> Router:
    """
    Объединяет все дочерние роутеры приложения в единый корневой роутер в строгом порядке:
    1. errors_router: глобальный перехват ошибок
    2. common_router: системные команды (/start, /help, анкета FSM, кнопки меню)
    3. zap_router: сканирование безопасности веб-приложений через OWASP ZAP (/check)
    4. ai_router: обработка свободного текста, фото, голосовых и команды /reset через Gemini
    5. fallback_router: заглушка для нераспознанных типов сообщений
    """
    root_router = Router(name="root")
    fallback_router = Router(name="fallback")

    # Заглушка для любых других необработанных типов сообщений
    @fallback_router.message()
    async def global_fallback(message: Message) -> None:
        await message.answer(
            "🤖 Я понимаю текстовые вопросы, фото и голосовые сообщения через Gemini, "
            "команду аудита сайтов /check <URL>, а также команды из меню. "
            "Напишите /help для подробностей.",
            reply_markup=get_main_menu_keyboard(),
        )

    root_router.include_router(errors_router)
    root_router.include_router(common_router)
    root_router.include_router(zap_router)
    root_router.include_router(ai_router)
    root_router.include_router(fallback_router)

    return root_router


__all__ = ["get_root_router", "common_router", "errors_router", "ai_router", "zap_router"]
