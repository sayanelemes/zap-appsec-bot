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
    3. zap_router: сканирование безопасности веб-приложений через OWASP ZAP (/check) и вызов AI-аудита
    4. fallback_router: информативная заглушка для текстовых сообщений (прямой чат с ИИ отключен)
    """
    root_router = Router(name="root")
    fallback_router = Router(name="fallback")

    # Заглушка для любых текстовых/медиа сообщений вне команды /check
    @fallback_router.message()
    async def global_fallback(message: Message) -> None:
        await message.answer(
            "🛡️ <b>ZAP AppSec AI Auditor</b> работает исключительно в режиме аудита безопасности веб-сайтов.\n\n"
            "Прямой чат с нейросетью отключен — ИИ анализирует уязвимости и генерирует промпты для исправления после сканирования сайта.\n\n"
            "Отправьте команду для проверки целевого ресурса:\n"
            "<code>/check &lt;URL&gt;</code>\n\n"
            "<i>Пример:</i>\n"
            "<code>/check http://testphp.vulnweb.com/listproducts.php?cat=1</code>\n\n"
            "Напишите /help для подробностей.",
            reply_markup=get_main_menu_keyboard(),
        )

    root_router.include_router(errors_router)
    root_router.include_router(common_router)
    root_router.include_router(zap_router)
    root_router.include_router(fallback_router)

    return root_router


__all__ = ["get_root_router", "common_router", "errors_router", "zap_router"]
