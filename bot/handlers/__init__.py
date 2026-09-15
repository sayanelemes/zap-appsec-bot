from aiogram import Router
from aiogram.types import Message

from bot.handlers.common import common_router
from bot.handlers.errors import errors_router
from bot.handlers.github_audit import github_sast_router
from bot.handlers.zap_scan import zap_router
from bot.keyboards.reply import get_main_menu_keyboard


def get_root_router() -> Router:
    """
    Объединяет все дочерние роутеры приложения в единый корневой роутер в строгом порядке:
    1. errors_router: глобальный перехват ошибок
    2. common_router: системные команды (/start, /help, анкета FSM, кнопки меню)
    3. github_sast_router: SAST-аудит зависимостей GitHub (OSV.dev CVE/CVSS)
    4. zap_router: DAST сканирование безопасности веб-приложений через OWASP ZAP (/check) и вызов AI-аудита
    5. fallback_router: информативная заглушка для текстовых сообщений
    """
    root_router = Router(name="root")
    fallback_router = Router(name="fallback")

    # Заглушка для любых текстовых/медиа сообщений вне проверок
    @fallback_router.message()
    async def global_fallback(message: Message) -> None:
        await message.answer(
            "🛡️ <b>ZAP AppSec AI Auditor</b> поддерживает два режима анализа безопасности:\n\n"
            "1️⃣ <b>DAST: Проверка веб-сайта (OWASP ZAP):</b>\n"
            "Отправьте команду:\n"
            "<code>/check &lt;URL&gt;</code>\n"
            "<i>(или просто пришлите ссылку на веб-сайт)</i>\n\n"
            "2️⃣ <b>SAST: Аудит зависимостей репозитория GitHub (OSV.dev CVE/CVSS):</b>\n"
            "Отправьте ссылку на публичный GitHub репозиторий:\n"
            "<code>https://github.com/pallets/jinja</code>\n"
            "<i>(проверяются requirements.txt и package.json)</i>\n\n"
            "Напишите /help для подробной справки.",
            reply_markup=get_main_menu_keyboard(),
        )

    root_router.include_router(errors_router)
    root_router.include_router(common_router)
    root_router.include_router(github_sast_router)
    root_router.include_router(zap_router)
    root_router.include_router(fallback_router)

    return root_router


__all__ = [
    "get_root_router",
    "common_router",
    "errors_router",
    "github_sast_router",
    "zap_router",
]
