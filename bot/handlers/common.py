import html
from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, Message

from bot.keyboards.inline import (
    MenuActionCallback,
    get_welcome_inline_keyboard,
)
from bot.keyboards.reply import get_main_menu_keyboard

common_router = Router(name="common")


# --------------------------------------------------------------------------
# Базовые команды: /start и /help
# --------------------------------------------------------------------------


@common_router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    """
    Обработчик команды /start.
    Выводит приветственное сообщение и стартовое меню.
    """
    user = message.from_user
    if not user:
        return

    user_name = user.full_name or user.first_name or "пользователь"
    welcome_text = (
        f"👋 Привет, <b>{html.escape(user_name)}</b>!\n\n"
        "🛡️ Добро пожаловать в <b>ZAP AppSec AI Auditor</b> — сканер веб-уязвимостей и ИИ-ассистент по безопасности.\n\n"
        "✨ <b>Что умеет бот:</b>\n"
        "• <b>/check &lt;URL&gt;</b> — Запуск быстрого сканирования сайта через <b>OWASP ZAP</b> (Spider + Active Scan)\n"
        "• <b>💡 ИИ-аудит (Gemini)</b> — Понятное объяснение сути рисков простыми словами\n"
        "• <b>🤖 Промпты для AI-агентов</b> — Готовые задачи <code>/goal</code> для Cursor, Antigravity, Claude Code с кодом исправления\n"
        "• <b>📄 Отчеты</b> — Выгрузка полного HTML-отчета ZAP со всеми техническими деталями\n"
        "• <b>/zap_status</b> — Проверка состояния демона сканера\n\n"
        "<i>Отправьте команду <code>/check http://target-site.com</code> или выберите действие в меню:</i>"
    )

    await message.answer(
        text=welcome_text,
        reply_markup=get_main_menu_keyboard(),
    )
    await message.answer(
        text="👇 Дополнительные действия:",
        reply_markup=get_welcome_inline_keyboard(),
    )


@common_router.message(F.text == "🛡 Проверить сайт")
async def cmd_check_hint(message: Message) -> None:
    """
    Подсказка по запуску проверки при нажатии кнопки в меню.
    """
    await message.answer(
        "🛡 <b>Запуск аудита безопасности:</b>\n\n"
        "Отправьте команду с адресом целевого сайта:\n"
        "<code>/check &lt;URL&gt;</code>\n\n"
        "<i>Пример:</i>\n"
        "<code>/check http://testphp.vulnweb.com/listproducts.php?cat=1</code>\n\n"
        "После сканирования нажмите кнопку <b>«💡 Получить аудит и код исправлений от ИИ»</b> для анализа уязвимостей.",
        reply_markup=get_main_menu_keyboard(),
    )


@common_router.message(Command("help"))
@common_router.message(F.text == "ℹ️ Помощь")
async def cmd_help(message: Message) -> None:
    """
    Обработчик команды /help и кнопки 'ℹ️ Помощь'.
    """
    help_text = (
        "📖 <b>Справка ZAP AppSec AI Auditor:</b>\n\n"
        "/start — Главное меню и перезапуск\n"
        "/help — Вывод этого справочного сообщения\n"
        "/zap_status — Проверка статуса подключения к ZAP\n\n"
        "🛡 <b>Аудит безопасности веб-сайтов (OWASP ZAP):</b>\n"
        "/check &lt;URL&gt; — Запуск сканирования и аудита уязвимостей\n"
        "<i>Пример:</i> <code>/check http://testphp.vulnweb.com/listproducts.php?cat=1</code>\n\n"
        "💡 <b>AI-аудит (Gemini):</b>\n"
        "• ИИ-ассистент работает в связке со сканером.\n"
        "• После выполнения <code>/check</code> нажмите кнопку <b>«💡 Получить аудит и код исправлений от ИИ»</b>, чтобы нейросеть сгенерировала простое объяснение рисков и готовый промпт для AI-агентов кодогенерации (/goal).\n\n"
        "Кнопки нижнего меню:\n"
        "• <b>🛡 Проверить сайт</b> — вызов сканирования\n"
        "• <b>🔍 Статус ZAP</b> — проверка доступности сканера\n"
        "• <b>👤 Мой профиль</b> — учетная запись\n"
        "• <b>ℹ️ Помощь</b> — данная справка"
    )
    await message.answer(text=help_text, reply_markup=get_main_menu_keyboard())


# --------------------------------------------------------------------------
# Профиль пользователя
# --------------------------------------------------------------------------


@common_router.message(F.text == "👤 Мой профиль")
async def cmd_profile(message: Message) -> None:
    """
    Выводит информацию о текущем пользователе Telegram.
    """
    user = message.from_user
    if not user:
        return

    profile_text = (
        "👤 <b>Ваш профиль в Telegram:</b>\n\n"
        f"• <b>Telegram ID:</b> <code>{user.id}</code>\n"
        f"• <b>Username:</b> @{html.escape(user.username or 'не указан')}\n"
        f"• <b>Имя:</b> {html.escape(user.full_name)}\n"
        "• <b>Режим работы:</b> Stateless Fast Scanner (без БД)"
    )
    await message.answer(text=profile_text)


# --------------------------------------------------------------------------
# Обработка Inline кнопок через CallbackData
# --------------------------------------------------------------------------


@common_router.callback_query(MenuActionCallback.filter(F.action == "features"))
async def callback_features(callback: CallbackQuery) -> None:
    """
    Показывает возможности сканера.
    """
    text = (
        "🛡️ <b>Возможности ZAP AppSec AI Auditor:</b>\n\n"
        "• <b>OWASP ZAP Fast Scan:</b> Spider + активный поиск уязвимостей (SQLi, XSS, CSRF, RCE, IDOR).\n"
        "• <b>Двухблочный ИИ-аудит (Gemini):</b> Простое объяснение рисков + пошаговый промпт с кодом для Cursor / Claude Code / Antigravity.\n"
        "• <b>Детальные HTML-отчеты:</b> Мгновенная генерация полного отчета ZAP файлом.\n"
        "• <b>Автономность и скорость:</b> Асинхронный aiogram 3.x, работа без БД, защита от спама."
    )
    if callback.message:
        await callback.message.answer(text)
    await callback.answer()


@common_router.callback_query(MenuActionCallback.filter(F.action == "stats"))
async def callback_stats(callback: CallbackQuery) -> None:
    """
    Выводит статус режима работы бота.
    """
    await callback.answer(
        text="⚡ Бот работает в быстром автономном режиме (без БД).",
        show_alert=True,
    )


@common_router.callback_query(MenuActionCallback.filter(F.action == "close"))
async def callback_close(callback: CallbackQuery) -> None:
    """
    Удаляет сообщение с инлайн-кнопками.
    """
    if callback.message:
        await callback.message.delete()
    await callback.answer()
