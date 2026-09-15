import html
from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.keyboards.inline import (
    MenuActionCallback,
    get_welcome_inline_keyboard,
)
from bot.keyboards.reply import get_main_menu_keyboard
from bot.utils.ui import update_screen

common_router = Router(name="common")


# --------------------------------------------------------------------------
# Базовые команды: /start и /help
# --------------------------------------------------------------------------


@common_router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    """
    Обработчик команды /start.
    Выводит приветственное сообщение со всеми возможностями бота и стартовое меню.
    Удаляет входящую команду и предыдущее сообщение бота для чистого экрана.
    """
    user = message.from_user
    if not user:
        return

    user_name = user.full_name or user.first_name or "пользователь"
    welcome_text = (
        f"👋 Привет, <b>{html.escape(user_name)}</b>!\n\n"
        "🛡️ Добро пожаловать в <b>ZAP AppSec AI Auditor</b> — комплексный сканер веб-уязвимостей и ИИ-ассистент по безопасности.\n\n"
        "✨ <b>Ключевые возможности бота:</b>\n\n"
        "1️⃣ <b>Динамический анализ (DAST / OWASP ZAP):</b>\n"
        "• Отправьте ссылку на сайт или команду <code>/check &lt;URL&gt;</code>\n"
        "• <b>3 уровня глубины анализа:</b>\n"
        "  - 🛡 <b>Пассивный</b> (5–10 сек): аудит заголовков безопасности, Cookies, CSP без инъекций\n"
        "  - ⚡ <b>Быстрый</b> (90 сек): Spider + Active Scan с лимитом времени\n"
        "  - 🔍 <b>Глубокий</b> (5–10 мин): глубокий краулинг и полное сканирование\n"
        "• <b>🛑 Кнопка 'Стоп':</b> экстренная остановка процесса в один клик с возвратом к выбору режимов\n"
        "• <b>📄 HTML-отчет:</b> автоматическая выгрузка полного технического отчета ZAP файлом в чат\n\n"
        "2️⃣ <b>Статический анализ зависимостей (SAST / GitHub + OSV.dev):</b>\n"
        "• Отправьте ссылку на публичный GitHub-репозиторий: <code>https://github.com/owner/repo</code>\n"
        "• Мгновенный парсинг <code>requirements.txt</code> и <code>package.json</code> без клонирования\n"
        "• Отображение CVE/GHSA, точный расчет баллов CVSS и сопоставление уровней риска (Critical/High/Medium/Low)\n"
        "• Рекомендация безопасных версий для обновления (Fixed in: >= x.x.x)\n\n"
        "3️⃣ <b>Двухэтапный ИИ-аудит (Google Gemini):</b>\n"
        "• Простое объяснение сути каждой найденной проблемы и реалистичного сценария атаки\n"
        "• Однокликовые задачи <code>/goal</code> для AI-агентов кодогенерации (Cursor, Antigravity, Claude Code) с кодом исправления\n\n"
        "🔒 <b>4️⃣ Защита периметра (Hardening):</b>\n"
        "• Встроенный SSRF-фильтр с DNS-резолвом (блокировка RFC 1918, 127.0.0.0/8, Cloud Metadata)\n"
        "• Авторизация доступа (Admin Whitelist)\n\n"
        "<i>Отправьте ссылку на сайт или GitHub-репозиторий для начала аудита:</i>"
    )

    await message.answer(
        text=welcome_text,
        reply_markup=get_main_menu_keyboard(),
        parse_mode="HTML",
    )
    await state.update_data(last_bot_msg_id=None, extra_msg_ids=[])


@common_router.message(F.text == "🛡 Проверить сайт")
async def cmd_check_hint(message: Message, state: FSMContext) -> None:
    """
    Подсказка по запуску проверки при нажатии кнопки в меню.
    """
    text = (
        "🛡 <b>Запуск аудита безопасности:</b>\n\n"
        "1️⃣ <b>DAST (OWASP ZAP):</b>\n"
        "Отправьте команду или ссылку на сайт:\n"
        "<code>/check &lt;URL&gt;</code>\n"
        "<i>Пример:</i> <code>/check http://testphp.vulnweb.com</code>\n"
        "Вам будет предложен выбор режима: <b>Пассивный</b>, <b>Быстрый</b> или <b>Глубокий</b>, а также кнопка экстренной остановки (Стоп).\n\n"
        "2️⃣ <b>SAST (GitHub + OSV.dev):</b>\n"
        "Отправьте ссылку на репозиторий GitHub:\n"
        "<code>https://github.com/pallets/jinja</code>\n"
        "Бот проанализирует зависимости (Python / Node.js) на известные CVE и баллы CVSS."
    )
    await update_screen(
        event=message,
        state=state,
        text=text,
        reply_markup=get_main_menu_keyboard(),
    )


@common_router.message(Command("help"))
@common_router.message(F.text == "ℹ️ Помощь")
async def cmd_help(message: Message, state: FSMContext) -> None:
    """
    Обработчик команды /help и кнопки 'ℹ️ Помощь'.
    """
    help_text = (
        "📖 <b>Справка ZAP AppSec AI Auditor:</b>\n\n"
        "/start — Главное меню и статус\n"
        "/help — Вывод этого справочного сообщения\n"
        "/zap_status — Проверка статуса демона OWASP ZAP\n\n"
        "🛡 <b>1. Динамический анализ (DAST / OWASP ZAP):</b>\n"
        "• <code>/check &lt;URL&gt;</code> или прямая ссылка на сайт\n"
        "• <b>Выбор глубины:</b>\n"
        "  - <i>Пассивный</i> (5–10 сек): заголовки, куки, CSP без инъекций\n"
        "  - <i>Быстрый</i> (90 сек): Spider + Active Scan с лимитом времени\n"
        "  - <i>Глубокий</i> (5–10 мин): полный краулинг и сканирование\n"
        "• <b>🛑 Кнопка 'Стоп':</b> мгновенная остановка паука и сканера с возвратом к выбору режимов\n"
        "• <b>💡 ИИ-аудит (Gemini):</b> карточки уязвимостей и готовые задачи <code>/goal</code> для AI-агентов\n\n"
        "📦 <b>2. Статический анализ зависимостей (SAST / OSV.dev):</b>\n"
        "• Отправьте ссылку на GitHub: <code>https://github.com/owner/repo</code>\n"
        "• Проверка <code>requirements.txt</code> и <code>package.json</code>\n"
        "• Отображение CVE/GHSA, числового балла CVSS (Critical/High/Medium/Low) и безопасной версии (Fixed in)\n\n"
        "🔒 <b>3. Защита периметра (Hardening):</b>\n"
        "• <b>SSRF-фильтр:</b> блокировка сканирования локальных сетей (RFC 1918, 127.0.0.0/8, 169.254.169.254)\n"
        "• <b>Admin Whitelist:</b> проверка доступа по списку <code>ALLOWED_USERS</code>"
    )
    await update_screen(
        event=message,
        state=state,
        text=help_text,
        reply_markup=get_main_menu_keyboard(),
    )


# --------------------------------------------------------------------------
# Профиль пользователя
# --------------------------------------------------------------------------


@common_router.message(F.text == "👤 Мой профиль")
async def cmd_profile(message: Message, state: FSMContext) -> None:
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
        f"• <b>Имя:</b> {html.escape(user.full_name)}"
    )
    await update_screen(
        event=message,
        state=state,
        text=profile_text,
        reply_markup=get_main_menu_keyboard(),
    )


# --------------------------------------------------------------------------
# Обработка Inline кнопок через CallbackData
# --------------------------------------------------------------------------


@common_router.callback_query(MenuActionCallback.filter(F.action == "features"))
async def callback_features(callback: CallbackQuery, state: FSMContext) -> None:
    """
    Показывает возможности сканера на месте.
    """
    text = (
        "🛡️ <b>Возможности ZAP AppSec AI Auditor:</b>\n\n"
        "• <b>OWASP ZAP Fast Scan:</b> Spider + активный поиск уязвимостей (SQLi, XSS, CSRF, RCE, IDOR).\n"
        "• <b>Двухблочный ИИ-аудит (Gemini):</b> Простое объяснение рисков + пошаговый промпт с кодом для Cursor / Claude Code / Antigravity.\n"
        "• <b>Детальные HTML-отчеты:</b> Мгновенная генерация полного отчета ZAP файлом.\n"
        "• <b>Автономность и скорость:</b> Асинхронный aiogram 3.x, работа без БД, защита от спама."
    )
    await update_screen(
        event=callback,
        state=state,
        text=text,
    )


@common_router.callback_query(MenuActionCallback.filter(F.action == "stats"))
async def callback_stats(callback: CallbackQuery) -> None:
    """
    Выводит статус режима работы бота во всплывающем окне.
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
        try:
            await callback.message.delete()
        except Exception:
            pass
    await callback.answer()
