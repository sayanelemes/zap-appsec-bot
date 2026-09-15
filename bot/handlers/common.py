import html
from aiogram import F, Router
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message
from sqlalchemy.ext.asyncio import AsyncSession

from bot.database.requests import (
    get_total_users_count,
    get_user_by_tg_id,
    upsert_user,
)
from bot.keyboards.inline import (
    MenuActionCallback,
    get_welcome_inline_keyboard,
)
from bot.keyboards.reply import (
    get_cancel_keyboard,
    get_main_menu_keyboard,
)
from bot.states.states import ProfileForm

common_router = Router(name="common")


# --------------------------------------------------------------------------
# Базовые команды: /start и /help
# --------------------------------------------------------------------------


@common_router.message(CommandStart())
async def cmd_start(message: Message, session: AsyncSession) -> None:
    """
    Обработчик команды /start.
    Регистрирует или обновляет пользователя в БД и выводит стартовое меню.
    """
    user = message.from_user
    if not user:
        return

    # Сохраняем пользователя в БД через сессию
    db_user = await upsert_user(
        session=session,
        telegram_id=user.id,
        username=user.username,
        full_name=user.full_name,
    )

    welcome_text = (
        f"👋 Привет, <b>{html.escape(db_user.full_name)}</b>!\n\n"
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
        "/cancel — Прерывание текущего ввода (FSM)\n\n"
        "🛡 <b>Аудит безопасности веб-сайтов (OWASP ZAP):</b>\n"
        "/check &lt;URL&gt; — Запуск сканирования и аудита уязвимостей\n"
        "<i>Пример:</i> <code>/check http://testphp.vulnweb.com/listproducts.php?cat=1</code>\n"
        "/zap_status — Проверка статуса подключения к ZAP\n\n"
        "💡 <b>AI-аудит (Gemini):</b>\n"
        "• ИИ-ассистент работает в связке со сканером.\n"
        "• После выполнения <code>/check</code> нажмите кнопку <b>«💡 Получить аудит и код исправлений от ИИ»</b>, чтобы нейросеть сгенерировала простое объяснение рисков и готовый промпт для AI-агентов кодогенерации (/goal).\n\n"
        "Кнопки нижнего меню:\n"
        "• <b>🛡 Проверить сайт</b> — вызов сканирования\n"
        "• <b>ℹ️ Помощь</b> — данная справка\n"
        "• <b>👤 Мой профиль</b> — учетная запись в БД\n"
        "• <b>📝 Заполнить анкету</b> — анкета пользователя"
    )
    await message.answer(text=help_text, reply_markup=get_main_menu_keyboard())



# --------------------------------------------------------------------------
# Профиль пользователя
# --------------------------------------------------------------------------


@common_router.message(F.text == "👤 Мой профиль")
async def cmd_profile(message: Message, session: AsyncSession) -> None:
    """
    Выводит информацию о текущем пользователе из базы данных.
    """
    user = message.from_user
    if not user:
        return

    db_user = await get_user_by_tg_id(session, user.id)
    if not db_user:
        await message.answer("Пользователь не найден в базе данных. Введите /start.")
        return

    created_str = db_user.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    profile_text = (
        "👤 <b>Ваш профиль в БД:</b>\n\n"
        f"• <b>Внутренний ID:</b> <code>{db_user.id}</code>\n"
        f"• <b>Telegram ID:</b> <code>{db_user.telegram_id}</code>\n"
        f"• <b>Username:</b> @{html.escape(db_user.username or 'не указан')}\n"
        f"• <b>Имя:</b> {html.escape(db_user.full_name)}\n"
        f"• <b>Дата регистрации:</b> {created_str}"
    )
    await message.answer(text=profile_text)


# --------------------------------------------------------------------------
# FSM: Машина состояний (Анкета профиля)
# --------------------------------------------------------------------------


@common_router.message(Command("cancel"))
@common_router.message(F.text == "❌ Отмена", StateFilter("*"))
async def cmd_cancel_fsm(message: Message, state: FSMContext) -> None:
    """
    Сброс текущего состояния FSM при нажатии кнопки 'Отмена' или команде /cancel.
    """
    current_state = await state.get_state()
    if current_state is None:
        await message.answer(
            "Нет активных действий для отмены.",
            reply_markup=get_main_menu_keyboard(),
        )
        return

    await state.clear()
    await message.answer(
        "Действие отменено.",
        reply_markup=get_main_menu_keyboard(),
    )


@common_router.message(F.text == "📝 Заполнить анкету", StateFilter(None))
async def start_fsm_profile(message: Message, state: FSMContext) -> None:
    """
    Запуск сценария заполнения анкеты (шаг 1: ввод имени).
    """
    await state.set_state(ProfileForm.waiting_for_name)
    await message.answer(
        "📝 <b>Шаг 1 из 3:</b> Как вас зовут?\n\n"
        "Для отмены нажмите кнопку ниже.",
        reply_markup=get_cancel_keyboard(),
    )


@common_router.message(ProfileForm.waiting_for_name, F.text)
async def fsm_process_name(message: Message, state: FSMContext) -> None:
    """
    Шаг 2: валидация имени и запрос возраста.
    """
    name = (message.text or "").strip()
    if len(name) < 2 or len(name) > 50:
        await message.answer("Имя должно содержать от 2 до 50 символов. Попробуйте еще раз:")
        return

    await state.update_data(name=name)
    await state.set_state(ProfileForm.waiting_for_age)
    await message.answer("🔢 <b>Шаг 2 из 3:</b> Сколько вам полных лет?")


@common_router.message(ProfileForm.waiting_for_age, F.text)
async def fsm_process_age(message: Message, state: FSMContext) -> None:
    """
    Шаг 3: валидация возраста и запрос информации о себе.
    """
    text = (message.text or "").strip()
    if not text.isdigit() or not (1 <= int(text) <= 120):
        await message.answer("Пожалуйста, введите корректный возраст (число от 1 до 120):")
        return

    await state.update_data(age=int(text))
    await state.set_state(ProfileForm.waiting_for_bio)
    await message.answer("✍️ <b>Шаг 3 из 3:</b> Напишите пару слов о себе:")


@common_router.message(ProfileForm.waiting_for_bio, F.text)
async def fsm_process_bio(message: Message, state: FSMContext) -> None:
    """
    Финал FSM: сохранение данных, сброс состояния и вывод результата.
    """
    bio = (message.text or "").strip()
    data = await state.get_data()
    name = data.get("name")
    age = data.get("age")

    await state.clear()

    summary_text = (
        "✅ <b>Анкета успешно сохранена!</b>\n\n"
        f"• <b>Имя:</b> {html.escape(str(name))}\n"
        f"• <b>Возраст:</b> {age}\n"
        f"• <b>О себе:</b> {html.escape(bio)}"
    )

    await message.answer(text=summary_text, reply_markup=get_main_menu_keyboard())


# --------------------------------------------------------------------------
# Обработка Inline кнопок через CallbackData
# --------------------------------------------------------------------------


@common_router.callback_query(MenuActionCallback.filter(F.action == "features"))
async def callback_features(callback: CallbackQuery) -> None:
    """
    Показывает список фич архитектуры шаблона.
    """
    text = (
        "🛡️ <b>Возможности ZAP AppSec AI Auditor:</b>\n\n"
        "• <b>OWASP ZAP Fast Scan:</b> Spider + активный поиск уязвимостей (SQLi, XSS, CSRF, RCE, IDOR).\n"
        "• <b>Двухблочный ИИ-аудит (Gemini):</b> Простое объяснение рисков + пошаговый промпт с кодом для Cursor / Claude Code / Antigravity.\n"
        "• <b>Детальные HTML-отчеты:</b> Мгновенная генерация полного отчета ZAP файлом.\n"
        "• <b>Автономность и надежность:</b> Асинхронный aiogram 3.x, сессии SQLAlchemy 2.0, защита от спама."
    )
    if callback.message:
        await callback.message.answer(text)
    await callback.answer()


@common_router.callback_query(MenuActionCallback.filter(F.action == "stats"))
async def callback_stats(callback: CallbackQuery, session: AsyncSession) -> None:
    """
    Запрашивает из базы данных количество пользователей и выводит alert.
    """
    count = await get_total_users_count(session)
    await callback.answer(
        text=f"👥 Всего пользователей в базе: {count}",
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

