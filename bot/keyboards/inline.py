from aiogram.filters.callback_data import CallbackData
from aiogram.types import InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder


class MenuActionCallback(CallbackData, prefix="menu"):
    """
    Фабрика данных для инлайн-кнопок главного меню.
    Обеспечивает строгую типизацию payload коллбэка.
    """

    action: str


def get_welcome_inline_keyboard() -> InlineKeyboardMarkup:
    """
    Создает Inline-клавиатуру для стартового сообщения.
    """
    builder = InlineKeyboardBuilder()

    builder.button(
        text="⚡ Возможности шаблона",
        callback_data=MenuActionCallback(action="features"),
    )
    builder.button(
        text="📊 Статистика БД",
        callback_data=MenuActionCallback(action="stats"),
    )
    builder.button(
        text="🗑️ Закрыть",
        callback_data=MenuActionCallback(action="close"),
    )

    # Расположение: 2 кнопки в первой строке, 1 кнопка во второй
    builder.adjust(2, 1)
    return builder.as_markup()


class ZapAiAuditCallback(CallbackData, prefix="zap_ai"):
    """
    Фабрика данных для кнопки запроса AI-аудита уязвимостей.
    """
    cache_id: str


def get_ai_audit_keyboard(
    cache_id: str,
    text: str = "💡 Получить аудит и код исправлений от ИИ",
) -> InlineKeyboardMarkup:
    """
    Создает клавиатуру с кнопкой запроса AI-рекомендаций и кода исправлений.
    """
    builder = InlineKeyboardBuilder()
    builder.button(
        text=text,
        callback_data=ZapAiAuditCallback(cache_id=cache_id),
    )
    return builder.as_markup()


class ZapScanModeCallback(CallbackData, prefix="zap_mode"):
    """
    Коллбэк выбора типа/глубины сканирования (DAST).
    """
    mode: str       # "passive", "fast", "full", "cancel"
    target_id: str  # id записи в FSM/кэше


def get_scan_mode_keyboard(target_id: str) -> InlineKeyboardMarkup:
    """
    Клавиатура выбора глубины сканирования:
    1) 🛡 Пассивный (Passive, 5-10 сек)
    2) ⚡ Быстрый (Fast, 90 сек)
    3) 🔍 Глубокий (Full, 5-10 мин)
    4) ❌ Отмена
    """
    builder = InlineKeyboardBuilder()
    builder.button(
        text="🛡 Пассивный (5-10 сек)",
        callback_data=ZapScanModeCallback(mode="passive", target_id=target_id),
    )
    builder.button(
        text="⚡ Быстрый (90 сек)",
        callback_data=ZapScanModeCallback(mode="fast", target_id=target_id),
    )
    builder.button(
        text="🔍 Глубокий (5-10 мин)",
        callback_data=ZapScanModeCallback(mode="full", target_id=target_id),
    )
    builder.button(
        text="❌ Отмена",
        callback_data=ZapScanModeCallback(mode="cancel", target_id=target_id),
    )
    builder.adjust(1)
    return builder.as_markup()


class ZapScanStopCallback(CallbackData, prefix="zap_stop"):
    """
    Коллбэк принудительной остановки сканирования.
    """
    token: str


def get_scan_stop_keyboard(token: str) -> InlineKeyboardMarkup:
    """
    Клавиатура со статусом выполнения и кнопкой остановки сканирования.
    """
    builder = InlineKeyboardBuilder()
    builder.button(
        text="🛑 Остановить сканирование",
        callback_data=ZapScanStopCallback(token=token),
    )
    return builder.as_markup()
