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
