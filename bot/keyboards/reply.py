from aiogram.types import KeyboardButton, ReplyKeyboardMarkup
from aiogram.utils.keyboard import ReplyKeyboardBuilder


def get_main_menu_keyboard() -> ReplyKeyboardMarkup:
    """
    Создает основную Reply-клавиатуру нижнего меню бота.
    """
    builder = ReplyKeyboardBuilder()
    builder.row(
        KeyboardButton(text="📝 Заполнить анкету"),
        KeyboardButton(text="👤 Мой профиль"),
    )
    builder.row(
        KeyboardButton(text="🧹 Новый диалог"),
        KeyboardButton(text="ℹ️ Помощь"),
    )
    return builder.as_markup(

        resize_keyboard=True,
        input_field_placeholder="Выберите действие из меню...",
    )


def get_cancel_keyboard() -> ReplyKeyboardMarkup:
    """
    Клавиатура с кнопкой отмены для FSM-сценариев.
    """
    builder = ReplyKeyboardBuilder()
    builder.button(text="❌ Отмена")
    return builder.as_markup(
        resize_keyboard=True,
        one_time_keyboard=True,
    )
