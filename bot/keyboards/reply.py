from aiogram.types import KeyboardButton, ReplyKeyboardMarkup
from aiogram.utils.keyboard import ReplyKeyboardBuilder


def get_main_menu_keyboard() -> ReplyKeyboardMarkup:
    """
    Создает основную Reply-клавиатуру нижнего меню бота.
    """
    builder = ReplyKeyboardBuilder()
    builder.row(
        KeyboardButton(text="🛡 Проверить сайт"),
        KeyboardButton(text="🔍 Статус ZAP"),
    )
    builder.row(
        KeyboardButton(text="👤 Мой профиль"),
        KeyboardButton(text="ℹ️ Помощь"),
    )
    return builder.as_markup(
        resize_keyboard=True,
        input_field_placeholder="Выберите действие из меню...",
    )
