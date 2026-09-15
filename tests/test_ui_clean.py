import unittest
from unittest.mock import AsyncMock, MagicMock
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from bot.utils.ui import safe_edit_message, track_extra_message, update_screen


class TestCleanUiHelper(unittest.IsolatedAsyncioTestCase):
    """Тестирование функционала Clean UI, сохранения /start и HTML-рендеринга."""

    async def test_update_screen_with_message_edits_in_place(self):
        """Проверка in-place редактирования существующего экрана без дерганий и удалений."""
        state = AsyncMock(spec=FSMContext)
        state.get_data.return_value = {
            "last_bot_msg_id": 100,
        }

        edited_bot_msg = MagicMock()
        edited_bot_msg.__class__ = Message
        edited_bot_msg.message_id = 100

        user_msg = MagicMock()
        user_msg.__class__ = Message
        user_msg.chat = MagicMock()
        user_msg.chat.id = 12345
        user_msg.delete = AsyncMock()
        user_msg.bot = MagicMock()
        user_msg.bot.edit_message_text = AsyncMock(return_value=edited_bot_msg)

        res = await update_screen(
            event=user_msg,
            state=state,
            text="Обновленный рабочий экран",
        )

        self.assertEqual(res, edited_bot_msg)
        # Входящее сообщение пользователя НЕ удаляется
        user_msg.delete.assert_not_awaited()
        # Старое сообщение бота редактируется на месте с parse_mode="HTML"
        user_msg.bot.edit_message_text.assert_awaited_once_with(
            chat_id=12345,
            message_id=100,
            text="Обновленный рабочий экран",
            reply_markup=None,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

    async def test_update_screen_with_message_sends_new_when_no_active(self):
        """Проверка отправки новой карточки с parse_mode='HTML', если активного экрана еще нет."""
        state = AsyncMock(spec=FSMContext)
        state.get_data.return_value = {
            "last_bot_msg_id": None,
        }

        new_bot_msg = MagicMock()
        new_bot_msg.__class__ = Message
        new_bot_msg.message_id = 250

        user_msg = MagicMock()
        user_msg.__class__ = Message
        user_msg.chat = MagicMock()
        user_msg.chat.id = 12345
        user_msg.answer = AsyncMock(return_value=new_bot_msg)

        res = await update_screen(
            event=user_msg,
            state=state,
            text="Первый экран после /start",
        )

        self.assertEqual(res, new_bot_msg)
        user_msg.answer.assert_awaited_once_with(
            text="Первый экран после /start",
            reply_markup=None,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
        state.update_data.assert_awaited_once_with(last_bot_msg_id=250)

    async def test_update_screen_with_callback_query_success(self):
        """Проверка редактирования текущего экрана на месте при нажатии инлайн-кнопки с parse_mode='HTML'."""
        state = AsyncMock(spec=FSMContext)

        edited_msg = MagicMock()
        edited_msg.__class__ = Message
        edited_msg.message_id = 150

        target_msg = MagicMock()
        target_msg.__class__ = Message
        target_msg.edit_text = AsyncMock(return_value=edited_msg)

        callback = MagicMock(spec=CallbackQuery)
        callback.message = target_msg
        callback.answer = AsyncMock()

        res = await update_screen(
            event=callback,
            state=state,
            text="<b>Жирный текст</b> и <code>код</code>",
        )

        self.assertEqual(res, edited_msg)
        # Снятие индикатора загрузки с кнопки
        callback.answer.assert_awaited_once()
        # Редактирование на месте с parse_mode='HTML'
        target_msg.edit_text.assert_awaited_once_with(
            text="<b>Жирный текст</b> и <code>код</code>",
            reply_markup=None,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
        # Обновление ID в FSM
        state.update_data.assert_awaited_once_with(last_bot_msg_id=150)

    async def test_update_screen_callback_message_not_modified(self):
        """Проверка устойчивости к ошибке 'message is not modified' при CallbackQuery."""
        state = AsyncMock(spec=FSMContext)

        target_msg = MagicMock()
        target_msg.__class__ = Message
        method_mock = MagicMock()
        target_msg.edit_text = AsyncMock(
            side_effect=TelegramBadRequest(method=method_mock, message="Bad Request: message is not modified")
        )

        callback = MagicMock(spec=CallbackQuery)
        callback.message = target_msg
        callback.answer = AsyncMock()

        res = await update_screen(
            event=callback,
            state=state,
            text="Тот же текст",
        )

        # Должен вернуть текущее сообщение без падения
        self.assertEqual(res, target_msg)

    async def test_safe_edit_message_html(self):
        """Проверка вспомогательной функции safe_edit_message с parse_mode='HTML'."""
        msg = MagicMock()
        msg.__class__ = Message
        msg.edit_text = AsyncMock()

        # Успешный edit с HTML
        success = await safe_edit_message(msg, text="<b>Прогресс 50%</b>")
        self.assertTrue(success)
        msg.edit_text.assert_awaited_once_with(
            text="<b>Прогресс 50%</b>",
            reply_markup=None,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

        # Исключение 'message is not modified'
        method_mock = MagicMock()
        msg.edit_text = AsyncMock(
            side_effect=TelegramBadRequest(method=method_mock, message="message is not modified")
        )
        self.assertTrue(await safe_edit_message(msg, text="Прогресс 50%"))

        # TelegramRetryAfter
        msg.edit_text = AsyncMock(
            side_effect=TelegramRetryAfter(method=method_mock, message="Flood control", retry_after=5)
        )
        self.assertFalse(await safe_edit_message(msg, text="Прогресс 50%"))

    async def test_track_extra_message(self):
        """Проверка регистрации дополнительных сообщений."""
        state = AsyncMock(spec=FSMContext)
        state.get_data.return_value = {"extra_msg_ids": [50]}

        await track_extra_message(state, 51)
        state.update_data.assert_awaited_once_with(extra_msg_ids=[50, 51])
