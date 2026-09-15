import unittest
from unittest.mock import AsyncMock, MagicMock
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from bot.utils.ui import safe_edit_message, track_extra_message, update_screen


class TestCleanUiHelper(unittest.IsolatedAsyncioTestCase):
    """Тестирование функционала Clean UI и хелперов экрана."""

    async def test_update_screen_with_message_success(self):
        """Проверка удаления входящего сообщения пользователя, старого экрана и отправки нового."""
        # Мок FSMContext с сохраненным старым экраном и доп. сообщениями
        state = AsyncMock(spec=FSMContext)
        state.get_data.return_value = {
            "last_bot_msg_id": 100,
            "extra_msg_ids": [101, 102],
        }

        # Мок нового отправленного сообщения бота
        new_bot_msg = MagicMock()
        new_bot_msg.__class__ = Message
        new_bot_msg.message_id = 200

        # Мок входящего сообщения пользователя
        user_msg = MagicMock()
        user_msg.__class__ = Message
        user_msg.chat = MagicMock()
        user_msg.chat.id = 12345
        user_msg.delete = AsyncMock()
        user_msg.answer = AsyncMock(return_value=new_bot_msg)
        user_msg.bot = MagicMock()
        user_msg.bot.delete_message = AsyncMock()

        res = await update_screen(
            event=user_msg,
            state=state,
            text="Тестовый экран",
        )

        self.assertEqual(res, new_bot_msg)
        # Проверяем немедленное удаление входящего сообщения пользователя
        user_msg.delete.assert_awaited_once()

        # Проверяем удаление старого экрана бота (100) и связанных сообщений (101, 102)
        self.assertEqual(user_msg.bot.delete_message.await_count, 3)
        user_msg.bot.delete_message.assert_any_await(chat_id=12345, message_id=100)
        user_msg.bot.delete_message.assert_any_await(chat_id=12345, message_id=101)
        user_msg.bot.delete_message.assert_any_await(chat_id=12345, message_id=102)

        # Проверяем отправку нового сообщения и сохранение его ID в FSM
        user_msg.answer.assert_awaited_once_with(
            text="Тестовый экран",
            reply_markup=None,
            parse_mode=None,
            disable_web_page_preview=True,
        )
        state.update_data.assert_any_await(last_bot_msg_id=200)

    async def test_update_screen_with_callback_query_success(self):
        """Проверка редактирования текущего экрана на месте при нажатии инлайн-кнопки."""
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
            text="Обновленный экран",
        )

        self.assertEqual(res, edited_msg)
        # Снятие индикатора загрузки с кнопки
        callback.answer.assert_awaited_once()
        # Редактирование на месте
        target_msg.edit_text.assert_awaited_once_with(
            text="Обновленный экран",
            reply_markup=None,
            parse_mode=None,
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
            side_effect=TelegramBadRequest(method=method_mock, message="Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message")
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

    async def test_update_screen_message_delete_not_found(self):
        """Проверка устойчивости при удалении уже удаленного сообщения."""
        state = AsyncMock(spec=FSMContext)
        state.get_data.return_value = {"last_bot_msg_id": 999}

        new_bot_msg = MagicMock()
        new_bot_msg.__class__ = Message
        new_bot_msg.message_id = 300

        user_msg = MagicMock()
        user_msg.__class__ = Message
        user_msg.chat = MagicMock()
        user_msg.chat.id = 12345
        method_mock = MagicMock()
        user_msg.delete = AsyncMock(
            side_effect=TelegramBadRequest(method=method_mock, message="Bad Request: message to delete not found")
        )
        user_msg.bot = MagicMock()
        user_msg.bot.delete_message = AsyncMock(
            side_effect=TelegramBadRequest(method=method_mock, message="Bad Request: message to delete not found")
        )
        user_msg.answer = AsyncMock(return_value=new_bot_msg)

        res = await update_screen(
            event=user_msg,
            state=state,
            text="Экран после ошибки удаления",
        )

        self.assertEqual(res, new_bot_msg)
        state.update_data.assert_awaited_once_with(last_bot_msg_id=300)

    async def test_safe_edit_message(self):
        """Проверка вспомогательной функции safe_edit_message."""
        msg = MagicMock(spec=Message)
        msg.edit_text = AsyncMock()

        # Успешный edit
        success = await safe_edit_message(msg, text="Прогресс 50%")
        self.assertTrue(success)

        # Исключение 'message is not modified'
        method_mock = MagicMock()
        msg.edit_text = AsyncMock(
            side_effect=TelegramBadRequest(method=method_mock, message="message is not modified")
        )
        self.assertTrue(await safe_edit_message(msg, text="Прогресс 50%"))

        # Любой другой TelegramBadRequest
        msg.edit_text = AsyncMock(
            side_effect=TelegramBadRequest(method=method_mock, message="Chat not found")
        )
        self.assertFalse(await safe_edit_message(msg, text="Прогресс 50%"))

        # TelegramRetryAfter
        msg.edit_text = AsyncMock(
            side_effect=TelegramRetryAfter(method=method_mock, message="Flood control", retry_after=5)
        )
        self.assertFalse(await safe_edit_message(msg, text="Прогресс 50%"))

    async def test_track_extra_message(self):
        """Проверка регистрации дополнительных сообщений для очистки."""
        state = AsyncMock(spec=FSMContext)
        state.get_data.return_value = {"extra_msg_ids": [50]}

        await track_extra_message(state, 51)
        state.update_data.assert_awaited_once_with(extra_msg_ids=[50, 51])
