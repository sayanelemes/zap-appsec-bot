import logging
from typing import Any
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardMarkup,
    Message,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
)

logger = logging.getLogger(__name__)


async def update_screen(
    event: Message | CallbackQuery,
    state: FSMContext,
    text: str,
    reply_markup: InlineKeyboardMarkup | ReplyKeyboardMarkup | ReplyKeyboardRemove | None = None,
    parse_mode: str | None = None,
    disable_web_page_preview: bool = True,
) -> Message | None:
    """
    Динамическое обновление экрана (Clean UI):
    1. Если передан CallbackQuery:
       - Снимает индикатор загрузки кнопки через await event.answer().
       - Редактирует текущее сообщение "на месте" (edit_text).
       - Обновляет last_bot_msg_id в FSM-хранилище.
    2. Если передан Message:
       - Удаляет входящее сообщение пользователя через event.delete().
       - Удаляет предыдущее сообщение экрана бота (last_bot_msg_id) и связанные доп. сообщения.
       - Отправляет новое сообщение экрана бота и сохраняет его ID в state.update_data(last_bot_msg_id=...).
    3. Все операции Telegram API защищены от исключений TelegramBadRequest.
    """
    if isinstance(event, CallbackQuery):
        # 1. Снимаем индикатор загрузки с кнопки
        try:
            await event.answer()
        except TelegramBadRequest as e:
            logger.debug("Сбой при ответе на callback: %s", e)

        target_msg = event.message
        if not target_msg or not isinstance(target_msg, Message):
            return None

        # 2. Редактируем сообщение на месте
        try:
            edited_msg = await target_msg.edit_text(
                text=text,
                reply_markup=reply_markup,
                parse_mode=parse_mode,
                disable_web_page_preview=disable_web_page_preview,
            )
            await state.update_data(last_bot_msg_id=edited_msg.message_id)
            return edited_msg
        except TelegramBadRequest as exc:
            err_msg = str(exc).lower()
            if "message is not modified" in err_msg:
                # Текст и клавиатура идентичны - это штатная ситуация
                return target_msg
            logger.warning("TelegramBadRequest при редактировании экрана: %s", exc)

            # Fallback: если сообщение не удалось отредактировать (например, удалено), шлем новое
            try:
                new_msg = await target_msg.answer(
                    text=text,
                    reply_markup=reply_markup,
                    parse_mode=parse_mode,
                    disable_web_page_preview=disable_web_page_preview,
                )
                await state.update_data(last_bot_msg_id=new_msg.message_id)
                return new_msg
            except Exception as e_send:
                logger.error("Сбой fallback отправки экрана: %s", e_send)
                return None

    elif isinstance(event, Message):
        # 1. Немедленно удаляем входящее текстовое сообщение пользователя
        try:
            await event.delete()
        except (TelegramBadRequest, Exception) as exc:
            logger.debug("Не удалось удалить входящее сообщение пользователя: %s", exc)

        # 2. Проверяем наличие last_bot_msg_id и удаляем предыдущие системные сообщения
        data = await state.get_data()
        last_bot_msg_id = data.get("last_bot_msg_id")

        if last_bot_msg_id:
            try:
                await event.bot.delete_message(
                    chat_id=event.chat.id,
                    message_id=last_bot_msg_id,
                )
            except (TelegramBadRequest, Exception) as exc:
                logger.debug("Не удалось удалить предыдущее сообщение экрана %s: %s", last_bot_msg_id, exc)

        # Дополнительная очистка вспомогательных сообщений (документы отчетов, чанки)
        extra_msg_ids = data.get("extra_msg_ids", [])
        if extra_msg_ids:
            for extra_id in extra_msg_ids:
                try:
                    await event.bot.delete_message(
                        chat_id=event.chat.id,
                        message_id=extra_id,
                    )
                except Exception:
                    pass
            await state.update_data(extra_msg_ids=[])

        # 3. Отправляем новое сообщение экрана и сохраняем его ID в FSM
        try:
            new_msg = await event.answer(
                text=text,
                reply_markup=reply_markup,
                parse_mode=parse_mode,
                disable_web_page_preview=disable_web_page_preview,
            )
            await state.update_data(last_bot_msg_id=new_msg.message_id)
            return new_msg
        except TelegramBadRequest as exc:
            logger.error("Сбой при отправке нового экрана: %s", exc)
            return None

    return None


async def safe_edit_message(
    message: Message,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
    parse_mode: str | None = None,
    disable_web_page_preview: bool = True,
) -> bool:
    """
    Безопасное редактирование сообщения на месте для воркеров и таймеров прогресса.
    Игнорирует 'message is not modified' и перехватывает TelegramBadRequest / TelegramRetryAfter.
    """
    try:
        await message.edit_text(
            text=text,
            reply_markup=reply_markup,
            parse_mode=parse_mode,
            disable_web_page_preview=disable_web_page_preview,
        )
        return True
    except TelegramBadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return True
        logger.debug("safe_edit_message: TelegramBadRequest: %s", exc)
        return False
    except TelegramRetryAfter as retry:
        logger.debug("safe_edit_message: Rate limit hit, retry after %s", retry.retry_after)
        return False
    except Exception as exc:
        logger.debug("safe_edit_message: непредвиденная ошибка: %s", exc)
        return False


async def track_extra_message(state: FSMContext, message_id: int) -> None:
    """
    Регистрирует ID дополнительного сообщения (например, файл отчета),
    чтобы при следующем обновлении экрана через update_screen оно было удалено.
    """
    data = await state.get_data()
    extra_ids = list(data.get("extra_msg_ids", []))
    extra_ids.append(message_id)
    await state.update_data(extra_msg_ids=extra_ids)
