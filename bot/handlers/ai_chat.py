import asyncio
import io
import logging
import time
from typing import Optional, Sequence, Set
from aiogram import F, Router
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.filters import Command, StateFilter
from aiogram.types import Message
from aiogram.utils.chat_action import ChatActionSender
from google.genai import types
from sqlalchemy.ext.asyncio import AsyncSession

from bot.config import settings
from bot.database.models.dialog import DialogMessage
from bot.database.requests import (
    clear_dialog_history,
    get_dialog_history,
    save_dialog_message,
    upsert_user,
)
from bot.services.ai import GeminiService, format_telegram_html

logger = logging.getLogger(__name__)

ai_router = Router(name="ai_chat")

# Множество ID пользователей, чьи запросы сейчас обрабатываются (защита от спама)
_processing_users: Set[int] = set()

# Ленивая или прямая инициализация GeminiService
_gemini_service: Optional[GeminiService] = None


def get_service() -> GeminiService:
    global _gemini_service
    if _gemini_service is None:
        api_key = (
            settings.GEMINI_API_KEY.get_secret_value()
            if settings and settings.GEMINI_API_KEY
            else None
        )
        model = settings.GEMINI_MODEL if settings else "gemini-3.6-flash"
        temperature = settings.GEMINI_TEMPERATURE if settings else 0.7
        max_history = settings.MAX_CONTEXT_HISTORY if settings else 10
        _gemini_service = GeminiService(
            api_key=api_key,
            model=model,
            temperature=temperature,
            max_history=max_history,
        )
    return _gemini_service


def split_text_into_chunks(text: str, max_chunk_size: int = 4000) -> list[str]:
    """
    Разбивает длинный текст на части, не превышающие лимит Telegram (4096 символов).
    Пытается аккуратно разбивать по абзацам или строкам.
    """
    if len(text) <= max_chunk_size:
        return [text]

    chunks = []
    lines = text.split("\n")
    current_chunk = ""

    for line in lines:
        if len(current_chunk) + len(line) + 1 <= max_chunk_size:
            current_chunk += ("\n" if current_chunk else "") + line
        else:
            if current_chunk:
                chunks.append(current_chunk)
                current_chunk = ""
            while len(line) > max_chunk_size:
                chunks.append(line[:max_chunk_size])
                line = line[max_chunk_size:]
            current_chunk = line

    if current_chunk:
        chunks.append(current_chunk)

    return chunks


async def stream_and_send_response(
    message: Message,
    history: Sequence[DialogMessage],
    prompt: Optional[str] = None,
    media_part: Optional[types.Part] = None,
) -> str:
    """
    Потоковая генерация ответа с динамическим эффектом печатания (стриминг, как в мобильном приложении).
    Периодически обновляет сообщение с курсором ▌, соблюдая ограничения Telegram на частоту редактирования.
    """
    service = get_service()

    # Отправляем начальное статус-сообщение
    status_msg = await message.answer("✍️ <i>Печатает...</i>", parse_mode=ParseMode.HTML)

    accumulated_text = ""
    last_edited_text = ""
    last_edit_time = time.monotonic()
    edit_interval = 0.8  # Редактирование раз в 0.8с для гладкого стриминга
    cursor = " ▌"

    stream = service.generate_response_stream(
        history=history,
        prompt=prompt,
        media_part=media_part,
    )

    async for chunk in stream:
        accumulated_text += chunk
        now = time.monotonic()

        # Обновляем текст в чате, если прошло более 0.8с и накопилось хотя бы 4 символа
        if (now - last_edit_time >= edit_interval) and (len(accumulated_text) - len(last_edited_text) >= 4):
            preview = accumulated_text[:3990] + cursor
            try:
                await status_msg.edit_text(preview, parse_mode=None)
                last_edited_text = accumulated_text
                last_edit_time = now
            except TelegramRetryAfter as e:
                await asyncio.sleep(e.retry_after)
            except TelegramBadRequest:
                pass
            except Exception as e:
                logger.debug("Ошибка редактирования стрима: %s", e)

    final_text = accumulated_text.strip() or "⚠️ Пустой ответ от модели."

    # Финальное оформление: снимаем курсор и применяем красивую HTML-типографику (шрифт, цитаты, код)
    formatted_final = format_telegram_html(final_text)
    if len(formatted_final) <= 4000:
        try:
            await status_msg.edit_text(formatted_final, parse_mode=ParseMode.HTML)
        except TelegramBadRequest as e:
            logger.warning("Ошибка разметки HTML в ai_chat (%s): %s", e, formatted_final[:100])
            try:
                await status_msg.edit_text(final_text, parse_mode=None)
            except TelegramBadRequest:
                pass
    else:
        chunks = split_text_into_chunks(final_text)
        try:
            await status_msg.edit_text(format_telegram_html(chunks[0]), parse_mode=ParseMode.HTML)
        except TelegramBadRequest:
            await status_msg.edit_text(chunks[0], parse_mode=None)

        for remaining_chunk in chunks[1:]:
            try:
                await message.answer(format_telegram_html(remaining_chunk), parse_mode=ParseMode.HTML)
            except TelegramBadRequest:
                await message.answer(remaining_chunk, parse_mode=None)

    return final_text


# --------------------------------------------------------------------------
# Команды управления контекстом: /reset, /new_dialog
# --------------------------------------------------------------------------


@ai_router.message(Command("reset"))
@ai_router.message(Command("new_dialog"))
@ai_router.message(F.text == "🧹 Новый диалог")
async def cmd_reset_dialog(message: Message, session: AsyncSession) -> None:
    """
    Очищает историю переписки пользователя с моделью Gemini.
    """
    user = message.from_user
    if not user:
        return

    deleted_count = await clear_dialog_history(session, user.id)
    await message.answer(
        f"🧹 <b>Контекст диалога успешно очищен!</b>\n"
        f"Удалено сообщений из памяти: {deleted_count}.\n"
        f"Задайте новый вопрос — модель готова к новой теме."
    )


# --------------------------------------------------------------------------
# Обработка текстовых запросов к Gemini со стримингом
# --------------------------------------------------------------------------


@ai_router.message(F.text, ~F.text.startswith("/"), StateFilter(None))
async def handle_ai_text_query(message: Message, session: AsyncSession) -> None:
    """
    Обработчик текстовых запросов: сохранение в БД, стриминг ответа в Telegram в реальном времени.
    """
    user = message.from_user
    text = (message.text or "").strip()
    if not user or not text:
        return

    if user.id in _processing_users:
        await message.answer("⏳ Пожалуйста, дождитесь завершения ответа на предыдущий запрос.")
        return

    _processing_users.add(user.id)

    try:
        if message.bot is None:
            return

        await upsert_user(
            session=session,
            telegram_id=user.id,
            full_name=user.full_name,
            username=user.username,
        )

        history = await get_dialog_history(
            session=session,
            user_id=user.id,
            limit=settings.MAX_CONTEXT_HISTORY if settings else 10,
        )

        await save_dialog_message(
            session=session,
            user_id=user.id,
            role="user",
            content=text,
        )

        # Запускаем стриминг ответа в Telegram
        response_text = await stream_and_send_response(
            message=message,
            history=history,
            prompt=text,
        )

        await save_dialog_message(
            session=session,
            user_id=user.id,
            role="model",
            content=response_text,
        )

    finally:
        _processing_users.discard(user.id)


# --------------------------------------------------------------------------
# Мультимодальность: Фотографии (F.photo) со стримингом
# --------------------------------------------------------------------------


@ai_router.message(F.photo, StateFilter(None))
async def handle_ai_photo_query(message: Message, session: AsyncSession) -> None:
    """
    Обработчик фото: скачивание изображения и стриминг анализа через Gemini.
    """
    user = message.from_user
    if not user or not message.photo or not message.bot:
        return

    if user.id in _processing_users:
        await message.answer("⏳ Пожалуйста, дождитесь завершения ответа на предыдущий запрос.")
        return

    _processing_users.add(user.id)

    try:
        await upsert_user(
            session=session,
            telegram_id=user.id,
            full_name=user.full_name,
            username=user.username,
        )

        # Скачиваем фото максимального качества
        photo = message.photo[-1]
        file_io = io.BytesIO()
        await message.bot.download(photo, destination=file_io)
        image_bytes = file_io.getvalue()

        media_part = types.Part.from_bytes(
            data=image_bytes,
            mime_type="image/jpeg",
        )
        prompt = (message.caption or "").strip() or "Опиши, что изображено на этом фото, и выдели ключевые детали."

        history = await get_dialog_history(
            session=session,
            user_id=user.id,
            limit=settings.MAX_CONTEXT_HISTORY if settings else 10,
        )

        await save_dialog_message(
            session=session,
            user_id=user.id,
            role="user",
            content=f"[Фото] {prompt}",
        )

        response_text = await stream_and_send_response(
            message=message,
            history=history,
            prompt=prompt,
            media_part=media_part,
        )

        await save_dialog_message(
            session=session,
            user_id=user.id,
            role="model",
            content=response_text,
        )

    finally:
        _processing_users.discard(user.id)


# --------------------------------------------------------------------------
# Мультимодальность: Голосовые сообщения (F.voice) со стримингом
# --------------------------------------------------------------------------


@ai_router.message(F.voice, StateFilter(None))
async def handle_ai_voice_query(message: Message, session: AsyncSession) -> None:
    """
    Обработчик голосовых сообщений: скачивание OGG Opus и стриминг ответа Gemini.
    """
    user = message.from_user
    if not user or not message.voice or not message.bot:
        return

    if user.id in _processing_users:
        await message.answer("⏳ Пожалуйста, дождитесь завершения ответа на предыдущий запрос.")
        return

    _processing_users.add(user.id)

    try:
        await upsert_user(
            session=session,
            telegram_id=user.id,
            full_name=user.full_name,
            username=user.username,
        )

        voice = message.voice
        file_io = io.BytesIO()
        await message.bot.download(voice, destination=file_io)
        voice_bytes = file_io.getvalue()

        media_part = types.Part.from_bytes(
            data=voice_bytes,
            mime_type="audio/ogg",
        )
        prompt = "Послушай это аудиосообщение. Ответь на то, о чем спрашивает или говорит собеседник."

        history = await get_dialog_history(
            session=session,
            user_id=user.id,
            limit=settings.MAX_CONTEXT_HISTORY if settings else 10,
        )

        await save_dialog_message(
            session=session,
            user_id=user.id,
            role="user",
            content="[Голосовое сообщение]",
        )

        response_text = await stream_and_send_response(
            message=message,
            history=history,
            prompt=prompt,
            media_part=media_part,
        )

        await save_dialog_message(
            session=session,
            user_id=user.id,
            role="model",
            content=response_text,
        )

    finally:
        _processing_users.discard(user.id)
