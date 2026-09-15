import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock
from google.genai import errors, types

from bot.database import create_engine, create_session_pool
from bot.database.models import Base, DialogMessage, User
from bot.database.requests import (
    clear_dialog_history,
    get_dialog_history,
    save_dialog_message,
    upsert_user,
)
from bot.handlers.ai_chat import split_text_into_chunks
from bot.services.ai.service import GeminiService


class TestGeminiService(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite+aiosqlite:///:memory:")
        cls.session_pool = create_session_pool(cls.engine)

    @classmethod
    async def asyncSetUp(cls):
        async with cls.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    @classmethod
    async def asyncTearDown(cls):
        await cls.engine.dispose()

    async def test_dialog_messages_crud(self):
        """Проверка сохранения, выборки и очистки истории диалога"""
        async with self.session_pool() as session:
            # Создаем пользователя
            user = await upsert_user(session, telegram_id=555666, full_name="AI Tester")

            # Добавляем цепочку сообщений
            m1 = await save_dialog_message(session, user_id=user.id, role="user", content="Привет!")
            m2 = await save_dialog_message(session, user_id=user.id, role="model", content="Здравствуйте! Чем могу помочь?")
            m3 = await save_dialog_message(session, user_id=user.id, role="user", content="Как погода?")

            # Проверяем получение истории (хронологический порядок)
            history = await get_dialog_history(session, user_id=user.id, limit=10)
            self.assertEqual(len(history), 3)
            self.assertEqual(history[0].content, "Привет!")
            self.assertEqual(history[1].content, "Здравствуйте! Чем могу помочь?")
            self.assertEqual(history[2].content, "Как погода?")

            # Проверяем лимит скользящего окна
            limited_history = await get_dialog_history(session, user_id=user.id, limit=2)
            self.assertEqual(len(limited_history), 2)
            self.assertEqual(limited_history[0].content, "Здравствуйте! Чем могу помочь?")
            self.assertEqual(limited_history[1].content, "Как погода?")

            # Очистка истории
            deleted_count = await clear_dialog_history(session, user_id=user.id)
            self.assertEqual(deleted_count, 3)

            cleared_history = await get_dialog_history(session, user_id=user.id)
            self.assertEqual(len(cleared_history), 0)

    def test_format_history_to_contents(self):
        """Проверка формирования types.Content с чередованием ролей для Gemini API"""
        service = GeminiService(api_key=None, max_history=5)

        m1 = DialogMessage(id=1, user_id=1, role="user", content="Первый вопрос")
        m2 = DialogMessage(id=2, user_id=1, role="model", content="Первый ответ")
        m3 = DialogMessage(id=3, user_id=1, role="model", content="Второй ответ подряд")

        contents = service.format_history_to_contents(
            history=[m1, m2, m3],
            current_text="Второй вопрос",
        )

        # Проверяем чередование
        self.assertEqual(contents[0].role, "user")
        self.assertEqual(contents[0].parts[0].text, "Первый вопрос")

        self.assertEqual(contents[1].role, "model")
        # Сообщения одной роли должны быть объединены
        self.assertIn("Первый ответ", contents[1].parts[0].text)
        self.assertIn("Второй ответ подряд", contents[1].parts[0].text)

        self.assertEqual(contents[2].role, "user")
        self.assertEqual(contents[2].parts[0].text, "Второй вопрос")

    async def test_generate_without_api_key(self):
        """Проверка вывода подсказки при отсутствии API-ключа"""
        service = GeminiService(api_key=None)
        response = await service.generate_response(history=[], prompt="Привет")
        self.assertIn("API-ключ Gemini не настроен", response)

    async def test_generate_success_with_mock(self):
        """Проверка успешной генерации ответа через мок client.aio.models.generate_content"""
        service = GeminiService(api_key="dummy_key")

        # Мокаем client и generate_content
        mock_response = MagicMock()
        mock_response.text = "Это ответ от модели Gemini."
        mock_candidate = MagicMock()
        mock_candidate.finish_reason = "STOP"
        mock_response.candidates = [mock_candidate]

        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        service.client = mock_client

        reply = await service.generate_response(history=[], prompt="Привет")
        self.assertEqual(reply, "Это ответ от модели Gemini.")

    async def test_generate_safety_filter_trigger(self):
        """Проверка перехвата срабатывания Safety Filter"""
        service = GeminiService(api_key="dummy_key")

        mock_response = MagicMock()
        mock_candidate = MagicMock()
        mock_candidate.finish_reason = "SAFETY"
        mock_response.candidates = [mock_candidate]

        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        service.client = mock_client

        reply = await service.generate_response(history=[], prompt="Опасный запрос")
        self.assertIn("ограничений безопасности", reply)

    async def test_generate_rate_limit_429(self):
        """Проверка перехвата ошибки квоты (429 Rate Limit)"""
        service = GeminiService(api_key="dummy_key")

        api_err = errors.APIError(
            429,
            {"error": {"message": "Resource has been exhausted (e.g. check quota)."}},
        )

        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(side_effect=api_err)
        service.client = mock_client

        reply = await service.generate_response(history=[], prompt="Запрос под спамом")
        self.assertIn("Превышен лимит запросов", reply)

    def test_split_text_into_chunks(self):
        """Проверка аккуратного разбиения длинных сообщений (>4000 символов)"""
        short_text = "Короткий текст"
        chunks = split_text_into_chunks(short_text, max_chunk_size=100)
        self.assertEqual(chunks, ["Короткий текст"])

        # Генерируем текст из 3 длинных абзацев по 2500 символов каждый
        p1 = "A" * 2500
        p2 = "B" * 2500
        p3 = "C" * 2500
        long_text = f"{p1}\n{p2}\n{p3}"

        chunks = split_text_into_chunks(long_text, max_chunk_size=4000)
        self.assertTrue(len(chunks) >= 3)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 4000)

    async def test_generate_response_stream(self):
        """Проверка стриминга ответа от GeminiService"""
        service = GeminiService(api_key="dummy_key")

        async def fake_generator():
            yield MagicMock(text="Привет, ", candidates=[])
            yield MagicMock(text="мир!", candidates=[])

        async def mock_stream(*args, **kwargs):
            return fake_generator()

        mock_client = MagicMock()
        mock_client.aio.models.generate_content_stream = mock_stream
        service.client = mock_client

        collected = []
        async for chunk in service.generate_response_stream(history=[], prompt="Тест"):
            collected.append(chunk)

        self.assertEqual("".join(collected), "Привет, мир!")



if __name__ == "__main__":
    unittest.main()

