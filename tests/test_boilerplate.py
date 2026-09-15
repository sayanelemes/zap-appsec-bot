import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock
from pydantic import ValidationError

from bot.config.config import Settings
from bot.database import check_db_connection, create_engine, create_session_pool
from bot.database.requests import (
    get_all_users,
    get_total_users_count,
    get_user_by_tg_id,
    upsert_user,
)
from bot.handlers import get_root_router
from bot.keyboards import get_main_menu_keyboard, get_welcome_inline_keyboard
from bot.middlewares import DbSessionMiddleware, ThrottlingMiddleware
from bot.states import ProfileForm


class TestBotBoilerplate(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        # Используем тестовую базу SQLite в памяти
        cls.db_url = "sqlite+aiosqlite:///:memory:"
        cls.engine = create_engine(cls.db_url)
        cls.session_pool = create_session_pool(cls.engine)

    @classmethod
    async def asyncSetUp(cls):
        from bot.database.models import Base

        async with cls.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    @classmethod
    async def asyncTearDown(cls):
        await cls.engine.dispose()

    def test_settings_validation(self):
        """Проверка строгой валидации Pydantic Settings"""
        # Проверяем, что отсутствие BOT_TOKEN вызывает исключение ValidationError
        with self.assertRaises(ValidationError):
            Settings(_env_file=None)  # type: ignore[call-arg]

        # Проверяем корректную инициализацию с токеном и строковыми ADMIN_IDS
        settings = Settings(
            BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrs",
            ADMIN_IDS="111, 222, 333",
            _env_file=None,
        )
        self.assertEqual(settings.ADMIN_IDS, [111, 222, 333])
        self.assertEqual(
            settings.BOT_TOKEN.get_secret_value(), "123456789:ABCdefGHIjklMNOpqrs"
        )

        # Проверяем парсинг JSON-списка в ADMIN_IDS
        settings_json = Settings(
            BOT_TOKEN="test:token",
            ADMIN_IDS="[100, 200]",
            _env_file=None,
        )
        self.assertEqual(settings_json.ADMIN_IDS, [100, 200])

    async def test_database_crud(self):
        """Проверка CRUD операций с базой данных через AsyncSession"""
        async with self.session_pool() as session:
            # 1. Проверка upsert нового пользователя
            user = await upsert_user(
                session=session,
                telegram_id=999888777,
                full_name="Иван Иванов",
                username="ivan_test",
            )
            self.assertIsNotNone(user.id)
            self.assertEqual(user.telegram_id, 999888777)
            self.assertEqual(user.full_name, "Иван Иванов")
            self.assertEqual(user.username, "ivan_test")

            # 2. Получение по telegram_id
            fetched_user = await get_user_by_tg_id(session, 999888777)
            self.assertIsNotNone(fetched_user)
            self.assertEqual(fetched_user.telegram_id, 999888777)

            # 3. Upsert существующего пользователя с обновлением имени
            updated_user = await upsert_user(
                session=session,
                telegram_id=999888777,
                full_name="Иван Петров",
                username="ivan_new",
            )
            self.assertEqual(updated_user.id, user.id)
            self.assertEqual(updated_user.full_name, "Иван Петров")
            self.assertEqual(updated_user.username, "ivan_new")

            # 4. Проверка общего количества
            count = await get_total_users_count(session)
            self.assertEqual(count, 1)

            # 5. Список пользователей
            all_users = await get_all_users(session)
            self.assertEqual(len(all_users), 1)

    def test_routers_and_handlers(self):
        """Проверка регистрации и структуры роутеров"""
        root_router = get_root_router()
        self.assertIsNotNone(root_router)
        sub_router_names = [r.name for r in root_router.sub_routers]
        self.assertIn("errors", sub_router_names)
        self.assertIn("common", sub_router_names)

    def test_keyboards(self):
        """Проверка сборки клавиатур"""
        main_kb = get_main_menu_keyboard()
        self.assertTrue(len(main_kb.keyboard) >= 2)

        inline_kb = get_welcome_inline_keyboard()
        self.assertTrue(len(inline_kb.inline_keyboard) >= 2)

    def test_fsm_states(self):
        """Проверка состояний FSM"""
        states = ProfileForm.__all_states__
        state_names = [s.state for s in states]
        self.assertIn("ProfileForm:waiting_for_name", state_names)
        self.assertIn("ProfileForm:waiting_for_age", state_names)
        self.assertIn("ProfileForm:waiting_for_bio", state_names)

    async def test_throttling_middleware(self):
        """Проверка антиспам-мидлваря"""
        middleware = ThrottlingMiddleware(rate_limit=0.5)

        # Мокаем событие и обработчик
        user_mock = MagicMock()
        user_mock.id = 12345
        data = {"event_from_user": user_mock}
        handler_mock = AsyncMock(return_value="OK")
        event_mock = MagicMock()

        # Первый запрос должен пройти успешно
        res1 = await middleware(handler_mock, event_mock, data)
        self.assertEqual(res1, "OK")
        handler_mock.assert_called_once()

        # Мгновенный повторный запрос должен быть заблокирован (вернуть None)
        handler_mock.reset_mock()
        res2 = await middleware(handler_mock, event_mock, data)
        self.assertIsNone(res2)
        handler_mock.assert_not_called()

        # Запрос после ожидания интервала должен пройти
        await asyncio.sleep(0.55)
        res3 = await middleware(handler_mock, event_mock, data)
        self.assertEqual(res3, "OK")
        handler_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
