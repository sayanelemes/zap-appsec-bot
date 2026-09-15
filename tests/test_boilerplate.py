import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock
from pydantic import ValidationError

from bot.config.config import Settings
from bot.handlers import get_root_router
from bot.keyboards import get_main_menu_keyboard, get_welcome_inline_keyboard
from bot.middlewares import ThrottlingMiddleware


class TestBotStructure(unittest.IsolatedAsyncioTestCase):
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
        self.assertEqual(settings.BOT_NAME, "ZAP AppSec AI Auditor")
        self.assertEqual(settings.ZAP_URL, "http://zap:8080")

        # Проверяем парсинг JSON-списка в ADMIN_IDS
        settings_json = Settings(
            BOT_TOKEN="test:token",
            ADMIN_IDS="[100, 200]",
            _env_file=None,
        )
        self.assertEqual(settings_json.ADMIN_IDS, [100, 200])

    def test_routers_and_handlers(self):
        """Проверка регистрации и структуры роутеров"""
        root_router = get_root_router()
        self.assertIsNotNone(root_router)
        sub_router_names = [r.name for r in root_router.sub_routers]
        self.assertIn("errors", sub_router_names)
        self.assertIn("common", sub_router_names)
        self.assertIn("zap_scanner", sub_router_names)

    def test_keyboards(self):
        """Проверка сборки клавиатур"""
        main_kb = get_main_menu_keyboard()
        self.assertTrue(len(main_kb.keyboard) >= 2)
        # Проверяем наличие кнопки аудита
        button_texts = [btn.text for row in main_kb.keyboard for btn in row]
        self.assertIn("🛡 Проверить сайт", button_texts)

        inline_kb = get_welcome_inline_keyboard()
        self.assertTrue(len(inline_kb.inline_keyboard) >= 2)

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
