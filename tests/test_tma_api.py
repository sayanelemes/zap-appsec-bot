import hashlib
import hmac
import json
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

from starlette.testclient import TestClient

from bot.api.app import app
from bot.api.auth import verify_telegram_webapp_data
from bot.config.config import settings
from bot.services.scan_manager import scan_manager


def make_valid_init_data(user_dict: dict, bot_token: str, auth_date: int = 1710000000) -> str:
    """Генерирует валидную подписанную строку initData Telegram Mini App."""
    data = {
        "auth_date": str(auth_date),
        "query_id": "AAHdF6IQAAAAAN0XohDhr123",
        "user": json.dumps(user_dict, separators=(",", ":")),
    }
    sorted_pairs = sorted(data.items(), key=lambda x: x[0])
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted_pairs)

    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    data_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()

    data["hash"] = data_hash
    return urlencode(data)


class TestTelegramWebAppAuth(unittest.TestCase):
    """Тестирование валидации цифровой подписи Telegram WebApp initData."""

    def setUp(self):
        self.bot_token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ"
        self.user = {"id": 987654321, "first_name": "SecOps", "username": "secops_user"}

    def test_valid_signature(self):
        init_data = make_valid_init_data(self.user, self.bot_token)
        result = verify_telegram_webapp_data(init_data, self.bot_token)
        self.assertIsNotNone(result)
        self.assertEqual(result["user"]["id"], 987654321)
        self.assertEqual(result["user"]["username"], "secops_user")

    def test_tampered_signature_fails(self):
        init_data = make_valid_init_data(self.user, self.bot_token)
        # Подделываем параметр user
        tampered_data = init_data.replace("secops_user", "hacker_user")
        result = verify_telegram_webapp_data(tampered_data, self.bot_token)
        self.assertIsNone(result)

    def test_wrong_bot_token_fails(self):
        init_data = make_valid_init_data(self.user, self.bot_token)
        wrong_token = "999999999:WroooooongToken"
        result = verify_telegram_webapp_data(init_data, wrong_token)
        self.assertIsNone(result)

    def test_missing_hash_fails(self):
        init_data = "user=%7B%22id%22%3A123%7D&auth_date=1710000000"
        result = verify_telegram_webapp_data(init_data, self.bot_token)
        self.assertIsNone(result)


class TestFastApiEndpoints(unittest.TestCase):
    """Интеграционные тесты эндпоинтов TMA API."""

    def setUp(self):
        self.client = TestClient(app)
        self.token = settings.BOT_TOKEN.get_secret_value() if settings else "dummy_token"
        self.allowed_user_id = settings.ADMIN_IDS[0] if (settings and settings.ADMIN_IDS) else 111222333
        self.user_data = {"id": self.allowed_user_id, "first_name": "Admin", "username": "admin"}
        self.valid_init_data = make_valid_init_data(self.user_data, self.token)

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertEqual(json_data["status"], "ok")
        self.assertIn("zap_daemon_connected", json_data)
        self.assertIn("scanner_busy", json_data)

    def test_static_index_html_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("ZAP_DAST // CORE", response.text)

    def test_get_status_requires_auth_when_whitelist_active(self):
        if settings and (settings.ADMIN_IDS or settings.ALLOWED_USERS):
            response = self.client.get("/api/scan/status")
            self.assertEqual(response.status_code, 401)

    def test_get_status_authorized(self):
        headers = {"X-Telegram-Init-Data": self.valid_init_data}
        response = self.client.get("/api/scan/status", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("state", data)
        self.assertIn("progress", data)
        self.assertIn("logs", data)
        self.assertIn("findings", data)

    def test_unauthorized_user_forbidden(self):
        if settings:
            unauthorized_user = {"id": 999999999, "first_name": "Intruder"}
            init_data = make_valid_init_data(unauthorized_user, self.token)
            headers = {"X-Telegram-Init-Data": init_data}

            with patch("bot.config.config.Settings.is_user_allowed", return_value=False):
                response = self.client.get("/api/scan/status", headers=headers)
                self.assertEqual(response.status_code, 403)

    def test_start_scan_validation_error(self):
        headers = {"X-Telegram-Init-Data": self.valid_init_data}
        # Пустой target
        response = self.client.post("/api/scan/start", json={"target": ""}, headers=headers)
        self.assertEqual(response.status_code, 422)  # Pydantic validation error

    def test_stop_scan_endpoint(self):
        headers = {"X-Telegram-Init-Data": self.valid_init_data}
        response = self.client.post("/api/scan/stop", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn(data["state"], ("idle", "stopped", "finished"))


class TestScanManager(unittest.IsolatedAsyncioTestCase):
    """Тестирование логики ScanManager."""

    async def test_scan_manager_initial_state(self):
        status = scan_manager.get_status()
        self.assertIn(status["state"], ("idle", "stopped", "finished"))
        self.assertIsInstance(status["logs"], list)
        self.assertIsInstance(status["findings"], list)

    async def test_scan_manager_empty_target_raises(self):
        with self.assertRaises(ValueError):
            await scan_manager.start_scan(target="   ")

    async def test_scan_manager_stop(self):
        result = await scan_manager.stop_scan()
        self.assertEqual(result["state"], "stopped")
        self.assertFalse(scan_manager.is_running)


if __name__ == "__main__":
    unittest.main()
