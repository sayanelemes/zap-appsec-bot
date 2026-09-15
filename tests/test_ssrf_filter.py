import asyncio
import unittest
from bot.services.security.ssrf_filter import is_ip_blocked, validate_url_safe
import ipaddress


class TestSsrfFilter(unittest.IsolatedAsyncioTestCase):
    """Тестирование механизмов защиты от SSRF-атак."""

    def test_blocked_ip_ranges(self):
        blocked_ips = [
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",  # AWS/GCP/Azure metadata
            "100.64.0.1",       # CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
        ]
        for ip_str in blocked_ips:
            ip = ipaddress.ip_address(ip_str)
            self.assertTrue(is_ip_blocked(ip), f"IP {ip_str} должен быть заблокирован!")

    def test_allowed_public_ips(self):
        allowed_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ]
        for ip_str in allowed_ips:
            ip = ipaddress.ip_address(ip_str)
            self.assertFalse(is_ip_blocked(ip), f"Публичный IP {ip_str} не должен блокироваться!")

    async def test_validate_url_schemes(self):
        # Запрещенные схемы
        safe, reason, _ = await validate_url_safe("ftp://example.com")
        self.assertFalse(safe)
        self.assertIn("только протоколы HTTP и HTTPS", reason)

        safe, reason, _ = await validate_url_safe("file:///etc/passwd")
        self.assertFalse(safe)

    async def test_validate_private_hosts(self):
        # Запрет localhost и локальных имен
        safe, reason, _ = await validate_url_safe("http://localhost:8080")
        self.assertFalse(safe)
        self.assertIn("SSRF-защита", reason)

        safe, reason, _ = await validate_url_safe("http://127.0.0.1:8000/admin")
        self.assertFalse(safe)
        self.assertIn("Запрещенный адрес", reason)

        safe, reason, _ = await validate_url_safe("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(safe)

        safe, reason, _ = await validate_url_safe("http://app.internal/status")
        self.assertFalse(safe)


if __name__ == "__main__":
    unittest.main()
