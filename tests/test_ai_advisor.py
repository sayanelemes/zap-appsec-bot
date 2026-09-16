import unittest
from bot.services.ai.llm_advisor import (
    APPSEC_SYSTEM_INSTRUCTION,
    deduplicate_alerts,
    split_text_safe,
)
from bot.services.ai.formatter import format_telegram_html


class TestAiAdvisor(unittest.TestCase):
    def test_system_prompt_structure(self):
        """Проверка структуры системного промпта AppSec AI аудитора"""
        self.assertIn("Ты — AppSec аудитор", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("КОНТЕКСТ РАБОТЫ", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("ШАГ 1 — ВАЛИДАЦИЯ АЛЕРТА", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("REAL", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("FALSE_POSITIVE", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("LAB_ARTIFACT", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("DEFENSE_GAP", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("ШАГ 2 — КОНТЕКСТ", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("ШАГ 2.5 — ПОДТВЕРЖДЕНИЕ", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("ШАГ 3 — СТЕК", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("ШАГ 4 — ФОРМИРОВАНИЕ ПРОМПТА ДЛЯ КОДЕРА", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("--- НАЧАЛО ПРОМПТА ---", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("--- КОНЕЦ ПРОМПТА ---", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("Не трогать:", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("Критерии приёмки:", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("РАБОТА С ЛЮБЫМИ САЙТАМИ", APPSEC_SYSTEM_INSTRUCTION)
        self.assertIn("testfire.net", APPSEC_SYSTEM_INSTRUCTION)


    def test_deduplication(self):
        """Проверка дедупликации алертов ZAP по имени и параметру"""
        raw_alerts = [
            {"alert": "SQL Injection", "param": "id", "risk": "High", "confidence": "High"},
            {"alert": "SQL Injection", "param": "id", "risk": "High", "confidence": "High"},
            {"alert": "Cross Site Scripting", "param": "q", "risk": "Medium", "confidence": "Medium"},
            {"alert": "Missing Headers", "param": "", "risk": "Low", "confidence": "Low"},
        ]
        deduped = deduplicate_alerts(raw_alerts)
        # Должно остаться 2 уязвимости (High и Medium), дубликат SQL Injection отфильтрован
        self.assertEqual(len(deduped), 2)
        names = [a["alert"] for a in deduped]
        self.assertIn("SQL Injection", names)
        self.assertIn("Cross Site Scripting", names)

    def test_telegram_html_formatting(self):
        """Проверка генерации <pre><code> для 1-клик копирования в Telegram"""
        sample_card = (
            "💡 <b>Что это такое простыми словами:</b>\n"
            "<blockquote>Простая уязвимость</blockquote>\n\n"
            "🤖 <b>Промпт для AI-агента (Cursor / Antigravity / Claude Code):</b>\n"
            "```\n"
            "/goal Устранить уязвимость SQL Injection (CWE-89) на /api?cat=1\n"
            "```"
        )
        formatted = format_telegram_html(sample_card)
        self.assertIn("<pre><code>/goal Устранить уязвимость", formatted)
        self.assertIn("<blockquote>Простая уязвимость</blockquote>", formatted)

    def test_split_text_safe(self):
        """Проверка безопасного разбиения длинных сообщений"""
        short_text = "Короткий текст"
        chunks = split_text_safe(short_text, max_chunk_size=1000)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], short_text)


if __name__ == "__main__":
    unittest.main()
