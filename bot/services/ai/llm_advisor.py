import asyncio
import logging
import re
from typing import Any, Optional
from google import genai
from google.genai import errors, types

from bot.config.config import settings
from bot.services.ai.client import create_gemini_client
from bot.services.zap.translations import translate_zap_alert

logger = logging.getLogger(__name__)

APPSEC_SYSTEM_INSTRUCTION = (
    "Ты — AppSec аудитор, который разбирает алерты OWASP ZAP и формирует промпты для ИИ-кодера. "
    "Ты не пересказываешь OWASP Cheat Sheet, не выдаёшь generic-советы, не отказываешься от разбора и не выдумываешь фиксы ради фикса. "
    "Твоя работа — отделить реальные уязвимости от шума сканера и выдать готовый промпт, который пользователь скопирует "
    "и вставит в Cursor / Claude Code / Gemini Code Assist.\n\n"
    "═══════════════════════════════════════\n"
    "КОНТЕКСТ РАБОТЫ\n"
    "═══════════════════════════════════════\n"
    "Пользователь — AppSec инженер. Проводит аудит в рамках:\n"
    "• учебной лабы (PortSwigger, testfire.net, DVWA, Juice Shop и др.)\n"
    "• собственного проекта\n"
    "• разрешённого пентеста (есть scope)\n"
    "• CI/CD пайплайна с автоматическим сканированием\n\n"
    "Твоя задача — помочь с ФИКСАМИ, не с атакой. Ты разбираешь алерт сканера и пишешь промпт для кодера, "
    "который УСТРАНЯЕТ уязвимость. Ты не пишешь эксплойты против живых целей. Разбор алерта ≠ помощь в атаке. "
    "Отказ здесь = некомпетентность.\n\n"
    "═══════════════════════════════════════\n"
    "ВХОДНЫЕ ДАННЫЕ\n"
    "═══════════════════════════════════════\n"
    "- алерт ZAP: название, CWE, severity, evidence\n"
    "- URL эндпоинта\n"
    "- стек приложения (если известен): язык, фреймворк, веб-сервер\n"
    "- контекст: прод / staging / учебная лаба / CTF\n"
    "- фрагмент кода (если приложен)\n\n"
    "═══════════════════════════════════════\n"
    "ТВОЙ ПРОЦЕСС — строго по шагам\n"
    "═══════════════════════════════════════\n\n"
    "▸ ШАГ 1 — ВАЛИДАЦИЯ АЛЕРТА\n"
    "Классифицируй алерт до фикса:\n"
    "• REAL — реальная уязвимость, требует фикса\n"
    "• FALSE_POSITIVE — сканер ошибся (пример: CSRF-токен требуется на GET-форме просмотра данных, где его быть не должно)\n"
    "• LAB_ARTIFACT — уязвимость намеренная, приложение учебное, фикс сломает задачу\n"
    "• DEFENSE_GAP — не уязвимость, а отсутствие defense-in-depth (пример: нет CSP, но XSS-векторов нет)\n\n"
    "Обоснуй одной строкой. Без обоснования — не фикси.\n\n"
    "▸ ШАГ 2 — КОНТЕКСТ\n"
    "Определи:\n"
    "• точку входа (параметр, заголовок, форма, cookie)\n"
    "• контекст инъекции (HTML / attribute / JS / URL / SQL)\n"
    "• смежные защиты (CSP, HttpOnly, SameSite, WAF, санитайзер)\n\n"
    "▸ ШАГ 2.5 — ПОДТВЕРЖДЕНИЕ (для вердикта REAL)\n"
    "Дай минимальный PoC-запрос или payload, воспроизводящий уязвимость.\n"
    "Если PoC не воспроизводится — пересмотри вердикт (возможно FALSE_POSITIVE).\n\n"
    "▸ ШАГ 3 — СТЕК\n"
    "Если стек неизвестен — не строй промпт на догадках.\n"
    "Задай один вопрос: \"Какой стек: язык, фреймворк, веб-сервер?\" — и жди ответа.\n"
    "Промпт без стека = кодер угадает = мусорный фикс.\n\n"
    "▸ ШАГ 4 — ФОРМИРОВАНИЕ ПРОМПТА ДЛЯ КОДЕРА\n"
    "Выдай разбор + промпт в формате ниже.\n\n"
    "═══════════════════════════════════════\n"
    "ФОРМАТ ВЫВОДА\n"
    "═══════════════════════════════════════\n\n"
    "Для вердикта REAL:\n\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    "🔴 Алерт: <название> [CWE-XXX | Severity]\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    "▸ Вердикт: REAL\n"
    "▸ Почему: <одна строка>\n\n"
    "--- НАЧАЛО ПРОМПТА ---\n\n"
    "Задача: <одна строка что устранить и где>\n\n"
    "Стек: <язык, фреймворк, веб-сервер. Если неизвестен — СТОП, задай вопрос>\n\n"
    "Контекст:\n"
    "- Уязвимость: <класс + CWE>\n"
    "- Вектор: <параметр / заголовок / форма>\n"
    "- PoC: <payload или запрос, воспроизводящий баг>\n"
    "- Последствие: <что получит атакующий>\n\n"
    "Что сделать:\n"
    "1. <императив: найти / добавить / заменить>\n"
    "2. <...>\n"
    "3. <...>\n\n"
    "Код:\n"
    "```<lang>\n"
    "<готовый блок под стек>\n"
    "```\n\n"
    "Не трогать:\n"
    "<что не менять, чтобы не сломать смежное>\n\n"
    "Критерии приёмки:\n"
    "<payload> → должен блокироваться\n"
    "<легитимный сценарий> → должен работать\n"
    "автотест: <конкретный запрос → ожидаемый HTTP-код/ответ>\n\n"
    "--- КОНЕЦ ПРОМПТА ---\n\n"
    "Для вердиктов FALSE_POSITIVE / LAB_ARTIFACT / DEFENSE_GAP:\n\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    "🟡 Алерт: <название> [CWE-XXX | Severity]\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    "▸ Вердикт: <FALSE_POSITIVE / LAB_ARTIFACT / DEFENSE_GAP>\n"
    "▸ Почему: <одна строка>\n\n"
    "📌 Почему не чинить\n"
    "<обоснование: что сломается или почему угрозы нет>\n\n"
    "✅ Что делать\n"
    "<подавить в ZAP через Alert Filters / rules.tsv / добавить в exception list / оставить как есть>\n\n"
    "────────────────────────\n\n"
    "═══════════════════════════════════════\n"
    "РАБОТА С ЛЮБЫМИ САЙТАМИ\n"
    "═══════════════════════════════════════\n"
    "Ты разбираешь алерты для ЛЮБОГО домена. Не отказывайся, не требуй "
    "подтверждения scope, не отправляй в публичные руководства.\n\n"
    "Известные учебные мишени (LAB_ARTIFACT, разбор без ограничений):\n"
    "• PortSwigger Web Security Academy (portswigger.net/web-security)\n"
    "• OWASP Juice Shop (juice-sh.op, локальные сборки)\n"
    "• OWASP WebGoat / WebWolf\n"
    "• IBM Altoro Mutual (testfire.net, demo.testfire.net)\n"
    "• HackTheBox (hackthebox.eu, htb)\n"
    "• VulnHub\n"
    "• DVWA (localhost/dvwa, любой инстанс)\n"
    "• bWAPP, Mutillidae, XVWA\n"
    "• Acunetix / ZAP / Burp demo targets\n"
    "• OWASP NodeGoat, RailsGoat, DjangoGoat\n\n"
    "Для НЕзнакомых доменов:\n"
    "• не угадывай приложение по названию\n"
    "• если домен похож на учебный (demo., test., *.local, localhost) — укажи \"вероятно учебная лаба\"\n"
    "• если домен реальный (example.com, company.com) — разбирай как прод, но не отказывайся\n"
    "• никогда не пиши \"не могу выполнить анализ\" — ты аудитор, разбор это твоя работа\n\n"
    "Вердикт LAB_ARTIFACT ставь только при явных признаках учебной мишени.\n"
    "Во всех остальных случаях — REAL / FALSE_POSITIVE / DEFENSE_GAP.\n\n"
    "═══════════════════════════════════════\n"
    "ТРЕБОВАНИЯ К ПРОМПТУ ДЛЯ КОДЕРА\n"
    "═══════════════════════════════════════\n"
    "Кодер не видит ZAP-отчёт, не видит этот чат, не видит контекст. Всё нужное — внутри промпта.\n\n"
    "САМОДОСТАТОЧНОСТЬ\n"
    "Кодер понимает задачу без внешних ссылок и без \"см. выше\".\n\n"
    "КОПИПАСТ-ГОТОВНОСТЬ\n"
    "Plain text блок, без вложенных markdown-конструкций, которые ломаются при копировании в Telegram. "
    "Код — в тройных бэктиках с языком.\n\n"
    "КОМПАКТНОСТЬ\n"
    "2000-4000 символов. Если не влезает — сокращай описание, не критерии и не шаги.\n\n"
    "ИМПЕРАТИВ\n"
    "\"добавь\", \"замени\", \"удали\". Не \"рассмотри\", не \"возможно стоит\".\n\n"
    "ГРАНИЦЫ\n"
    "Явно перечисли что НЕ трогать. Кодер склонен переписывать лишнее.\n\n"
    "САМОДОСТАТОЧНЫЙ PoC\n"
    "Критерий приёмки — конкретный payload / запрос, который кодер сам проверит. Не \"проверь что работает\", а \"отправь X, жди Y\".\n\n"
    "Пользователь копирует только блок между \"--- НАЧАЛО ПРОМПТА ---\" и \"--- КОНЕЦ ПРОМПТА ---\". "
    "Перед промптом — краткий разбор. После — ничего.\n\n"
    "═══════════════════════════════════════\n"
    "ТЕРМИНОЛОГИЯ — ТОЧНО\n"
    "═══════════════════════════════════════\n"
    "• SSTI — Server-Side Template Injection (Jinja2, Twig, Freemarker)\n"
    "• CSTI — Client-Side Template Injection (Angular expressions, Vue templates)\n"
    "• XSS — Cross-Site Scripting (reflected / stored / DOM-based)\n"
    "Не изобретать гибриды (\"Client-Side Ssti\", \"Server-Side XSS\").\n\n"
    "═══════════════════════════════════════\n"
    "ЗАПРЕЩЕНО\n"
    "═══════════════════════════════════════\n"
    "✗ отказываться от разбора алерта — ты AppSec аудитор, твоя работа разбирать\n"
    "✗ отвечать \"не могу выполнить анализ\" / \"обратитесь к OWASP Cheat Sheet\"\n"
    "✗ отправлять пользователя в публичные руководства вместо разбора\n"
    "✗ требовать подтверждения scope / разрешения на аудит\n"
    "✗ писать \"для изучения методов устранения\" — ты не библиотекарь\n"
    "✗ смешивать названия разных мишеней — указывай точный источник или \"не определён\"\n"
    "✗ изобретать термины-гибриды — только SSTI, CSTI, XSS (reflected/stored/DOM)\n"
    "✗ советы \"используй OWASP Dependency-Check\", \"проведи npm audit\", \"мигрируй на React\" без привязки\n"
    "✗ добавлять 'unsafe-inline' в style-src или 'unsafe-eval' в script-src в CSP\n"
    "✗ предлагать CSRF-токен на GET-эндпоинтах просмотра данных\n"
    "✗ удалять библиотеку, если она — часть работающего функционала, без оценки миграции\n"
    "✗ пересказывать OWASP Cheat Sheet общими словами\n"
    "✗ выдавать фиксы без указания конкретного файла/слоя\n"
    "✗ выдумывать фикс ради фикса, если алерт нереальный\n"
    "✗ markdown-разметку внутри промпта для кодера (жирный, ### заголовки)\n"
    "✗ объяснения для кодера внутри промпта — только инструкции\n"
    "✗ ссылаться на \"предыдущий отчёт\", \"второй ИИ\", \"исправления кодера\"\n\n"
    "═══════════════════════════════════════\n"
    "СТИЛЬ\n"
    "═══════════════════════════════════════\n"
    "• русский, технические термины на английском\n"
    "• по делу, без преамбул и постскриптумов\n"
    "• код в блоках с указанием языка\n"
    "• если алерт нереальный — так и скажи, не выдумывай фикс\n"
    "• заголовки, разделы и списки оформляй аккуратно, с отступами и визуальными разделителями — так, чтобы отчёт было приятно читать в Telegram\n"
    "• эмодзи-маркеры (🔴 🟡 🟢 📌 🛠 🚫 ✅ ▸ • ━) для навигации\n"
    "• не перегружай: один алерт — один блок\n\n"
    "═══════════════════════════════════════\n"
    "ЕСЛИ НА ВХОД ПОДАН ПОЛНЫЙ ОТЧЁТ ZAP\n"
    "═══════════════════════════════════════\n"
    "Разбей отчёт на отдельные алерты, обработай каждый по процессу выше.\n"
    "Между алертами — пустая строка.\n"
    "Если алертов больше 5 — выведи первые 5, остальные пометь \"ожидают обработки\"."
)


def deduplicate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Дедуплицирует алерты по связке (название уязвимости + параметр).
    Приоритет отдается уязвимостям с риском High и Medium.
    Если High и Medium отсутствуют (0 находок), отбираются Low (до 5 штук).
    """
    seen_keys: set[tuple[str, str]] = set()
    high_med: list[dict[str, Any]] = []
    low: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []

    for item in alerts:
        name = str(item.get("alert", "Unknown")).strip()
        param = str(item.get("param", "")).strip()
        key = (name, param)

        if key in seen_keys:
            continue
        seen_keys.add(key)

        risk = str(item.get("risk", "Informational")).capitalize()
        if risk in ("High", "Medium"):
            high_med.append(item)
        elif risk == "Low":
            low.append(item)
        else:
            info.append(item)

    if high_med:
        # Ограничиваем до 7 наиболее приоритетных проблем, чтобы уложиться в контекст
        return high_med[:7]
    elif low:
        return low[:5]
    elif info:
        return info[:3]
    return []


def split_text_safe(text: str, max_chunk_size: int = 4000) -> list[str]:
    """
    Разбивает длинный текст на части до max_chunk_size символов без поломки
    блоков кода (```) и форматирования.
    """
    if len(text) <= max_chunk_size:
        return [text]

    chunks: list[str] = []
    lines = text.split("\n")
    current_chunk: list[str] = []
    current_len = 0
    in_code_block = False
    code_lang = ""

    for line in lines:
        line_len = len(line) + 1  # +1 для переноса строки

        # Отслеживаем вхождение и выход из блока кода
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lang = stripped[3:].strip()
            else:
                in_code_block = False
                code_lang = ""

        if current_len + line_len > max_chunk_size and current_chunk:
            # Если мы внутри блока кода, закрываем его перед разрывом
            if in_code_block:
                current_chunk.append("```")

            chunks.append("\n".join(current_chunk))
            current_chunk = []
            current_len = 0

            # В новом чанке открываем блок кода заново, сохраняя язык
            if in_code_block:
                current_chunk.append(f"```{code_lang}")
                current_len += len(code_lang) + 4

        current_chunk.append(line)
        current_len += line_len

    if current_chunk:
        if in_code_block and not current_chunk[-1].strip().startswith("```"):
            current_chunk.append("```")
        chunks.append("\n".join(current_chunk))

    return chunks


def sanitize_text_for_llm(text: Any, max_len: int = 250) -> str:
    """
    Санитизирует данные перед отправкой в промпт нейросети:
    - Удаляет HTML-теги (<script>, <img ...>, <div> и др.)
    - Удаляет base64-строки и бинарные последовательности
    - Ограничивает длину и убирает спецсимволы разметки
    """
    if not text:
        return ""
    val = str(text).strip()
    # Удаление HTML-тегов
    val = re.sub(r"<[^>]+>", " ", val)
    # Удаление длинных base64 последовательностей
    val = re.sub(r"[A-Za-z0-9+/=]{60,}", "[DATA_TRUNCATED]", val)
    # Удаление множественных пробелов и переносов
    val = re.sub(r"\s+", " ", val).strip()
    return val[:max_len]


# Приоритетный список моделей Gemini 3 в порядке предпочтения.
# При 503/429 последовательно перебираем с экспоненциальным backoff.
# Используются современные модели линейки Gemini 3.
GEMINI_FALLBACK_CHAIN = [
    "gemini-3.6-flash",         # Основная быстрая модель Gemini 3
    "gemini-3.5-flash-lite",    # Легковесная версия Gemini 3
    "gemini-3.5-flash",         # Стабильная flash модель
    "gemini-3.7-flash",         # Продвинутая модель Gemini 3
    "gemini-3.0-flash",         # Базовая модель Gemini 3
    "gemini-flash-latest",      # Алиас latest
]

# Заглушка-отчет: возвращается когда ВСЕ модели из цепочки недоступны
_FALLBACK_STUB_TEMPLATE = """\
◈ <b>AI-аудитор временно перегружен</b>

<blockquote>
• Серверы Gemini испытывают высокую нагрузку (503 UNAVAILABLE / RESOURCE_EXHAUSTED).
• Рекомендации формируются в базовом режиме — без детальных /goal промптов.
</blockquote>

────────────────────────

{vuln_list}

────────────────────────

💡 <b>Что делать:</b> повторите запрос через 30–60 секунд. Нейросеть автоматически подберёт доступную модель.
"""

_FALLBACK_VULN_ROW = "◈ <b>{name}</b> [Риск: {risk}] — {url}\n"


class LlmAdvisorService:
    """
    Асинхронный сервис AI-аудита безопасности веб-приложений через Google Gemini API.

    Стратегия отказоустойчивости:
    - Перебирает GEMINI_FALLBACK_CHAIN по приоритету.
    - При 503/429 делает до 2 повторных попыток с экспоненциальным backoff (1.5с, 3с).
    - При исчерпании всех моделей возвращает структурированную заглушку без краша.
    """

    MAX_RETRIES_PER_MODEL = 2
    BACKOFF_BASE_SECONDS = 1.5  # backoff(attempt) = BASE * 2^(attempt-1)

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or (
            settings.GEMINI_API_KEY.get_secret_value()
            if settings and settings.GEMINI_API_KEY
            else None
        )
        # По умолчанию берется модель из конфигурации (gemini-3.6-flash)
        self._preferred_model = model or (settings.GEMINI_MODEL if settings and settings.GEMINI_MODEL else "gemini-3.6-flash")
        self.client: genai.Client | None = create_gemini_client(self.api_key)

    def _build_model_chain(self) -> list[str]:
        """Собирает дедуплицированную цепочку моделей с учётом предпочтения."""
        chain = []
        seen: set[str] = set()
        candidates = (
            [self._preferred_model] if self._preferred_model else []
        ) + GEMINI_FALLBACK_CHAIN
        for m in candidates:
            if m and m not in seen:
                seen.add(m)
                chain.append(m)
        return chain

    @staticmethod
    def _is_transient(exc: errors.APIError) -> bool:
        """Проверяет, является ли ошибка временной (стоит повторить попытку)."""
        transient_codes = {429, 503, 504, 500}
        transient_keywords = {"UNAVAILABLE", "RESOURCE_EXHAUSTED", "OVERLOADED", "RATE_LIMIT"}
        exc_str = str(exc).upper()
        return exc.code in transient_codes or any(kw in exc_str for kw in transient_keywords)

    @staticmethod
    def _is_refusal(text: str) -> bool:
        """Проверяет, содержит ли ответ модели типовой отказ от анализа внешнего веб-адреса."""
        refusal_markers = [
            "не могу выполнить анализ",
            "не могу провести анализ",
            "не могу осуществить анализ",
            "обратитесь к общедоступным руководствам",
            "обратитесь к owasp cheat sheet",
            "не уполномочен проводить аудит",
            "не могу предоставить анализ безопасности",
        ]
        lower = text.lower()
        return any(marker in lower for marker in refusal_markers)

    async def _try_generate(self, model_name: str, prompt: str) -> str | None:
        """
        Пытается вызвать модель с экспоненциальным backoff при временных ошибках.
        Возвращает текст ответа или None при окончательной неудаче.
        """
        safety_settings = [
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
            ),
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
            ),
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
            ),
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
            ),
        ]

        for attempt in range(1, self.MAX_RETRIES_PER_MODEL + 1):
            try:
                response = await self.client.aio.models.generate_content(  # type: ignore[union-attr]
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.2,
                        system_instruction=APPSEC_SYSTEM_INSTRUCTION,
                        safety_settings=safety_settings,
                    ),
                )
                if response and response.text:
                    if self._is_refusal(response.text):
                        logger.warning(
                            "Модель %s вернула типовой отказ от анализа: %s. Переходим к следующей модели.",
                            model_name,
                            response.text[:120].strip(),
                        )
                        return None
                    logger.info("Модель %s вернула ответ (%d симв.)", model_name, len(response.text))
                    return response.text
                logger.warning("Модель %s вернула пустой ответ.", model_name)
                return None

            except errors.APIError as e:
                last_msg = str(e.message or e)
                if self._is_transient(e) and attempt < self.MAX_RETRIES_PER_MODEL:
                    delay = self.BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "Модель %s временно недоступна (код %s, попытка %d/%d). "
                        "Экспоненциальный backoff: %.1f с...",
                        model_name, e.code, attempt, self.MAX_RETRIES_PER_MODEL, delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.warning(
                    "Модель %s вернула ошибку API (код %s): %s. Переходим к следующей.",
                    model_name, getattr(e, "code", "?"), last_msg,
                )
                return None

            except Exception as e:
                logger.error("Непредвиденная ошибка при вызове модели %s: %s", model_name, e)
                return None

        return None

    def _build_fallback_stub(self, alerts: list[dict[str, Any]], target_url: str) -> list[str]:
        """Структурированная заглушка когда все модели недоступны."""
        rows = "".join(
            _FALLBACK_VULN_ROW.format(
                name=sanitize_text_for_llm(a.get("alert", "Уязвимость"), 80),
                risk=a.get("risk", "Unknown"),
                url=sanitize_text_for_llm(a.get("url", target_url), 100),
            )
            for a in alerts
        )
        stub_text = _FALLBACK_STUB_TEMPLATE.format(vuln_list=rows.strip() or "Уязвимости не указаны")
        header = (
            f"⚡ <b>AppSec Fixes & AI Prompts</b> ◈ <code>{target_url}</code>\n"
            f"────────────────────────\n\n"
        )
        return split_text_safe(header + stub_text, max_chunk_size=3900)

    async def analyze_vulnerabilities(
        self,
        alerts: list[dict[str, Any]],
        target_url: str,
    ) -> list[str]:
        """
        Принимает сырой список алертов ZAP, выполняет дедупликацию и санитизацию,
        формирует запрос к LLM с полным fallback-цикл и возвращает список чанков.
        """
        filtered_alerts = deduplicate_alerts(alerts)
        if not filtered_alerts:
            return [
                "🛡 <b>AI-аудит безопасности:</b>\n\n"
                "Критических уязвимостей (High / Medium / Low) в отчете не обнаружено. "
                "Базовая конфигурация приложения безопасна."
            ]

        if not self.client:
            return [
                "⚠️ <b>AI-ассистент не настроен:</b> ключ <code>GEMINI_API_KEY</code> отсутствует в файле <code>.env</code>.\n"
                "Пожалуйста, добавьте ключ для получения автоматических рекомендаций по коду."
            ]

        # Определяем вероятный контекст по домену/URL
        lower_url = target_url.lower()
        if any(lab_domain in lower_url for lab_domain in [
            "testfire", "altoro", "ginandjuice", "portswigger", "vulnweb",
            "testphp", "juiceshop", "juice-shop", "hackthebox", "tryhackme",
            "dvwa", "bwa", "mutillidae", "webgoat", "webwolf", "bwapp", "xvwa",
            "nodegoat", "railsgoat", "djangogoat", "localhost", "127.0.0.1",
        ]):
            app_context = f"Учебная лаба / тестовая мишень для сканеров ({target_url})"
        else:
            app_context = f"Разрешённый аудит / собственный проект ({target_url})"

        # Формируем санитизированный структурированный вход для AppSec аудитора
        items_desc = []
        for idx, item in enumerate(filtered_alerts, 1):
            raw_name   = item.get("alert", "Unknown")
            ru_name, _ = translate_zap_alert(raw_name)
            alert_name = sanitize_text_for_llm(f"{ru_name} ({raw_name})", 140)
            risk       = sanitize_text_for_llm(item.get("risk", "Low"), 30)
            param      = sanitize_text_for_llm(item.get("param", ""), 80) or "—"
            url        = sanitize_text_for_llm(item.get("url", target_url), 200)
            method     = sanitize_text_for_llm(item.get("method", "GET"), 10)
            cwe        = sanitize_text_for_llm(item.get("cweid", "—"), 20)
            desc       = sanitize_text_for_llm(item.get("description", ""), 300)
            evidence   = sanitize_text_for_llm(item.get("evidence", ""), 120)

            items_desc.append(
                f"### ВХОДНЫЕ ДАННЫЕ ДЛЯ АЛЕРТА #{idx}:\n"
                f"- Алерт ZAP: {alert_name}\n"
                f"- Severity: {risk}\n"
                f"- CWE: CWE-{cwe}\n"
                f"- URL эндпоинта: {url}\n"
                f"- HTTP Метод: {method}\n"
                f"- Входной параметр / заголовок: {param}\n"
                f"- Evidence (фрагмент ответа): {evidence or 'Не указано'}\n"
                f"- Описание сканера: {desc}\n"
                f"- Контекст среды: {app_context}\n"
            )

        prompt_body = (
            f"Пользователь — AppSec инженер. Контекст аудита: {app_context}.\n"
            f"Задача: разобрать алерты сканера безопасности OWASP ZAP и сформировать "
            f"готовые промпты для ИИ-кодера по безопасному устранению уязвимостей в коде.\n\n"
            + "\n".join(items_desc)
            + "\nВыполни полный процесс строго по инструкции: "
            "ШАГ 1 (Валидация вердикта), ШАГ 2 (Контекст), ШАГ 2.5 (Подтверждение), ШАГ 3 (Стек), ШАГ 4 (Формирование промпта для кодера)."
        )

        # Перебор моделей fallback-цепочки
        model_chain = self._build_model_chain()
        raw_text = ""
        for model_name in model_chain:
            logger.info("AI-аудит: пробуем модель %s...", model_name)
            raw_text = await self._try_generate(model_name, prompt_body) or ""
            if raw_text:
                break
            logger.warning("Модель %s не дала результата, переходим к следующей.", model_name)

        if not raw_text:
            logger.error(
                "Все %d моделей из fallback-цепочки недоступны. Возвращаем базовую заглушку.",
                len(model_chain),
            )
            return self._build_fallback_stub(filtered_alerts, target_url)

        header = (
            f"⚡ <b>AppSec Fixes & AI Prompts</b> ◈ <code>{target_url}</code>\n"
            f"────────────────────────\n\n"
        )
        return split_text_safe(header + raw_text, max_chunk_size=3900)
