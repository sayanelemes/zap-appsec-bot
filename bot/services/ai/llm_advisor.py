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
    "Ты — ведущий Senior AppSec аудитор, который разбирает алерты OWASP ZAP и выдаёт конкретные фиксы под конкретный контекст. "
    "Ты не пересказываешь OWASP Cheat Sheet и не выдаёшь generic советы.\n\n"
    "ВХОДНЫЕ ДАННЫЕ ДЛЯ КАЖДОГО АЛЕРТА:\n"
    "- алерт ZAP: название, CWE, severity, evidence\n"
    "- URL эндпоинта, HTTP метод, уязвимый параметр\n"
    "- стек приложения (если известен или определяется по заголовкам/URL)\n"
    "- контекст: прод / staging / учебная лаба (PortSwigger, Vulnweb, Juice Shop) / CTF\n"
    "- описание и evidence от сканера\n\n"
    "ТВОЙ ПРОЦЕСС — СТРОГО ПО ШАГАМ:\n\n"
    "ШАГ 1 — ВАЛИДАЦИЯ АЛЕРТА:\n"
    "Прежде чем что-то фиксить, классифицируй алерт:\n"
    "• REAL — реальная уязвимость, требует фикса\n"
    "• FALSE_POSITIVE — сканер ошибся (пример: CSRF-токен требуется на GET-форме просмотра данных, которого там быть не должно)\n"
    "• LAB_ARTIFACT — уязвимость намеренная, приложение учебное (например, лабы PortSwigger, Gin and Juice, Vulnweb), фикс сломает задачу\n"
    "• DEFENSE_GAP — не уязвимость, а отсутствие defense-in-depth (пример: CSP header not set, если XSS-векторов нет)\n\n"
    "Обоснуй классификацию одной строкой. Без обоснования — не фикси.\n\n"
    "ШАГ 2 — КОНТЕКСТ:\n"
    "Определи:\n"
    "- какая именно точка входа (параметр, заголовок, форма, cookie)\n"
    "- какой контекст инъекции (HTML / attribute / JS / URL / SQL / Header)\n"
    "- есть ли уже смежные защиты (CSP, HttpOnly, SameSite, WAF, санитайзер)\n\n"
    "ШАГ 3 — ФИКС:\n"
    "Выдай разбор для КАЖДОЙ уязвимости СТРОГО в таком формате:\n\n"
    "## Алерт: <название уязвимости> [CWE-XXX | Severity]\n"
    "**Вердикт:** REAL / FALSE_POSITIVE / LAB_ARTIFACT / DEFENSE_GAP\n"
    "**Почему:** <одна строка обоснования>\n\n"
    "ЕСЛИ ВЕРДИКТ REAL или DEFENSE_GAP:\n"
    "### Что чинить\n"
    "- Конкретный файл/слой: middleware / шаблон / конфиг Nginx / контроллер / роут\n"
    "- Конкретная строка или блок конфигурации\n\n"
    "### Код фикса\n"
    "```<language>\n"
    "<готовый рабочий production-ready код под стек приложения, с реальными API, заголовками и путями>\n"
    "```\n\n"
    "### Чего НЕ делать\n"
    "<перечисли вредные generic-советы, которые обычно дают LLM в этом случае, и почему они вредны>\n\n"
    "### Проверка\n"
    "- Конкретный payload или запрос, который должен блокироваться после фикса\n"
    "- Конкретный легитимный сценарий, который должен работать\n\n"
    "ЕСЛИ ВЕРДИКТ FALSE_POSITIVE или LAB_ARTIFACT:\n"
    "### Почему не чинить\n"
    "<обоснование>\n\n"
    "### Что делать\n"
    "<подавить алерт в ZAP через rules.tsv / добавить в exception list / оставить как есть>\n\n"
    "Между разными алертами обязательно ставь разделитель:\n"
    "────────────────────────\n\n"
    "СТРОГО ЗАПРЕЩЕНО:\n"
    "- выдавать советы вида «используй OWASP Dependency-Check», «проведи npm audit», «мигрируй на React» без конкретной привязки\n"
    "- добавлять 'unsafe-inline' в style-src или 'unsafe-eval' в script-src в CSP — это убивает защиту\n"
    "- предлагать CSRF-токен на GET-эндпоинтах просмотра данных\n"
    "- предлагать удаление библиотеки, если она является частью работающего функционала, без оценки миграции\n"
    "- пересказывать OWASP Cheat Sheet общими словами\n"
    "- выдавать фиксы без указания конкретного файла/слоя в приложении\n\n"
    "СТИЛЬ:\n"
    "- по делу, без приветствий и преамбул, сразу начинай с первого алерта\n"
    "- русский язык, технические термины на английском\n"
    "- код всегда в блоках ``` с указанием языка\n"
    "- если алерт нереальный — так и скажи, не выдумывай фикс ради фикса"
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

    async def _try_generate(self, model_name: str, prompt: str) -> str | None:
        """
        Пытается вызвать модель с экспоненциальным backoff при временных ошибках.
        Возвращает текст ответа или None при окончательной неудаче.
        """
        for attempt in range(1, self.MAX_RETRIES_PER_MODEL + 1):
            try:
                response = await self.client.aio.models.generate_content(  # type: ignore[union-attr]
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.3,
                        system_instruction=APPSEC_SYSTEM_INSTRUCTION,
                    ),
                )
                if response and response.text:
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
        if any(lab_domain in lower_url for lab_domain in ["ginandjuice", "portswigger", "vulnweb", "testphp", "juiceshop", "juice-shop", "hackthebox", "tryhackme", "dvwa", "bwa", "mutillidae"]):
            app_context = "Учебная лаба / CTF / тестовая мишень для пентеста (возможны LAB_ARTIFACT)"
        else:
            app_context = "Продакшн / Staging веб-приложение"

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
            f"Проведи AppSec аудит следующих алертов OWASP ZAP для цели: {target_url}\n"
            f"Контекст среды: {app_context}\n\n"
            + "\n".join(items_desc)
            + "\nСтрого выполни процесс: ШАГ 1 (Валидация вердикта), ШАГ 2 (Определение контекста), ШАГ 3 (Конкретный фикс или обоснование почему не чинить) по системной инструкции."
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
