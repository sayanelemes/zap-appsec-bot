import asyncio
import logging
import re
from typing import Any, Optional
from google import genai
from google.genai import errors, types

from bot.config.config import settings
from bot.services.ai.client import create_gemini_client

logger = logging.getLogger(__name__)

APPSEC_SYSTEM_INSTRUCTION = (
    "Вы — ведущий Senior AppSec инженер и разработчик систем автономного кодинга (Cursor, Antigravity, Claude Code).\n"
    "Сформируйте предельно практичный, структурированный разбор уязвимостей без воды, "
    "без дежурных приветствий, без вводных фраз и без общих заключений.\n\n"
    "Для КАЖДОЙ уникальной уязвимости сформируйте карточку, состоящую СТРОГО из двух смысловых блоков:\n\n"
    "◈ <b>НАЗВАНИЕ УЯЗВИМОСТИ</b> [<code>CWE-XXX</code> | 🔴 High / 🟠 Medium / 🟡 Low]\n\n"
    "💡 <b>Что это такое простыми словами:</b>\n"
    "<blockquote>"
    "• Суть проблемы: 2–3 понятных предложения без академического занудства и сложного жаргона.\n"
    "• Сценарий атаки: как злоумышленник может использовать это на практике и какой конкретно ущерб (утечка базы, перехват сессий, подмена контента) нанести."
    "</blockquote>\n\n"
    "🤖 <b>Промпт для AI-агента (Cursor / Antigravity / Claude Code):</b>\n"
    "```\n"
    "/goal Устранить уязвимость [Название] ([CWE]) на эндпоинте [URL или имя параметра]\n\n"
    "1. Контекст:\n"
    "- Сканер ZAP обнаружил: [краткое описание дефекта].\n"
    "- Уязвимый эндпоинт/URL: [URL]\n"
    "- Параметр / заголовок / селектор: [параметр или заголовок]\n"
    "- Evidence / подтверждение: [evidence]\n\n"
    "2. Пошаговый план поиска файлов в проекте:\n"
    "- Найти обработчик/маршрут/контроллер для данного URL или параметра.\n"
    "- Найти связанные шаблоны, компоненты UI или DTO-схемы валидации.\n"
    "- Проверить middleware обработки запросов и конфигурацию веб-сервера (Nginx / Caddy / Traefik / Dockerfile), если баг связан с заголовками безопасности или CORS.\n\n"
    "3. Инструкция по внедрению безопасного решения (OWASP Best Practices):\n"
    "- [Конкретные правила: параметризация SQL, allowlist-валидация входящих значений, экранирование в DOM, строгие заголовки CSP/HSTS/X-Content-Type, проверка CSRF-токенов].\n"
    "- Привести минимальный чистый фрагмент безопасного кода или конфигурации.\n\n"
    "4. Критерии приемки (Definition of Done):\n"
    "- Проект собирается и запускается без ошибок линтинга и компиляции.\n"
    "- Легитимные пользовательские запросы к эндпоинту отрабатывают стабильно (HTTP 200).\n"
    "- Попытки передачи вредоносных пейлоадов надежно блокируются или валидируются с кодами 400/403/422.\n"
    "```\n\n"
    "Между карточками разных уязвимостей обязательно вставляйте разделитель:\n"
    "────────────────────────\n\n"
    "СТРОГИЕ ТРЕБОВАНИЯ:\n"
    "1. Блок промпта для AI-агента ОБЯЗАТЕЛЬНО оформляйте в виде блока кода (fenced code block ```), "
    "чтобы пользователь в Telegram мог скопировать его целиком в один клик.\n"
    "2. Промпт внутри блока кода ВСЕГДА начинается со строки: /goal Устранить уязвимость ...\n"
    "3. Не добавляйте никакого лишнего текста до или после карточек. Сразу переходите к первой карточке."
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


# Приоритетный список моделей Gemini в порядке предпочтения.
# При 503/429 последовательно перебираем с экспоненциальным backoff.
GEMINI_FALLBACK_CHAIN = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
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
        # Пользовательская модель ставится первой в цепочке
        self._preferred_model = model
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

        # Формируем санитизированный промпт
        items_desc = []
        for idx, item in enumerate(filtered_alerts, 1):
            alert_name = sanitize_text_for_llm(item.get("alert", "Unknown"), 120)
            risk       = sanitize_text_for_llm(item.get("risk", "Low"), 30)
            param      = sanitize_text_for_llm(item.get("param", ""), 80) or "—"
            url        = sanitize_text_for_llm(item.get("url", target_url), 200)
            method     = sanitize_text_for_llm(item.get("method", "GET"), 10)
            cwe        = sanitize_text_for_llm(item.get("cweid", "—"), 20)
            desc       = sanitize_text_for_llm(item.get("description", ""), 250)
            evidence   = sanitize_text_for_llm(item.get("evidence", ""), 100)
            items_desc.append(
                f"### Уязвимость #{idx}: {alert_name} (Риск: {risk})\n"
                f"- Целевой URL / Эндпоинт: {url}\n"
                f"- HTTP Метод: {method}\n"
                f"- Уязвимый параметр / заголовок / селектор: {param}\n"
                f"- CWE ID: {cwe}\n"
                f"- Evidence: {evidence or 'Не указано'}\n"
                f"- Техническое описание: {desc}\n"
            )

        prompt_body = (
            f"Проанализируй обнаруженные уязвимости для веб-приложения: {target_url}\n\n"
            + "\n".join(items_desc)
            + "\nДля КАЖДОЙ уязвимости строго сформируй два блока: "
            "(1) '💡 Что это такое простыми словами' и "
            "(2) '🤖 Промпт для AI-агента' строго по системной инструкции."
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
