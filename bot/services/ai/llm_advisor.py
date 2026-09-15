import asyncio
import logging
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


class LlmAdvisorService:
    """
    Асинхронный сервис AI-аудита безопасности веб-приложений через Google Gemini API.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-3.6-flash"):
        self.api_key = api_key or (settings.GEMINI_API_KEY.get_secret_value() if settings and settings.GEMINI_API_KEY else None)
        self.model = model
        self.client: Optional[genai.Client] = create_gemini_client(self.api_key)

    async def analyze_vulnerabilities(
        self,
        alerts: list[dict[str, Any]],
        target_url: str,
    ) -> list[str]:
        """
        Принимает сырой список алертов ZAP, выполняет дедупликацию, выполняет санитизацию,
        формирует запрос к LLM и возвращает список сообщений-рекомендаций.
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

        # Формируем строго санитизированное описание уязвимостей для промпта (без сырого HTML/JS)
        items_desc = []
        for idx, item in enumerate(filtered_alerts, 1):
            alert_name = sanitize_text_for_llm(item.get("alert", "Unknown"), 120)
            risk = sanitize_text_for_llm(item.get("risk", "Low"), 30)
            param = sanitize_text_for_llm(item.get("param", ""), 80) or "—"
            url = sanitize_text_for_llm(item.get("url", target_url), 200)
            method = sanitize_text_for_llm(item.get("method", "GET"), 10)
            cwe = sanitize_text_for_llm(item.get("cweid", "—"), 20)
            desc = sanitize_text_for_llm(item.get("description", ""), 250)
            evidence = sanitize_text_for_llm(item.get("evidence", ""), 100)

            items_desc.append(
                f"### Уязвимость #{idx}: {alert_name} (Риск: {risk})\n"
                f"- Целевой URL / Эндпоинт: {url}\n"
                f"- HTTP Метод: {method}\n"
                f"- Уязвимый параметр / заголовок / селектор: {param}\n"
                f"- CWE ID: {cwe}\n"
                f"- Evidence (фрагмент детекции): {evidence if evidence else 'Не указано'}\n"
                f"- Техническое описание проблемы: {desc}\n"
            )

        prompt_body = (
            f"Проанализируй обнаруженные уязвимости для веб-приложения: {target_url}\n\n"
            + "\n".join(items_desc)
            + "\nДля КАЖДОЙ уязвимости строго сформируй два блока: "
            "(1) '💡 Что это такое простыми словами' и "
            "(2) '🤖 Промпт для AI-агента (Cursor / Antigravity / Claude Code)' строго по системной инструкции."
        )

        models_to_try = [
            self.model,
            "gemini-3.6-flash",
            "gemini-3.7-flash",
            "gemini-3.5-flash",
            "gemini-flash-latest",
        ]
        # Убираем дубликаты сохраняя порядок
        seen_models = set()
        models_to_try = [m for m in models_to_try if not (m in seen_models or seen_models.add(m))]

        raw_response_text = ""
        last_error_msg = ""

        for model_name in models_to_try:
            for attempt in range(1, 3):
                try:
                    response = await self.client.aio.models.generate_content(
                        model=model_name,
                        contents=prompt_body,
                        config=types.GenerateContentConfig(
                            temperature=0.3,  # Низкая температура для строгих технических рекомендаций
                            system_instruction=APPSEC_SYSTEM_INSTRUCTION,
                        ),
                    )
                    if response and response.text:
                        raw_response_text = response.text
                        break
                except errors.APIError as e:
                    last_error_msg = str(e.message or e)
                    # Если 503 (высокая нагрузка) или 429 (рейтлимит) — кратковременная пауза и повтор
                    is_transient = e.code in (503, 429) or "UNAVAILABLE" in str(e).upper() or "RESOURCE_EXHAUSTED" in str(e).upper()
                    if is_transient and attempt < 2:
                        logger.warning(
                            "Модель %s временно перегружена (код %s, попытка %d/2). Ожидание 1.5с...",
                            model_name, e.code, attempt,
                        )
                        await asyncio.sleep(1.5)
                        continue
                    logger.warning("Модель %s вернула ошибку API (%s). Пробуем следующую...", model_name, e)
                    break
                except Exception as e:
                    last_error_msg = str(e)
                    logger.error("Ошибка при генерации рекомендаций безопасности через %s: %s", model_name, e)
                    break

            if raw_response_text:
                break

        if not raw_response_text:
            logger.error("Все доступные AI-модели вернули ошибку. Последняя: %s", last_error_msg)
            return [
                "⚠️ <b>Нейросеть временно недоступна:</b> серверы Gemini перегружены (высокий спрос на модель / 503).\n"
                "Пожалуйста, повторите запрос через несколько секунд."
            ]

        header = (
            f"⚡ <b>AppSec Fixes & AI Prompts</b> ◈ <code>{target_url}</code>\n"
            f"────────────────────────\n\n"
        )
        full_text = header + raw_response_text

        return split_text_safe(full_text, max_chunk_size=3900)
