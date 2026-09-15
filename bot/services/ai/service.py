import asyncio
import logging
from typing import Any, AsyncIterator, Optional, Protocol, Sequence
from google import genai
from google.genai import errors, types


class DialogMessageProtocol(Protocol):
    role: str
    content: str


from bot.services.ai.client import create_gemini_client
from bot.services.ai.prompts import DEFAULT_SYSTEM_INSTRUCTION

logger = logging.getLogger(__name__)


class GeminiService:
    """
    Асинхронный сервис взаимодействия с моделями Gemini (Google GenAI).
    Управляет скользящим окном истории, системным промптом, мультимодальными данными
    и обработкой специфичных ошибок API (Safety, Rate Limit 429, таймауты).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-3.6-flash",
        temperature: float = 0.7,
        max_history: int = 10,
        system_instruction: str = DEFAULT_SYSTEM_INSTRUCTION,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_history = max_history
        self.system_instruction = system_instruction
        self.client: Optional[genai.Client] = create_gemini_client(api_key)

    def format_history_to_contents(
        self,
        history: Sequence[DialogMessageProtocol] | Sequence[Any],
        current_text: Optional[str] = None,
        media_part: Optional[types.Part] = None,
    ) -> list[types.Content]:
        """
        Конвертирует историю сообщений из БД в список types.Content для Gemini API.
        Обеспечивает строгое чередование ролей 'user' -> 'model' -> 'user'.
        """
        contents: list[types.Content] = []

        # Берем последние N сообщений в рамках скользящего окна
        recent_history = list(history[-self.max_history :]) if history else []

        for msg in recent_history:
            role = "user" if msg.role == "user" else "model"

            # Первое сообщение в Gemini API обязательно должно быть от 'user'
            if not contents and role != "user":
                continue

            # Если две одинаковые роли идут подряд, объединяем текст
            if contents and contents[-1].role == role:
                existing_parts = contents[-1].parts
                if existing_parts and hasattr(existing_parts[0], "text"):
                    existing_text = existing_parts[0].text or ""
                    existing_parts[0].text = f"{existing_text}\n{msg.content}"
                else:
                    contents[-1].parts.append(types.Part.from_text(text=msg.content))
            else:
                contents.append(
                    types.Content(
                        role=role,
                        parts=[types.Part.from_text(text=msg.content)],
                    )
                )

        # Формируем части текущего сообщения
        current_parts: list[types.Part] = []
        if media_part is not None:
            current_parts.append(media_part)
        if current_text:
            current_parts.append(types.Part.from_text(text=current_text))
        elif not current_parts:
            current_parts.append(types.Part.from_text(text=""))

        # Добавляем текущий запрос в конец
        if contents and contents[-1].role == "user":
            contents[-1].parts.extend(current_parts)
        else:
            contents.append(types.Content(role="user", parts=current_parts))

        return contents

    async def generate_response(
        self,
        history: Sequence[DialogMessage],
        prompt: Optional[str] = None,
        media_part: Optional[types.Part] = None,
    ) -> str:
        """
        Отправляет запрос к Gemini API и возвращает сгенерированный текстовый ответ.
        Перехватывает и обрабатывает исключения квот, безопасности и таймаутов.
        """
        if self.client is None:
            return (
                "⚠️ <b>API-ключ Gemini не настроен.</b>\n\n"
                "Для включения нейросети получите бесплатный ключ в "
                "<a href=\"https://aistudio.google.com/app/apikey\">Google AI Studio</a> "
                "и укажите его в переменной <code>GEMINI_API_KEY</code> в файле <code>.env</code>."
            )

        contents = self.format_history_to_contents(
            history=history,
            current_text=prompt,
            media_part=media_part,
        )

        models_to_try = [self.model]
        for fallback_name in ("gemini-3.6-flash", "gemini-2.0-flash", "gemini-1.5-flash"):
            if fallback_name not in models_to_try:
                models_to_try.append(fallback_name)

        try:
            response = None
            for current_model in models_to_try:
                try:
                    response = await asyncio.wait_for(
                        self.client.aio.models.generate_content(
                            model=current_model,
                            contents=contents,
                            config=types.GenerateContentConfig(
                                temperature=self.temperature,
                                system_instruction=self.system_instruction,
                            ),
                        ),
                        timeout=60.0,
                    )
                    if current_model != self.model:
                        logger.info("Успешный переход с %s на доступную модель %s", self.model, current_model)
                        self.model = current_model
                    break
                except errors.APIError as e:
                    if e.code == 404 and current_model != models_to_try[-1]:
                        logger.warning("Модель %s вернула 404 (недоступна). Пробуем fallback...", current_model)
                        continue
                    raise


            # Проверка фильтров безопасности (Safety Filters)
            if response.candidates:
                candidate = response.candidates[0]
                finish_reason_str = str(getattr(candidate, "finish_reason", "")).upper()
                if "SAFETY" in finish_reason_str:
                    logger.warning("Запрос к Gemini заблокирован фильтром безопасности.")
                    return "⚠️ Запрос не может быть обработан из-за ограничений безопасности (Safety Filter)."
                if "RECITATION" in finish_reason_str:
                    return "⚠️ Ответ не может быть показан из-за ограничений авторского права (Recitation Filter)."

            text = response.text
            if not text:
                return "⚠️ Модель не сгенерировала ответ. Попробуйте переформулировать запрос."

            return text.strip()

        except errors.APIError as e:
            logger.error("Ошибка Gemini API: код=%s, сообщение=%s", e.code, e.message)
            # Ошибка 429: исчерпание лимитов RPM/TPM
            if e.code == 429 or "RESOURCE_EXHAUSTED" in str(e).upper():
                return (
                    "⏳ <b>Превышен лимит запросов к нейросети (Rate Limit).</b>\n"
                    "Пожалуйста, подождите 10–15 секунд и отправьте запрос снова."
                )
            # Ошибка авторизации (400, 401, 403)
            if e.code in (400, 401, 403) or "API_KEY_INVALID" in str(e).upper():
                return (
                    "⚠️ <b>Ошибка авторизации Gemini API.</b>\n"
                    "Проверьте правильность значения <code>GEMINI_API_KEY</code> в файле <code>.env</code>."
                )
            return f"⚠️ Ошибка Gemini API ({e.code}): Попробуйте повторить позже."

        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("Таймаут при запросе к Gemini API.")
            return "⏱️ <b>Время ожидания ответа истекло.</b> Сервер перегружен, попробуйте снова через минуту."

        except Exception as e:
            logger.exception("Непредвиденное исключение при генерации в Gemini: %s", e)
            return "⚠️ <b>Произошла ошибка при обращении к нейросети.</b> Попробуйте позже."

    async def generate_response_stream(
        self,
        history: Sequence[DialogMessage],
        prompt: Optional[str] = None,
        media_part: Optional[types.Part] = None,
    ) -> AsyncIterator[str]:
        """
        Асинхронный генератор для потоковой отдачи текста (стриминг ответа в реальном времени, как в приложении).
        """
        if self.client is None:
            yield (
                "⚠️ <b>API-ключ Gemini не настроен.</b>\n\n"
                "Для включения нейросети получите бесплатный ключ в "
                "<a href=\"https://aistudio.google.com/app/apikey\">Google AI Studio</a> "
                "и укажите его в переменной <code>GEMINI_API_KEY</code> в файле <code>.env</code>."
            )
            return

        contents = self.format_history_to_contents(
            history=history,
            current_text=prompt,
            media_part=media_part,
        )

        models_to_try = [self.model]
        for fallback_name in ("gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.5-flash", "gemini-flash-latest"):
            if fallback_name not in models_to_try:
                models_to_try.append(fallback_name)

        stream = None
        for current_model in models_to_try:
            try:
                stream = await self.client.aio.models.generate_content_stream(
                    model=current_model,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        temperature=self.temperature,
                        system_instruction=self.system_instruction,
                    ),
                )

                if current_model != self.model:
                    self.model = current_model
                break
            except errors.APIError as e:
                if e.code == 404 and current_model != models_to_try[-1]:
                    continue
                logger.error("Ошибка Gemini API при старте стриминга: %s", e)
                yield f"⚠️ Ошибка Gemini API ({e.code}): Попробуйте повторить позже."
                return

        if stream is None:
            yield "⚠️ Не удалось подключиться к модели Gemini."
            return

        try:
            async for chunk in stream:
                if chunk.candidates:
                    cand = chunk.candidates[0]
                    finish_reason_str = str(getattr(cand, "finish_reason", "")).upper()
                    if "SAFETY" in finish_reason_str:
                        yield "\n\n⚠️ <i>[Ответ прерван фильтром безопасности]</i>"
                        return
                    if "RECITATION" in finish_reason_str:
                        yield "\n\n⚠️ <i>[Ответ прерван ограничением авторского права]</i>"
                        return

                if chunk.text:
                    yield chunk.text

        except errors.APIError as e:
            logger.error("Ошибка Gemini API в процессе стриминга: %s", e)
            if e.code == 429 or "RESOURCE_EXHAUSTED" in str(e).upper():
                yield "\n\n⏳ <b>Превышен лимит запросов к нейросети (Rate Limit).</b>"
            else:
                yield f"\n\n⚠️ Ошибка API ({e.code})."
        except (asyncio.TimeoutError, TimeoutError):
            yield "\n\n⏱️ <b>Время ожидания ответа истекло.</b>"
        except Exception as e:
            logger.exception("Ошибка при чтении стрима: %s", e)
            yield "\n\n⚠️ Ошибка при генерации текста."

