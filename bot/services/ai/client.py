import logging
from typing import Optional
from google import genai

logger = logging.getLogger(__name__)


def create_gemini_client(api_key: Optional[str]) -> Optional[genai.Client]:
    """
    Создает и возвращает экземпляр клиента Google GenAI Client.
    Если ключ не передан, возвращает None (сервис переходит в режим подсказки).
    """
    if not api_key or api_key.startswith("AIzaSy..."):
        logger.warning(
            "GEMINI_API_KEY не указан или содержит шаблонное значение. "
            "AI-модуль будет возвращать уведомление о необходимости настройки ключа."
        )
        return None

    try:
        client = genai.Client(api_key=api_key)
        logger.info("Клиент Google GenAI (Gemini) успешно инициализирован.")
        return client
    except Exception as e:
        logger.error("Ошибка при инициализации Google GenAI клиента: %s", e)
        return None
