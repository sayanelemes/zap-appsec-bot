import hashlib
import hmac
import json
import logging
from typing import Any
from urllib.parse import parse_qsl, unquote

from fastapi import Header, HTTPException, status
from bot.config.config import settings

logger = logging.getLogger(__name__)


def verify_telegram_webapp_data(init_data: str, bot_token: str) -> dict[str, Any] | None:
    """
    Валидация строки Telegram WebApp initData по алгоритму HMAC-SHA256:
    1. Извлекается hash.
    2. Все остальные пары ключ=значение сортируются по ключу и объединяются через \n.
    3. Вычисляется secret_key = HMAC_SHA256(b"WebAppData", bot_token.encode()).
    4. Вычисляется подпись HMAC_SHA256(secret_key, data_check_string.encode()).
    5. Сравнивается с переданным hash.
    Возвращает словарь с данными сессии (включая 'user') или None при ошибке.
    """
    if not init_data or not bot_token:
        return None

    try:
        parsed_items = parse_qsl(init_data, keep_blank_values=True)
        data_dict = dict(parsed_items)

        received_hash = data_dict.pop("hash", None)
        if not received_hash:
            return None

        # Формирование строки проверки (data_check_string)
        sorted_pairs = sorted(data_dict.items(), key=lambda x: x[0])
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted_pairs)

        # Вычисление HMAC secret_key
        secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
        computed_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(computed_hash, received_hash):
            logger.warning("Несовпадение HMAC подписи Telegram WebApp initData")
            return None

        result: dict[str, Any] = dict(data_dict)
        if "user" in result:
            try:
                result["user"] = json.loads(result["user"])
            except Exception:
                pass

        return result
    except Exception as e:
        logger.warning("Ошибка разбора initData Telegram WebApp: %s", e)
        return None


async def get_current_tma_user(
    x_telegram_init_data: str | None = Header(default=None, alias="X-Telegram-Init-Data"),
) -> dict[str, Any]:
    """
    FastAPI Dependency для проверки авторизации пользователя через Telegram Mini App.
    Проверяет HMAC-подпись и права доступа (ALLOWED_USERS / ADMIN_IDS).
    """
    # Если заголовок отсутствует
    if not x_telegram_init_data:
        # Для локальной разработки / запуска вне iframe Telegram разрешаем если whitelist пуст
        if settings and not settings.ADMIN_IDS and not settings.ALLOWED_USERS:
            return {"id": 0, "username": "anonymous_local", "is_admin": True}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Отсутствует заголовок X-Telegram-Init-Data. Запуск разрешен только из Telegram Mini App.",
        )

    token = settings.BOT_TOKEN.get_secret_value() if (settings and settings.BOT_TOKEN) else ""
    validated_data = verify_telegram_webapp_data(x_telegram_init_data, token)

    if not validated_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительная цифровая подпись Telegram WebApp initData.",
        )

    user_info = validated_data.get("user")
    if not user_info or not isinstance(user_info, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не удалось извлечь профиль пользователя из initData.",
        )

    user_id = user_info.get("id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ID пользователя отсутствует в сессии.",
        )

    # Проверка белого списка
    if settings and not settings.is_user_allowed(int(user_id)):
        logger.warning("Пользователю %s запрещен доступ к TMA (нет в Whitelist)", user_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ к панели управления SOC Scanner запрещен администратором.",
        )

    return user_info
