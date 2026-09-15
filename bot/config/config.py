from typing import Any, Union
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Конфигурация приложения на основе Pydantic Settings.
    Автоматически считывает и валидирует переменные из окружения и .env файла.
    """

    # Название бота
    BOT_NAME: str = "ZAP AppSec AI Auditor"

    # Обязательный токен бота
    BOT_TOKEN: SecretStr

    # Список Telegram ID администраторов (принимает строку, число или список, возвращает list[int])
    ADMIN_IDS: Union[list[int], str, int] = []

    # Список разрешенных пользователей (Whitelist). Если задан, доступ имеют только эти ID и ADMIN_IDS.
    ALLOWED_USERS: Union[list[int], str, int] = []

    # Уровень логирования
    LOG_LEVEL: str = "INFO"

    # Задержка между запросами для антиспам-мидлваря (в секундах)
    THROTTLE_RATE: float = 0.5

    # Конфигурация Google GenAI (Gemini)
    GEMINI_API_KEY: SecretStr | None = None
    GEMINI_MODEL: str = "gemini-3.6-flash"
    GEMINI_TEMPERATURE: float = 0.7
    MAX_CONTEXT_HISTORY: int = 10

    # Конфигурация OWASP ZAP
    ZAP_URL: str = "http://zap:8080"
    ZAP_PROXY: str = "http://127.0.0.1:8090"
    ZAP_API_KEY: SecretStr | None = None

    @property
    def zap_endpoint(self) -> str:
        return self.ZAP_PROXY or self.ZAP_URL

    def is_user_allowed(self, user_id: int) -> bool:
        """Проверяет, разрешен ли доступ пользователю по Whitelist и Admin спискам."""
        allowed: set[int] = set()
        if isinstance(self.ADMIN_IDS, list):
            allowed.update(self.ADMIN_IDS)
        if isinstance(self.ALLOWED_USERS, list):
            allowed.update(self.ALLOWED_USERS)
        if not allowed:
            return True
        return user_id in allowed

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("ADMIN_IDS", "ALLOWED_USERS", mode="before")
    @classmethod
    def parse_admin_ids(cls, v: Any) -> list[int]:
        """
        Позволяет задавать ADMIN_IDS и ALLOWED_USERS как списком JSON ([123, 456]),
        так и строкой через запятую ("123, 456, 789").
        """
        if isinstance(v, str):
            v = v.strip().strip("[]")
            if not v:
                return []
            return [int(item.strip()) for item in v.split(",") if item.strip()]
        elif isinstance(v, (list, tuple, set)):
            return [int(item) for item in v]
        elif isinstance(v, int):
            return [v]
        return []



# Глобальный синглтон настроек
# При импорте будет лениво инициализирован или проверен в main.py
def get_settings() -> Settings:
    return Settings()


try:
    settings = get_settings()
except Exception:
    # Позволяет импортировать файл даже если .env еще не создан (например, при вызове справки или генерации конфигов)
    settings = None  # type: ignore[assignment]
