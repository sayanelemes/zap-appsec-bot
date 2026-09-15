# =================================================================
# Dockerfile для запуска Telegram-бота в production
# =================================================================
FROM python:3.11-slim AS base

# Переменные окружения Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Установка системных зависимостей при необходимости компиляции
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Копирование и установка Python зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Создаем непривилегированного пользователя для безопасности
RUN useradd -m -u 1000 botuser && \
    mkdir -p /app/logs && \
    chown -R botuser:botuser /app

# Копирование исходного кода проекта
COPY --chown=botuser:botuser . .

USER botuser

# Команда по умолчанию
CMD ["python", "-m", "bot.main"]
