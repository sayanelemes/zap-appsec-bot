# 🚀 Telegram Bot Boilerplate (aiogram 3.x + SQLAlchemy 2.0)

Модульный, отказоустойчивый и масштабируемый шаблон (каркас) для быстрого старта разработки Telegram-ботов на **Python 3.11+**.

---

## 🛠 Стек технологий

* **Фреймворк:** [aiogram 3.x](https://docs.aiogram.dev/) (полная асинхронность, Routers, FSM, типизированные фильтры)
* **AI & LLM:** [google-genai](https://github.com/googleapis/python-genai) (Google GenAI SDK для Gemini 2.5 Flash / Pro, нативная мультимодальность для текста, фото и аудио)
* **База данных:** [SQLAlchemy 2.0](https://docs.sqlalchemy.org/) (Asyncio) + `aiosqlite` (для локальной разработки) / `asyncpg` (для PostgreSQL в production)

* **Миграции:** [Alembic](https://alembic.sqlalchemy.org/) с поддержкой асинхронного выполнения
* **Конфигурация:** [Pydantic-Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) (строгая валидация `.env`, типов и обязательных полей)
* **FSM & Кэш:** Встроенный `MemoryStorage` с поддержкой переключения на `RedisStorage`
* **Логирование:** Стандартный модуль `logging` с одновременным выводом в консоль и ротацией файлов (`RotatingFileHandler` в `logs/bot.log`)
* **Контейнеризация:** Готовые `Dockerfile` и `docker-compose.yml` (PostgreSQL 16 + Redis + Bot)

---

## 📂 Структура проекта

```text
bot_template/
├── alembic/
│   ├── env.py                  # Асинхронный запуск миграций с привязкой Base.metadata
│   ├── script.py.mako          # Шаблон файлов миграций
│   └── versions/               # Сгенерированные миграции
├── bot/
│   ├── config/
│   │   ├── __init__.py
│   │   └── config.py           # Валидация настроек через Pydantic Settings
│   ├── database/
│   │   ├── models/             # Описание моделей (Base, User)
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   └── user.py
│   │   ├── requests/           # CRUD операции и запросы к БД
│   │   │   ├── __init__.py
│   │   │   └── user.py
│   │   ├── __init__.py
│   │   └── session.py          # Асинхронный движок и sessionmaker
│   ├── handlers/
│   │   ├── __init__.py         # Сборка и регистрация корневого роутера
│   │   ├── common.py           # /start, /help, FSM-анкета, fallback
│   │   └── errors.py           # Глобальный перехват и логирование исключений
│   ├── keyboards/
│   │   ├── __init__.py
│   │   ├── inline.py           # Генераторы Inline-кнопок и CallbackData
│   │   └── reply.py            # Постоянные Reply-клавиатуры
│   ├── middlewares/
│   │   ├── __init__.py
│   │   ├── db.py               # Внедрение AsyncSession в каждый хэндлер
│   │   └── throttling.py       # Rate limiting / антиспам middleware
│   ├── states/
│   │   ├── __init__.py
│   │   └── states.py           # FSM-состояния (StatesGroup)
│   ├── __init__.py
│   └── main.py                 # Точка входа: запуск, polling, graceful shutdown
├── logs/                       # Логи бота (ротация до 10 МБ, 5 файлов)
├── .env.example                # Пример файла с переменными окружения
├── .gitignore
├── alembic.ini                 # Конфигурация Alembic
├── Dockerfile                  # Production-ready образ бота
├── docker-compose.yml          # Бот + PostgreSQL 16 + Redis
├── requirements.txt            # Зависимости Python
└── README.md                   # Документация проекта
```

---

## ⚡ Быстрый старт (Локальное окружение)

### 1. Клонирование и переход в папку
```bash
cd bot_template
```

### 2. Создание и активация виртуального окружения
```bash
python3 -m venv .venv
source .venv/bin/activate  # На Linux/macOS
# .venv\Scripts\activate   # На Windows
```

### 3. Установка зависимостей
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Настройка окружения
Скопируйте файл `.env.example` в `.env`:
```bash
cp .env.example .env 
```
Откройте `.env` и укажите ваш `BOT_TOKEN`, полученный у [@BotFather](https://t.me/BotFather), а также ваш Telegram ID в `ADMIN_IDS`:
```dotenv
BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
ADMIN_IDS=123456789
DB_URL=sqlite+aiosqlite:///bot.db
```

### 5. Выполнение миграций Alembic
Примените миграции для создания таблиц в базе данных:
```bash
alembic upgrade head
```

### 6. Запуск бота
```bash
python -m bot.main
```

---

## 🐳 Запуск через Docker Compose (PostgreSQL + Redis)

Для развертывания в изолированных контейнерах с PostgreSQL и Redis выполните:

1. Настройте файл `.env`:
   ```dotenv
   BOT_TOKEN=ваш_токен_бота
   ADMIN_IDS=ваш_telegram_id
   POSTGRES_USER=bot_user
   POSTGRES_PASSWORD=bot_secure_password
   POSTGRES_DB=bot_db
   ```

2. Соберите и запустите контейнеры:
   ```bash
   docker compose up -d --build
   ```

3. Просмотр логов:
   ```bash
   docker compose logs -f bot
   ```

Миграции базы данных применяются автоматически при каждом старте контейнера бота (`alembic upgrade head`).

---

## 🗄 Работа с миграциями Alembic

### Создание новой миграции после изменения моделей:
```bash
alembic revision --autogenerate -m "Описание изменений"
```

### Применение миграций:
```bash
alembic upgrade head
```

### Откат последней миграции:
```bash
alembic downgrade -1
```

---

## 🤖 AI-модуль (Google Gemini)

Каркас оснащен готовым сервисным слоем для работы с **Gemini API** через официальный SDK `google-genai`:

### 1. Возможности
* **Текстовые диалоги:** Поддержание контекста разговора (скользящее окно `MAX_CONTEXT_HISTORY`), сохранение истории в базе данных (`dialog_messages`).
* **Нативная мультимодальность:**
  * **Фотографии (`F.photo`):** Бот принимает изображения, скачивает их и передает напрямую в модель для анализа, ответа на вопросы или описания.
  * **Голосовые сообщения (`F.voice`):** Бот принимает аудиосообщения Telegram (`.ogg` Opus), передает в Gemini для распознавания речи и формулирует текстовый ответ без сторонних сервисов транскрипции.
* **UX и отказоустойчивость:**
  * Непрерывный статус «печатает...» (`ChatActionSender.typing`) во время ожидания генерации.
  * Защита от спама: блокировка повторного запроса, пока обрабатывается текущий.
  * Безопасная отправка: автоматическое деление сообщений длиннее 4000 символов и fallback на plain text при сбоях разметки.
  * Обработка Safety Filters и Rate Limit 429 (`ResourceExhausted`).
  * Команды `/reset` и `/new_dialog` для мгновенной очистки контекста беседы.

### 2. Подключение
1. Получите бесплатный API-ключ в [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Добавьте его в `.env`:
   ```dotenv
   GEMINI_API_KEY=AIzaSy...ваш_ключ
   GEMINI_MODEL=gemini-2.5-flash
   GEMINI_TEMPERATURE=0.7
   MAX_CONTEXT_HISTORY=10
   ```

---

## 🧩 Руководство по расширению шаблона


### 1. Добавление новой таблицы в БД
1. Создайте модель в `bot/database/models/your_model.py`:
   ```python
   from sqlalchemy import String
   from sqlalchemy.orm import Mapped, mapped_column
   from bot.database.models.base import Base, TimestampMixin

   class Item(Base, TimestampMixin):
       __tablename__ = "items"

       id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
       title: Mapped[str] = mapped_column(String(100), nullable=False)
   ```
2. Экспортируйте новую модель в `bot/database/models/__init__.py`.
3. Создайте и примените миграцию:
   ```bash
   alembic revision --autogenerate -m "Add items table"
   alembic upgrade head
   ```

### 2. Добавление нового роутера хэндлеров
1. Создайте файл `bot/handlers/admin.py`:
   ```python
   from aiogram import Router
   from aiogram.filters import Command
   from aiogram.types import Message

   admin_router = Router(name="admin")

   @admin_router.message(Command("admin"))
   async def cmd_admin(message: Message):
       await message.answer("Панель администратора")
   ```
2. Подключите роутер в `bot/handlers/__init__.py`:
   ```python
   root_router.include_router(admin_router)
   ```

### 3. Доступ к сессии БД в любом хэндлере
Сессия `AsyncSession` автоматически передается мидлварью `DbSessionMiddleware` по имени аргумента `session`:
```python
@my_router.message(Command("my_command"))
async def my_handler(message: Message, session: AsyncSession):
    # Работа с базой данных
    user = await get_user_by_tg_id(session, message.from_user.id)
    ...
```

---

## 🛡 Безопасность и отказоустойчивость
* **Антиспам (Throttling):** Встроенная защита `ThrottlingMiddleware` отсекает повторные запросы пользователя с интервалом менее заданного `THROTTLE_RATE`.
* **Глобальный перехват ошибок:** Любое неожиданное исключение логируется с полным трейсбеком через `errors_router`, а пользователю отправляется понятное уведомление без падения процесса.
* **Graceful Shutdown:** При получении сигналов `SIGINT` или `SIGTERM` бот корректно закрывает соединения с БД, завершает HTTP-сессию и отправляет уведомление администраторам.



глоб