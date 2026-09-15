# 🛡️ ZAP AppSec AI Auditor

Автономный Telegram-бот на **aiogram 3.x** для быстрого аудита безопасности веб-сайтов через **OWASP ZAP (Fast Scan)** и автоматической генерации исправлений от Senior AppSec AI-ассистента на базе **Google Gemini**.

---

## ⚡ Ключевые возможности

* **🛡️ Динамический анализ (DAST / OWASP ZAP):**
  * **Выбор глубины сканирования:**
    1. *Пассивный (5–10 сек)*: анализ заголовков, cookie, CSP без инъекций.
    2. *Быстрый (Fast Scan, 90 сек)*: Spider (глубина 2) + Active Scan с жестким лимитом времени 90с.
    3. *Глубокий (Full Scan, 5–10 мин)*: углубленный Spider (глубина 5) + полный Active Scan.
  * **🛑 Кнопка 'Стоп':** мгновенная экстренная остановка активного процесса сканирования в один клик.
  * **⚡ Ограничение ресурсов:** `asyncio.Semaphore(1)` предотвращает DoS сервера и перегрузку демона ZAP.
* **📦 Статический анализ зависимостей (SAST / GitHub + OSV.dev):**
  * Проверка публичных репозиториев по ссылке `https://github.com/owner/repo` без клонирования.
  * Анализ манифестов `requirements.txt` (Python / PyPI) и `package.json` (Node.js / npm).
  * Опрос API OSV.dev с парсингом CVE/GHSA, автоматическим расчетом баллов CVSS (0.0–10.0) и сопоставлением уровней риска (Critical / High / Medium / Low).
  * Рекомендация безопасных версий для обновления (Fixed in: >= x.x.x).
* **🔒 Защита инфраструктуры и периметра (Hardening):**
  * **SSRF-фильтр:** предварительный DNS-резолв и блокировка локальных, приватных адресов (RFC 1918, 127.0.0.0/8, 169.254.169.254, localhost, Cloud Metadata).
  * **Admin Whitelist:** ограничение доступа к боту по спискам `ALLOWED_USERS` и `ADMIN_IDS`.
  * **Санитизация промптов LLM:** передача в нейросеть только очищенных технических метаданных без сырого HTML/JS.
* **💡 Двухблочный AppSec AI-аудит (Gemini):**
  * **Блок 1 («Что это такое простыми словами»):** объяснение сути риска и реалистичного сценария атаки без академической воды.
  * **Блок 2 («Промпт для AI-агента»):** готовый блок кода для копирования в один клик, начинающийся с `/goal` (для Cursor, Antigravity, Claude Code) с контекстом, планом поиска файлов в проекте, рекомендациями OWASP и Definition of Done.
* **📄 Нативные HTML-отчеты:** генерация и мгновенная отправка полного отчета ZAP файлом в чат.
* **🚀 Полная автономность (Stateless):**
  * Работает без СУБД (нет PostgreSQL, SQLite, миграций или накладных расходов памяти).
  * Однострочный запуск и остановка ZAP и бота.
  * Настроенная автозагрузка через `systemd` и `Desktop Autostart`.

---

## 📂 Структура проекта

```text
zap-appsec-bot/
├── bot/
│   ├── config/              # Pydantic Settings конфигурация
│   │   └── config.py
│   ├── handlers/            # Обработчики Telegram
│   │   ├── zap_scan.py      # /check, /zap_status, двухэтапный AI-аудит
│   │   ├── common.py        # /start, /help, профиль и меню
│   │   ├── errors.py        # Глобальный перехват и логирование ошибок
│   │   └── __init__.py      # Корневой маршрутизатор
│   ├── keyboards/           # Клавиатуры
│   │   ├── inline.py        # Кнопка «💡 Получить аудит и код исправлений»
│   │   └── reply.py         # Меню быстрого доступа
│   ├── middlewares/         # Антиспам (Throttling)
│   ├── services/
│   │   ├── ai/              # Gemini AppSec Advisor & Telegram HTML типографика
│   │   └── zap/             # Асинхронный клиент OWASP ZAP API
│   └── main.py              # Точка входа в логику бота
├── tests/                   # Набор автоматических тестов
├── Dockerfile               # Легковесный продакшн образ (python:3.11-slim)
├── docker-compose.yml       # Изолированная связка ZAP + Bot
├── install_autostart.sh     # Скрипт настройки автозагрузки в Linux
├── zap-bot.service          # Системная служба systemd
├── main.py                  # Корневая точка входа Python
├── run.sh                   # Скрипт автозапуска ZAP и бота
├── stop.sh                  # Скрипт мгновенной остановки и очистки памяти
├── Makefile                 # Команды make up / make down / make logs
├── requirements.txt         # 5 ключевых зависимостей
└── .env.example             # Шаблон конфигурации
```

---

## 🚀 Быстрый старт

### 1. Клонирование и настройка окружения
```bash
git clone https://github.com/sayanelemes/zap-appsec-bot.git
cd zap-appsec-bot

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Создание файла `.env`
Скопируйте `.env.example` в `.env`:
```bash
cp .env.example .env
```

Заполните ключи:
```dotenv
BOT_TOKEN=ваш_telegram_токен_у_botfather
ADMIN_IDS=ваш_telegram_id
ZAP_URL=http://127.0.0.1:8090
ZAP_API_KEY=ваш_ключ_zap
GEMINI_API_KEY=ваш_ключ_google_ai_studio
```

---

## 💻 Управление связкой (ZAP + Бот)

Для запуска и остановки без необходимости держать несколько терминалов:

```bash
# Запуск ZAP в фоне + запуск Telegram-бота
./run.sh
# или
make up

# Мгновенная остановка всех процессов и очистка оперативной памяти
./stop.sh
# или
make down

# Просмотр логов в реальном времени
make logs
```

---

## ⚙️ Автозагрузка при включении системы

Скрипт автоматически настроит запуск при старте системы:

```bash
./install_autostart.sh
# или
make install-autostart
```

* Для запуска до входа пользователя как системной службы:
  ```bash
  sudo cp zap-bot.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now zap-bot.service
  ```

---

## 🐳 Развертывание в Docker Compose

Для деплоя на чистый сервер/VPS в закрытой Docker-сети:

```bash
docker compose up -d --build
docker compose logs -f bot
```

* Порт ZAP `8080` надежно изолирован внутри Docker-сети `zap-network` и не открывается наружу.
* Бот общается с демоном напрямую по адресу `http://zap:8080`.

---

## 🧪 Тестирование

Запуск тестов форматирования, валидации и логики:

```bash
python -m unittest discover tests
```

---

## 📄 Лицензия

MIT