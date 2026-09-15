#!/bin/bash
# =================================================================
# Скрипт автоматического запуска OWASP ZAP Daemon и Telegram-бота
# =================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔍 Проверка окружения и сервисов..."

# 1. Загрузка ZAP_API_KEY из .env
ZAP_API_KEY=""
if [ -f .env ]; then
    ZAP_API_KEY=$(grep -E '^ZAP_API_KEY=' .env | head -n 1 | cut -d '=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r')
fi
if [ -z "$ZAP_API_KEY" ]; then
    ZAP_API_KEY="dr5gaufvs0dh02s7cen1cdnvhf"
fi

# 2. Определение пути к бинарнику ZAP
find_zap() {
    if [ -n "$ZAP_BIN" ] && [ -x "$ZAP_BIN" ]; then
        echo "$ZAP_BIN"
        return
    fi
    # Проверяем локальные дистрибутивы в домашней директории
    local home_zap
    home_zap=$(ls -d "$HOME"/ZAP*/zap.sh /home/*/ZAP*/zap.sh 2>/dev/null | head -n 1)
    if [ -n "$home_zap" ] && [ -x "$home_zap" ]; then
        echo "$home_zap"
        return
    fi
    # Проверяем в PATH
    if command -v zap.sh >/dev/null 2>&1; then
        echo "zap.sh"
        return
    fi
    if command -v zaproxy >/dev/null 2>&1; then
        echo "zaproxy"
        return
    fi
    echo "zaproxy"
}

ZAP_CMD=$(find_zap)

# 3. Проверка статуса ZAP на порту 8090
check_port() {
    (echo > /dev/tcp/127.0.0.1/8090) >/dev/null 2>&1 || (echo > /dev/tcp/localhost/8090) >/dev/null 2>&1
}

if check_port; then
    echo "⚡ OWASP ZAP Daemon уже работает на порту 8090."
else
    echo "🚀 Запуск OWASP ZAP Daemon в фоновом режиме на порту 8090..."
    
    # Очистка устаревшего файла блокировки, если ZAP завершился некорректно
    if [ -f "$HOME/.ZAP/.homelock" ]; then
        if ! pgrep -f -i "zap" >/dev/null 2>&1 && ! pgrep -f "org.zaproxy" >/dev/null 2>&1; then
            rm -f "$HOME/.ZAP/.homelock"
        fi
    fi

    # Запуск ZAP в фоне (с поддержкой 0.0.0.0 и регулярки для хостов)
    "$ZAP_CMD" -daemon -host 0.0.0.0 -port 8090 -config api.key="$ZAP_API_KEY" -config api.addrs.addr.name=".*" -config api.addrs.addr.regex=true > /dev/null 2>&1 &

    echo "⏳ Ожидание инициализации ZAP сокета..."
    # Ожидание сокета: до 30 секунд с шагом 1 секунда, но не менее 2-3 секунд
    max_wait=30
    waited=0
    while [ $waited -lt $max_wait ]; do
        sleep 1
        waited=$((waited + 1))
        if [ $waited -ge 3 ] && check_port; then
            break
        fi
    done

    if check_port; then
        echo "✅ OWASP ZAP Daemon успешно инициализирован и слушает порт 8090 (${waited}s)."
    else
        echo "⚠️ ZAP запущен, но порт 8090 еще не ответил. Продолжаем запуск бота..."
    fi
fi

# 4. Активация виртуального окружения
if [ -d ".venv" ]; then
    echo "📦 Активация виртуального окружения .venv..."
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo "📦 Активация виртуального окружения venv..."
    source venv/bin/activate
else
    echo "⚠️ Виртуальное окружение не найдено, запуск через системный python3"
fi

# 5. Запуск Telegram-бота на переднем плане
echo "🤖 Запуск Telegram-бота (main.py)..."
exec python main.py
