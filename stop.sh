#!/usr/bin/env bash
# =================================================================
# Скрипт мгновенной остановки Telegram-бота и OWASP ZAP
# =================================================================

# 1. Завершение процесса бота
pkill -f "python.*main\.py" >/dev/null 2>&1 || true
pkill -f "python.*bot\.main" >/dev/null 2>&1 || true

# 2. Завершение процесса OWASP ZAP (zaproxy, zap.sh, java)
pkill -f "zaproxy" >/dev/null 2>&1 || true
pkill -f "zap.sh" >/dev/null 2>&1 || true
pkill -f "org.zaproxy.zap.ZAP" >/dev/null 2>&1 || true
pkill -f "ZAP_.*zap\.jar" >/dev/null 2>&1 || true

# 3. Даем секунду на корректное завершение и освобождение ресурсов
sleep 1

# Дополнительная очистка, если процессы еще удерживают порты 8090 (ZAP) или 8000 (FastAPI)
if command -v fuser >/dev/null 2>&1; then
    fuser -k -9 8090/tcp >/dev/null 2>&1 || true
    fuser -k -9 8000/tcp >/dev/null 2>&1 || true
fi

# Очистка блокировки домашней директории ZAP, чтобы следующий запуск прошел успешно
rm -f "$HOME/.ZAP/.homelock"

# 4. Остановка фонового Cloudflare Tunnel
if [ -f "./tunnel.sh" ]; then
    chmod +x ./tunnel.sh
    ./tunnel.sh stop >/dev/null 2>&1 || true
fi

# 5. Сообщение в консоль (по требованию ТЗ)
echo "✅ ZAP, Telegram-бот и Cloudflare Tunnel успешно остановлены. Память освобождена."

