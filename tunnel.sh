#!/usr/bin/env bash
# =================================================================
# Управление автономным фоновым туннелем Cloudflare (TMA Gateway)
# =================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p logs
LOG_FILE="logs/tunnel.log"

action="${1:-start}"

case "$action" in
  start)
    echo "🔍 Проверка фонового процесса cloudflared..."
    if pgrep -f "cloudflared.*8000" >/dev/null 2>&1; then
      echo "⚠️ Cloudflare tunnel уже запущен в фоне (PID: $(pgrep -f 'cloudflared.*8000' | head -n 1))."
    else
      echo "🚀 Запуск cloudflared в фоне с выводом в $LOG_FILE..."
      nohup cloudflared tunnel --url http://127.0.0.1:8000 > "$LOG_FILE" 2>&1 &
      sleep 1
    fi

    echo "⏳ Ожидание генерации публичного HTTPS URL из Cloudflare..."
    max_wait=20
    waited=0
    TUNNEL_URL=""

    while [ $waited -lt $max_wait ]; do
      sleep 1
      waited=$((waited + 1))
      if [ -f "$LOG_FILE" ]; then
        TUNNEL_URL=$(grep -o -E 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG_FILE" | head -n 1 || true)
        if [ -n "$TUNNEL_URL" ]; then
          break
        fi
      fi
    done

    if [ -n "$TUNNEL_URL" ]; then
      echo "✅ Туннель активен: $TUNNEL_URL"

      # Обновляем WEBAPP_URL в .env
      if [ -f .env ]; then
        if grep -q "^WEBAPP_URL=" .env; then
          sed -i "s|^WEBAPP_URL=.*|WEBAPP_URL=$TUNNEL_URL|" .env
        else
          echo "WEBAPP_URL=$TUNNEL_URL" >> .env
        fi
        echo "📝 Параметр WEBAPP_URL в .env успешно обновлен: $TUNNEL_URL"
      fi

      # Если zap-bot.service работает в systemd, предлагаем перезагрузить для подхвата URL
      if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active zap-bot.service >/dev/null 2>&1; then
        echo "🔄 Перезапуск zap-bot.service для применения нового URL..."
        sudo systemctl restart zap-bot.service || true
      fi
    else
      echo "⚠️ Не удалось перехватить URL за $max_wait секунд. Проверьте лог: cat $LOG_FILE"
    fi
    ;;

  stop)
    echo "🛑 Остановка cloudflared..."
    pkill -f "cloudflared.*8000" >/dev/null 2>&1 || true
    echo "✅ Туннель остановлен."
    ;;

  status)
    if pgrep -f "cloudflared.*8000" >/dev/null 2>&1; then
      echo "🟢 Cloudflare tunnel РАБОТАЕТ (PID: $(pgrep -f 'cloudflared.*8000' | head -n 1))"
      CURRENT_URL=$(grep -o -E 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG_FILE" | tail -n 1 || true)
      echo "🌐 URL: ${CURRENT_URL:-не найден в логе}"
    else
      echo "🔴 Cloudflare tunnel ОСТАНОВЛЕН."
    fi
    ;;

  update-env)
    if [ -f "$LOG_FILE" ]; then
      TUNNEL_URL=$(grep -o -E 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG_FILE" | tail -n 1 || true)
      if [ -n "$TUNNEL_URL" ]; then
        if grep -q "^WEBAPP_URL=" .env; then
          sed -i "s|^WEBAPP_URL=.*|WEBAPP_URL=$TUNNEL_URL|" .env
        else
          echo "WEBAPP_URL=$TUNNEL_URL" >> .env
        fi
        echo "✅ WEBAPP_URL в .env обновлен на: $TUNNEL_URL"
      else
        echo "❌ Ссылка не найдена в $LOG_FILE"
      fi
    else
      echo "❌ Файл $LOG_FILE отсутствует."
    fi
    ;;

  *)
    echo "Использование: ./tunnel.sh {start|stop|status|update-env}"
    exit 1
    ;;
esac
