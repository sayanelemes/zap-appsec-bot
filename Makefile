.PHONY: all up start down status logs help tunnel-up tunnel-down tunnel-status install-autostart

all: up

up:
	@chmod +x run.sh stop.sh
	@./run.sh

start:
	@chmod +x run.sh stop.sh
	@echo "🚀 Запуск ZAP и Telegram-бота в фоновом режиме (daemon)..."
	@nohup ./run.sh > logs/bot.log 2>&1 &
	@sleep 2
	@echo "✅ Процессы запущены в фоне. Для просмотра логов: make logs"

down:
	@chmod +x stop.sh
	@./stop.sh

status:
	@echo "=== ⚡ OWASP ZAP (8090) ==="
	@lsof -i :8090 2>/dev/null || echo "Не активен"
	@echo "=== 🤖 Telegram Bot / FastAPI (8000) ==="
	@lsof -i :8000 2>/dev/null || echo "Не активен"
	@echo "=== 🌐 Cloudflare Tunnel ==="
	@chmod +x tunnel.sh
	@./tunnel.sh status

logs:
	@if [ -f logs/bot.log ]; then \
		tail -n 50 -f logs/bot.log; \
	else \
		echo "Файл logs/bot.log пока не создан."; \
	fi

install-autostart:
	@chmod +x install_autostart.sh
	@./install_autostart.sh

tunnel-up:
	@chmod +x tunnel.sh
	@./tunnel.sh start

tunnel-down:
	@chmod +x tunnel.sh
	@./tunnel.sh stop

tunnel-status:
	@chmod +x tunnel.sh
	@./tunnel.sh status

help:
	@echo "Доступные команды:"
	@echo "  make up                - Запустить OWASP ZAP Daemon и Telegram-бот (на переднем плане)"
	@echo "  make start             - Запустить ZAP и бота в фоновом режиме (24/7 nohup)"
	@echo "  make down              - Остановить ZAP и Telegram-бот (освободить память и порты)"
	@echo "  make status            - Проверить статус портов 8090, 8000 и туннеля"
	@echo "  make logs              - Просмотр логов бота в реальном времени"
	@echo "  make tunnel-up         - Запустить Cloudflare Tunnel в фоне и обновить .env"
	@echo "  make tunnel-down       - Остановить фоновый Cloudflare Tunnel"
	@echo "  make tunnel-status     - Проверить статус туннеля и текущий HTTPS URL"
	@echo "  make install-autostart - Настроить автозагрузку при старте системы (systemd)"

