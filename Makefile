.PHONY: all up down logs help

all: up

up:
	@chmod +x run.sh stop.sh
	@./run.sh

down:
	@chmod +x stop.sh
	@./stop.sh

logs:
	@if [ -f logs/bot.log ]; then \
		tail -n 50 -f logs/bot.log; \
	else \
		echo "Файл logs/bot.log пока не создан."; \
	fi

install-autostart:
	@chmod +x install_autostart.sh
	@./install_autostart.sh

help:
	@echo "Доступные команды:"
	@echo "  make up                - Запустить OWASP ZAP Daemon и Telegram-бот"
	@echo "  make down              - Остановить ZAP и Telegram-бот (освободить память)"
	@echo "  make logs              - Просмотр логов бота в реальном времени"
	@echo "  make install-autostart - Настроить автозагрузку при старте системы"
