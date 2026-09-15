#!/usr/bin/env bash
# =================================================================
# Скрипт настройки автозагрузки ZAP AppSec AI Auditor
# =================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "⚙️ Настройка автозапуска ZAP AppSec AI Auditor..."

# 1. Настройка Desktop Autostart (для графической сессии)
mkdir -p "$HOME/.config/autostart"
cp -f "$SCRIPT_DIR/zap-bot.desktop" "$HOME/.config/autostart/zap-bot.desktop" 2>/dev/null || cat << 'EOF' > "$HOME/.config/autostart/zap-bot.desktop"
[Desktop Entry]
Type=Application
Version=1.0
Name=ZAP AppSec AI Auditor
Comment=Autostart Telegram Bot & OWASP ZAP
Exec=/home/yelemessayan/bot_template/run.sh
Terminal=false
StartupNotify=false
Hidden=false
X-GNOME-Autostart-enabled=true
EOF
chmod +x "$HOME/.config/autostart/zap-bot.desktop"

# 2. Настройка User systemd
mkdir -p "$HOME/.config/systemd/user"
cat << 'EOF' > "$HOME/.config/systemd/user/zap-bot.service"
[Unit]
Description=ZAP AppSec AI Auditor Telegram Bot & OWASP ZAP Daemon
After=default.target

[Service]
Type=simple
WorkingDirectory=/home/yelemessayan/bot_template
ExecStart=/home/yelemessayan/bot_template/run.sh
ExecStop=/home/yelemessayan/bot_template/stop.sh
Restart=always
RestartSec=10
TimeoutStopSec=15
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF

echo "✅ Автозагрузка для текущего пользователя успешно сконфигурирована!"
echo "   1) Desktop Autostart: $HOME/.config/autostart/zap-bot.desktop"
echo "   2) Systemd User Unit: $HOME/.config/systemd/user/zap-bot.service"
echo ""
echo "💡 Чтобы служба стартовала сразу при загрузке системы (как демон на сервере):"
echo "   Выполните одну команду с sudo в вашем терминале:"
echo "   sudo cp $SCRIPT_DIR/zap-bot.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now zap-bot.service"
