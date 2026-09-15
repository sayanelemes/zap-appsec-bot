import asyncio
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
from typing import Sequence

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import MenuButtonWebApp, WebAppInfo
from pydantic import ValidationError
import uvicorn

from bot.api.app import app as fastapi_app
from bot.config import settings
from bot.config.config import get_settings
from bot.handlers import get_root_router
from bot.middlewares import ThrottlingMiddleware, WhitelistMiddleware

logger = logging.getLogger(__name__)


def setup_logging(log_level_str: str) -> None:
    """
    Настраивает вывод логов в консоль и с ротацией в файл logs/bot.log.
    """
    os.makedirs("logs", exist_ok=True)
    level = getattr(logging, log_level_str.upper(), logging.INFO)

    log_format = (
        "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] — %(message)s"
    )
    date_format = "%Y-%m-%d %H:%M:%S"

    # Обработчик консоли
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))

    # Обработчик файла с ротацией (до 10 МБ на файл, хранение до 5 резервных копий)
    file_handler = RotatingFileHandler(
        filename="logs/bot.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))

    logging.basicConfig(
        level=level,
        handlers=[console_handler, file_handler],
    )

    # Подавляем излишне подробные логи внешних библиотек
    logging.getLogger("aiogram.event").setLevel(logging.WARNING)


async def notify_admins(bot: Bot, admin_ids: Sequence[int], text: str) -> None:
    """
    Отправляет сервисное уведомление администраторам (например, о запуске/остановке).
    """
    for admin_id in admin_ids:
        try:
            await bot.send_message(chat_id=admin_id, text=text)
        except Exception as e:
            logger.warning(
                "Не удалось отправить сервисное уведомление админу %s: %s",
                admin_id,
                e,
            )


async def main() -> None:
    """
    Основная функция запуска бота.
    """
    # 1. Валидация конфигурации
    try:
        cfg = settings or get_settings()
    except ValidationError as e:
        print("❌ Ошибка валидации переменных окружения в .env:")
        for err in e.errors():
            loc = ".".join(str(item) for item in err["loc"])
            print(f"   • Поле '{loc}': {err['msg']}")
        print("\nПожалуйста, заполните файл .env по образцу из .env.example")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Критическая ошибка при загрузке конфигурации: {e}")
        sys.exit(1)

    # 2. Инициализация логирования
    setup_logging(cfg.LOG_LEVEL)
    logger.info("Инициализация сервисов %s...", cfg.BOT_NAME)

    # 3. Настройка FSM хранилища (In-Memory)
    storage = MemoryStorage()
    logger.info("Используется хранилище FSM: MemoryStorage")

    # 4. Инициализация Bot и Dispatcher
    bot = Bot(
        token=cfg.BOT_TOKEN.get_secret_value(),
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=storage)

    # 5. Регистрация Middlewares
    # Защита периметра (Whitelist & Admin check)
    whitelist = WhitelistMiddleware()
    dp.message.outer_middleware(whitelist)
    dp.callback_query.outer_middleware(whitelist)

    # Антиспам (Rate Limiting)
    throttling = ThrottlingMiddleware(rate_limit=cfg.THROTTLE_RATE)
    dp.message.outer_middleware(throttling)
    dp.callback_query.outer_middleware(throttling)

    # 6. Подключение роутеров
    dp.include_router(get_root_router())

    # 8. Запуск бота с Graceful Shutdown
    try:
        bot_info = await bot.get_me()
        logger.info("Бот успешно авторизован: @%s (ID: %s)", bot_info.username, bot_info.id)

        # Оповещение администраторов о старте
        if cfg.ADMIN_IDS:
            await notify_admins(
                bot=bot,
                admin_ids=cfg.ADMIN_IDS,
                text=f"🚀 <b>{cfg.BOT_NAME} (@{bot_info.username}) успешно запущен!</b>",
            )

        # Настройка кнопки меню чата Telegram (TMA)
        try:
            await bot.set_chat_menu_button(
                menu_button=MenuButtonWebApp(
                    text="SOC Scanner",
                    web_app=WebAppInfo(url=cfg.WEBAPP_URL),
                )
            )
            logger.info("Кнопка меню чата Telegram настроена на TMA: %s", cfg.WEBAPP_URL)
        except Exception as e:
            logger.warning("Не удалось установить кнопку меню чата TMA: %s", e)

        # Конфигурация веб-сервера FastAPI (Uvicorn)
        uvicorn_config = uvicorn.Config(
            app=fastapi_app,
            host=cfg.WEBAPP_HOST,
            port=cfg.WEBAPP_PORT,
            log_level="warning",
        )
        server = uvicorn.Server(uvicorn_config)

        logger.info(
            "Запуск FastAPI сервера (http://%s:%s) и Telegram Bot Polling...",
            cfg.WEBAPP_HOST,
            cfg.WEBAPP_PORT,
        )
        # Сбрасываем накопившиеся за время простоя апдейты
        await bot.delete_webhook(drop_pending_updates=True)

        # Запуск параллельно в едином цикле событий через asyncio.gather
        await asyncio.gather(
            server.serve(),
            dp.start_polling(bot),
        )

    except (KeyboardInterrupt, SystemExit):
        logger.info("Получен сигнал завершения работы...")
    finally:
        logger.info("Выполняется процедура Graceful Shutdown...")
        if "server" in locals():
            server.should_exit = True

        # Оповещение администраторов об остановке
        if cfg.ADMIN_IDS:
            try:
                await notify_admins(
                    bot=bot,
                    admin_ids=cfg.ADMIN_IDS,
                    text="🛑 <b>Бот остановлен (Graceful Shutdown).</b>",
                )
            except Exception:
                pass

        # Закрытие сессии бота
        logger.info("Закрытие HTTP-сессии бота...")
        await bot.session.close()

        # Закрытие FSM хранилища, если поддерживается
        if hasattr(storage, "close"):
            await storage.close()

        logger.info("Бот успешно остановлен. До свидания!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        sys.exit(e.code)

