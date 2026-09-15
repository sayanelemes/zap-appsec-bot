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
from pydantic import ValidationError

from bot.config import settings
from bot.config.config import get_settings
from bot.database import check_db_connection, create_engine, create_session_pool
from bot.handlers import get_root_router
from bot.middlewares import DbSessionMiddleware, ThrottlingMiddleware

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

    # 3. Настройка FSM хранилища (Redis или MemoryStorage)
    if cfg.REDIS_URL:
        try:
            from aiogram.fsm.storage.redis import RedisStorage

            storage = RedisStorage.from_url(cfg.REDIS_URL)
            logger.info("Подключено Redis-хранилище для FSM: %s", cfg.REDIS_URL)
        except ImportError:
            logger.warning(
                "Пакет redis не установлен или недоступен. Используется MemoryStorage."
            )
            storage = MemoryStorage()
    else:
        storage = MemoryStorage()
        logger.info("Используется хранилище FSM по умолчанию: MemoryStorage")

    # 4. Инициализация Bot и Dispatcher
    bot = Bot(
        token=cfg.BOT_TOKEN.get_secret_value(),
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=storage)

    # 5. Инициализация подключения к БД
    engine = create_engine(cfg.DB_URL, echo=False)
    session_pool = create_session_pool(engine)

    try:
        await check_db_connection(engine)
    except Exception:
        logger.critical(
            "Не удалось подключиться к БД по адресу '%s'. Проверьте настройки DB_URL!",
            cfg.DB_URL,
        )
        await engine.dispose()
        await bot.session.close()
        sys.exit(1)

    # 6. Регистрация Middlewares
    # Антиспам (внешний мидлварь)
    throttling = ThrottlingMiddleware(rate_limit=cfg.THROTTLE_RATE)
    dp.message.outer_middleware(throttling)
    dp.callback_query.outer_middleware(throttling)

    # Проброс сессии БД (внутренний мидлварь)
    db_middleware = DbSessionMiddleware(session_pool=session_pool)
    dp.message.middleware(db_middleware)
    dp.callback_query.middleware(db_middleware)

    # 7. Подключение роутеров
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

        logger.info("Запуск Long Polling...")
        # Сбрасываем накопившиеся за время простоя апдейты
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)

    except (KeyboardInterrupt, SystemExit):
        logger.info("Получен сигнал завершения работы...")
    finally:
        logger.info("Выполняется процедура Graceful Shutdown...")

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

        # Закрытие соединений с БД
        logger.info("Закрытие пула соединений с БД...")
        await engine.dispose()

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

