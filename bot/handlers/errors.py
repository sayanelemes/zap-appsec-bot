import logging
from aiogram import Router
from aiogram.types.error_event import ErrorEvent

logger = logging.getLogger(__name__)

errors_router = Router(name="errors")


@errors_router.error()
async def error_handler(event: ErrorEvent) -> None:
    """
    Глобальный обработчик необработанных исключений.
    Логирует полный стек ошибки и отправляет пользователю вежливое уведомление,
    предотвращая падение процесса бота.
    """
    exception = event.exception
    update = event.update

    logger.critical(
        "Необработанное исключение: %s при обработке update ID %s",
        exception,
        update.update_id if update else "unknown",
        exc_info=exception,
    )

    # Вежливый ответ пользователю в зависимости от типа события
    if update.message:
        try:
            await update.message.answer(
                "⚠️ <b>Произошла непредвиденная ошибка.</b>\n"
                "Мы уже зафиксировали проблему и работаем над ее устранением."
            )
        except Exception as e:
            logger.error("Не удалось отправить сообщение об ошибке пользователю: %s", e)
    elif update.callback_query:
        try:
            await update.callback_query.answer(
                "⚠️ Произошла внутренняя ошибка. Попробуйте снова позже.",
                show_alert=True,
            )
        except Exception as e:
            logger.error("Не удалось отправить alert об ошибке пользователю: %s", e)
