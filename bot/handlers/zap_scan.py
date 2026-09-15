import asyncio
import html
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import urlparse

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command, CommandObject
from aiogram.types import BufferedInputFile, CallbackQuery, Message
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter

from bot.config.config import settings
from bot.keyboards.inline import ZapAiAuditCallback, get_ai_audit_keyboard
from bot.services.ai import LlmAdvisorService, deduplicate_alerts, format_telegram_html
from bot.services.zap import ZapService

logger = logging.getLogger(__name__)

zap_router = Router(name="zap_scanner")

# Синглтоны сервисов
_zap_service: ZapService | None = None
_llm_advisor: LlmAdvisorService | None = None

# Временный кэш результатов сканирования для AI-аудита: {cache_id: {"alerts": [...], "target_url": ...}}
_audit_cache: dict[str, dict[str, Any]] = {}


def get_zap_service() -> ZapService:
    global _zap_service
    if _zap_service is None:
        api_key = settings.ZAP_API_KEY.get_secret_value() if settings.ZAP_API_KEY else ""
        _zap_service = ZapService(proxy_url=settings.ZAP_PROXY, api_key=api_key)
    return _zap_service


def get_llm_advisor() -> LlmAdvisorService:
    global _llm_advisor
    if _llm_advisor is None:
        _llm_advisor = LlmAdvisorService()
    return _llm_advisor


def extract_clean_url(raw_text: str | None) -> str:
    """
    Извлекает и нормализует URL из аргумента команды,
    обрабатывая Markdown-ссылки вида [text](url), скобки и пробелы.
    """
    if not raw_text:
        return ""

    text = raw_text.strip()

    # Если передана ссылка в формате Markdown: [любой_текст](https://example.com/...)
    md_match = re.search(r"\((https?://[^\s)]+)\)", text)
    if md_match:
        return md_match.group(1).strip()

    # Если внутри текста есть стандартный URL с http:// или https://
    url_match = re.search(r"https?://[^\s\[\]\(\)\<\>\"']+", text)
    if url_match:
        return url_match.group(0).strip()

    # Очистка от скобок и кавычек
    cleaned = text.strip("[]()<>'\" \t\n")
    if cleaned and not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned

    return cleaned


def render_progress_bar(percent: int, length: int = 10) -> str:
    """Генерирует визуальный индикатор прогресса: [████░░░░░░] 40%."""
    clamped = max(0, min(100, percent))
    filled = int(length * clamped / 100)
    empty = length - filled
    return f"[{'█' * filled}{'░' * empty}] {clamped}%"


def is_admin(user_id: int) -> bool:
    """Проверка прав администратора."""
    if not settings or not settings.ADMIN_IDS:
        return False
    return user_id in settings.ADMIN_IDS


@zap_router.message(Command("zap_status"))
async def cmd_zap_status(message: Message) -> None:
    """Проверка статуса подключения к OWASP ZAP."""
    if not message.from_user or not is_admin(message.from_user.id):
        await message.answer("⛔ <b>Доступ запрещен.</b> Команда доступна только администраторам.")
        return

    zap = get_zap_service()
    is_alive = await zap.check_health()
    if is_alive:
        await message.answer(f"✅ <b>OWASP ZAP готов к работе!</b>\nПрокси: <code>{settings.ZAP_PROXY}</code>")
    else:
        await message.answer(f"❌ <b>OWASP ZAP недоступен.</b>\nПроверьте, запущен ли демон на <code>{settings.ZAP_PROXY}</code>.")


@zap_router.message(Command("check"))
async def cmd_check(message: Message, command: CommandObject) -> None:
    """
    Запуск оптимизированного аудита (Fast Scan):
    1. Настройка Fast Scan опций ZAP (таймауты, потоки, глубина паука).
    2. Предварительный прогрев через access_url и HTTP-прокси.
    3. Паук (Spider, max_depth=2).
    4. Обязательный Active Scan (recurse=False) с аварийным дедлайном 90 секунд.
    5. ЭТАП 1: Выгрузка алертов по чистому origin, компактный список и кнопка вызова AI-аудита.
    """
    user = message.from_user
    if not user or not is_admin(user.id):
        await message.answer("⛔ <b>Доступ запрещен.</b> Проверку безопасности могут запускать только администраторы.")
        return

    raw_args = command.args if command.args else ""
    target_url = extract_clean_url(raw_args)

    if not target_url:
        await message.answer(
            "⚠️ <b>Укажите адрес веб-сайта для проверки!</b>\n\n"
            "Пример использования:\n"
            "<code>/check http://testphp.vulnweb.com/listproducts.php?cat=1</code>\n"
            "<code>/check http://127.0.0.1:8000</code>"
        )
        return

    # Извлекаем схему, хост и чистый origin (схема + хост[:порт])
    try:
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL components")
        clean_origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        await message.answer(
            "❌ <b>Некорректный формат адреса.</b>\n"
            "Укажите правильный URL (например, <code>http://testphp.vulnweb.com</code>)."
        )
        return

    zap = get_zap_service()
    is_alive = await zap.check_health()
    if not is_alive:
        await message.answer(
            f"❌ <b>Сканер OWASP ZAP недоступен.</b>\n"
            f"Убедитесь, что демон ZAP запущен на <code>{settings.ZAP_PROXY}</code>."
        )
        return

    status_msg = await message.answer(
        f"⚡ <b>Инициализация Fast Scan:</b>\n"
        f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
        f"⏳ Настройка лимитов скорости и прогрев дерева узлов..."
    )

    try:
        # 1. Применяем параметры Fast Scan к ZAP
        await zap.configure_fast_scan()

        # 2. Прогрев: предварительное посещение целевого URL
        await zap.access_url(target_url)

        # 3. Краулинг / Паук (Spider, max_depth=2)
        spider_id = await zap.start_spider(target_url)
        if not spider_id.isdigit():
            spider_id = await zap.start_spider(clean_origin)

        if not spider_id.isdigit():
            await status_msg.edit_text(
                f"❌ <b>Не удалось запустить Spider для:</b> <code>{html.escape(target_url)}</code>\n"
                f"Проверьте доступность сайта из сети."
            )
            return

        last_spider_percent = -1
        while True:
            await asyncio.sleep(3)
            percent = await zap.get_spider_status(spider_id)
            if percent != last_spider_percent:
                last_spider_percent = percent
                try:
                    await status_msg.edit_text(
                        f"⚡ <b>Fast Scan веб-приложения:</b>\n"
                        f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                        f"🕷 <b>Паук:</b> {render_progress_bar(percent)}"
                    )
                except TelegramRetryAfter as e:
                    await asyncio.sleep(e.retry_after)
                except TelegramBadRequest:
                    pass

            if percent >= 100:
                break

        # 4. Активное сканирование параметров (Active Scan, recurse=False) с дедлайном 90с
        await status_msg.edit_text(
            f"⚡ <b>Fast Scan веб-приложения:</b>\n"
            f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
            f"✔ <b>Паук:</b> 100%\n"
            f"🔥 <b>Активное сканирование параметров:</b> {render_progress_bar(0)}"
        )

        ascan_id = await zap.start_active_scan(target_url=target_url, base_domain=clean_origin)

        if not ascan_id.isdigit():
            logger.warning("Active scan вернул '%s', повторный прогрев...", ascan_id)
            await zap.access_url(target_url)
            await zap.access_url(clean_origin)
            ascan_id = await zap.start_active_scan(target_url=clean_origin)

        if not ascan_id.isdigit():
            await status_msg.edit_text(
                f"⚠️ <b>Активное сканирование не удалось запустить:</b> ZAP вернул статус <code>{html.escape(ascan_id)}</code>.\n"
                f"Ресурс не вернул доступных страниц для аудита параметров."
            )
            return

        last_ascan_percent = -1
        ascan_start_time = time.monotonic()
        deadline_hit = False

        while True:
            await asyncio.sleep(3.5)
            elapsed = time.monotonic() - ascan_start_time

            # Аварийный дедлайн 90 секунд для Fast Scan
            if elapsed > 90:
                logger.warning("Active Scan превысил аварийный дедлайн 90 секунд. Принудительная остановка...")
                deadline_hit = True
                await zap.stop_all_scans()
                break

            percent = await zap.get_active_scan_status(ascan_id)
            if percent != last_ascan_percent:
                last_ascan_percent = percent
                try:
                    await status_msg.edit_text(
                        f"⚡ <b>Fast Scan веб-приложения:</b>\n"
                        f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                        f"✔ <b>Паук:</b> 100%\n"
                        f"🔥 <b>Активное сканирование параметров:</b> {render_progress_bar(percent)}"
                    )
                except TelegramRetryAfter as e:
                    await asyncio.sleep(e.retry_after)
                except TelegramBadRequest:
                    pass

            if percent >= 100:
                break

        # 5. Выгрузка алертов по чистому origin
        alerts_summary, alerts_list = await zap.get_alerts_summary(clean_origin=clean_origin)
        html_report = await zap.generate_html_report()

        # Сохраняем в кэш для 2-го этапа (AI-аудит)
        cache_id = uuid.uuid4().hex[:12]
        _audit_cache[cache_id] = {
            "alerts": alerts_list,
            "target_url": target_url,
            "clean_origin": clean_origin,
            "created_at": time.time(),
        }

        # Формируем компактный список проблем с эмодзи
        deduped = deduplicate_alerts(alerts_list)
        risk_emojis = {
            "High": "🔴",
            "Medium": "🟠",
            "Low": "🟡",
            "Informational": "🔵",
        }

        issues_lines = []
        for item in deduped:
            r = str(item.get("risk", "Low")).capitalize()
            emoji = risk_emojis.get(r, "⚪")
            name = item.get("alert", "Неизвестная уязвимость")
            param = f" (параметр: <code>{html.escape(item['param'])}</code>)" if item.get("param") else ""
            issues_lines.append(f"{emoji} <b>[{r}]</b> {html.escape(name)}{param}")

        if issues_lines:
            issues_block = "\n".join(issues_lines)
        else:
            issues_block = "<i>Замечаний высокой и средней критичности не обнаружено.</i>"

        deadline_note = "\n⏱ <i>Fast Scan завершен по лимиту времени (90с).</i>" if deadline_hit else ""

        summary_text = (
            f"✅ <b>Аудит безопасности завершен (Fast Scan)!</b>{deadline_note}\n\n"
            f"🎯 <b>Цель:</b> <code>{html.escape(target_url)}</code>\n"
            f"🌐 <b>Origin:</b> <code>{html.escape(clean_origin)}</code>\n\n"
            f"📊 <b>Сводка уязвимостей:</b>\n"
            f"🔴 Высокий риск (High): <b>{alerts_summary.get('High', 0)}</b>\n"
            f"🟠 Средний риск (Medium): <b>{alerts_summary.get('Medium', 0)}</b>\n"
            f"🟡 Низкий риск (Low): <b>{alerts_summary.get('Low', 0)}</b>\n"
            f"🔵 Информационные: <b>{alerts_summary.get('Informational', 0)}</b>\n\n"
            f"📋 <b>Ключевые обнаруженные проблемы:</b>\n"
            f"{issues_block}\n\n"
            f"📄 <i>Полный HTML-отчет ZAP прикреплен ниже.</i>\n"
            f"Нажмите кнопку ниже для генерации AI-разбора и кода исправлений:"
        )

        try:
            await status_msg.edit_text(
                text=summary_text,
                reply_markup=get_ai_audit_keyboard(cache_id=cache_id),
            )
        except Exception:
            await message.answer(
                text=summary_text,
                reply_markup=get_ai_audit_keyboard(cache_id=cache_id),
            )

        # Отправляем HTML-отчет документом
        clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", parsed.netloc)
        report_filename = f"zap_report_{clean_name}.html"

        await message.answer_document(
            document=BufferedInputFile(html_report, filename=report_filename),
            caption=f"📋 Детальный HTML-отчет OWASP ZAP для <code>{html.escape(clean_origin)}</code>",
        )

    except Exception as exc:
        logger.exception("Ошибка при выполнении аудита ZAP: %s", exc)
        try:
            await status_msg.edit_text(
                f"❌ <b>Произошла ошибка во время сканирования:</b>\n<code>{html.escape(str(exc))}</code>"
            )
        except Exception:
            pass


# --------------------------------------------------------------------------
# ЭТАП 2: AI-аудит безопасности и генерация кода исправлений
# --------------------------------------------------------------------------


@zap_router.callback_query(ZapAiAuditCallback.filter())
async def handle_ai_audit_callback(
    callback: CallbackQuery,
    callback_data: ZapAiAuditCallback,
) -> None:
    """
    Обработка нажатия инлайн-кнопки «💡 Получить аудит и код исправлений от ИИ»:
    - Защита от повторных нажатий: атомарно извлекает задачу из кэша и сразу скрывает кнопку.
    - Отображает ChatAction.TYPING.
    - Вызывает LLM Advisor для дедуплицированных алертов.
    - Форматирует вывод в валидный Telegram HTML с красивым моноширинным шрифтом для кода и параметров.
    - Отправляет рекомендации порциями до 4000 символов.
    """
    user = callback.from_user
    if not user or not is_admin(user.id):
        await callback.answer("⛔ Доступ запрещен.", show_alert=True)
        return

    # 1. Защита от повторных нажатий: извлекаем данные из кэша один раз
    cache_data = _audit_cache.pop(callback_data.cache_id, None)
    if not cache_data:
        await callback.answer(
            "⏳ Запрос на аудит уже выполняется или отчет уже сформирован.",
            show_alert=True,
        )
        return

    # 2. Немедленно убираем inline-кнопку из сообщения, делая нажатие строго одноразовым
    if callback.message:
        try:
            await callback.message.edit_reply_markup(reply_markup=None)
        except Exception as e:
            logger.debug("Не удалось скрыть кнопку аудита: %s", e)

    await callback.answer("🧠 Запускаю анализ уязвимостей через нейросеть...")

    chat_id = callback.message.chat.id if callback.message else user.id

    # Фоновая задача обновления статуса "печатает..." в чате
    async def _keep_typing():
        try:
            while True:
                await callback.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
                await asyncio.sleep(4.5)
        except asyncio.CancelledError:
            pass

    typing_task = asyncio.create_task(_keep_typing())

    try:
        advisor = get_llm_advisor()
        advice_chunks = await advisor.analyze_vulnerabilities(
            alerts=cache_data["alerts"],
            target_url=cache_data["target_url"],
        )
    finally:
        typing_task.cancel()

    # Если нейросеть временно перегружена или вернула ошибку
    is_error = not advice_chunks or any("⚠️" in ch and ("недоступна" in ch.lower() or "квоты" in ch.lower()) for ch in advice_chunks)
    if is_error:
        retry_cache_id = uuid.uuid4().hex[:12]
        _audit_cache[retry_cache_id] = cache_data
        retry_kb = get_ai_audit_keyboard(cache_id=retry_cache_id, text="🔄 Повторить генерацию аудита")
        err_msg = advice_chunks[0] if advice_chunks else "⚠️ <b>Нейросеть временно недоступна.</b>"
        await callback.bot.send_message(
            chat_id=chat_id,
            text=f"{err_msg}\n\n<i>Нажмите кнопку ниже, чтобы повторить запрос к ИИ без повторного сканирования:</i>",
            reply_markup=retry_kb,
            parse_mode="HTML",
        )
        return

    # Отправляем результаты частями с гарантией валидной типографики (шрифт, цитаты, код)
    for chunk in advice_chunks:
        formatted_html = format_telegram_html(chunk)
        try:
            await callback.bot.send_message(
                chat_id=chat_id,
                text=formatted_html,
                parse_mode="HTML",
            )
        except Exception as e:
            logger.warning("Ошибка парсинга Telegram HTML при отправке аудита (%s), fallback на текст: %s", e, formatted_html[:150])
            await callback.bot.send_message(
                chat_id=chat_id,
                text=chunk,
                parse_mode=None,
            )
