import asyncio
import html
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import urlparse

from aiogram import F, Router
from aiogram.enums import ChatAction
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, CallbackQuery, Message
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter

from bot.config.config import settings
from bot.keyboards.inline import (
    ZapAiAuditCallback,
    ZapScanModeCallback,
    ZapScanStopCallback,
    get_ai_audit_keyboard,
    get_scan_mode_keyboard,
    get_scan_stop_keyboard,
)
from bot.services.ai import LlmAdvisorService, deduplicate_alerts, format_telegram_html
from bot.services.security import validate_url_safe
from bot.services.zap import ZapService, translate_zap_alert
from bot.utils.ui import safe_edit_message, track_extra_message, update_screen

logger = logging.getLogger(__name__)

zap_router = Router(name="zap_scanner")

# Синглтоны сервисов
_zap_service: ZapService | None = None
_llm_advisor: LlmAdvisorService | None = None

# Ограничение ресурсов: строго 1 сканирование одновременно
_scan_semaphore = asyncio.Semaphore(1)

# Кэш ожидающих подтверждения режима: {target_id: {"target_url": ..., "clean_origin": ...}}
_pending_scans: dict[str, dict[str, Any]] = {}

# Реестр активных сканирований для кнопки Stop:
# {scan_token: {"spider_id": str, "ascan_id": str, "stop_event": asyncio.Event, "status_msg": Message}}
_active_scans: dict[str, dict[str, Any]] = {}

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
    Извлекает и нормализует URL из аргумента команды или сообщения,
    обрабатывая Markdown-ссылки, скобки и пробелы.
    """
    if not raw_text:
        return ""

    text = raw_text.strip()

    md_match = re.search(r"\((https?://[^\s)]+)\)", text)
    if md_match:
        return md_match.group(1).strip()

    url_match = re.search(r"https?://[^\s\[\]\(\)\<\>\"']+", text)
    if url_match:
        return url_match.group(0).strip()

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
    """Проверка прав администратора / доступа."""
    if not settings:
        return False
    return settings.is_user_allowed(user_id)


@zap_router.message(Command("zap_status"))
@zap_router.message(F.text == "🔍 Статус ZAP")
async def cmd_zap_status(message: Message, state: FSMContext) -> None:
    """Проверка статуса подключения к OWASP ZAP."""
    if not message.from_user or not is_admin(message.from_user.id):
        await update_screen(
            event=message,
            state=state,
            text="⛔ <b>Доступ запрещен.</b> Команда доступна только администраторам.",
        )
        return

    zap = get_zap_service()
    is_alive = await zap.check_health()
    endpoint = settings.zap_endpoint if settings else "http://zap:8080"
    if is_alive:
        await update_screen(
            event=message,
            state=state,
            text=f"✅ <b>OWASP ZAP готов к работе!</b>\nАдрес: <code>{endpoint}</code>",
        )
    else:
        await update_screen(
            event=message,
            state=state,
            text=f"❌ <b>OWASP ZAP недоступен.</b>\nПроверьте, запущен ли демон на <code>{endpoint}</code>.",
        )


@zap_router.message(Command("check"))
@zap_router.message(F.text == "🛡 Проверить сайт")
@zap_router.message(F.text.regexp(r"^https?://(?!github\.com)[^\s]+"))
async def cmd_check(
    message: Message,
    state: FSMContext,
    command: CommandObject | None = None,
) -> None:
    """
    Первый шаг проверки: валидация URL, SSRF-фильтрация и предложение выбора глубины сканирования.
    Удаляет входящее сообщение и выводит выбор глубины на едином экране.
    """
    user = message.from_user
    if not user or not is_admin(user.id):
        await update_screen(
            event=message,
            state=state,
            text="⛔ <b>Доступ запрещен.</b> Проверку безопасности могут запускать только администраторы.",
        )
        return

    raw_args = command.args if command and command.args else (message.text or "")
    if raw_args.strip() == "🛡 Проверить сайт":
        raw_args = ""

    target_url = extract_clean_url(raw_args)

    if not target_url:
        await update_screen(
            event=message,
            state=state,
            text=(
                "⚠️ <b>Укажите адрес веб-сайта для проверки!</b>\n\n"
                "Пример использования:\n"
                "<code>/check http://testphp.vulnweb.com/listproducts.php?cat=1</code>\n"
                "или просто отправьте ссылку в чат."
            ),
        )
        return

    # 1. SSRF-фильтрация (DNS-резолв и проверка приватных диапазонов)
    is_safe, error_reason, resolved_ip = await validate_url_safe(target_url)
    if not is_safe:
        await update_screen(
            event=message,
            state=state,
            text=(
                f"🛡 <b>Защита от SSRF: Запрос отклонен</b>\n\n"
                f"❌ <b>Причина:</b> {html.escape(error_reason)}\n"
                f"🎯 <b>Цель:</b> <code>{html.escape(target_url)}</code>\n\n"
                f"<i>Сканирование локальных, приватных адресов и облачных метаданных строго запрещено.</i>"
            ),
        )
        return

    # Извлекаем схему и clean origin
    try:
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL components")
        clean_origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        await update_screen(
            event=message,
            state=state,
            text="❌ <b>Некорректный формат адреса.</b> Укажите правильный URL.",
        )
        return

    zap = get_zap_service()
    is_alive = await zap.check_health()
    if not is_alive:
        await update_screen(
            event=message,
            state=state,
            text=(
                f"❌ <b>Сканер OWASP ZAP недоступен.</b>\n"
                f"Убедитесь, что демон ZAP запущен на <code>{settings.ZAP_PROXY}</code>."
            ),
        )
        return

    target_id = uuid.uuid4().hex[:10]
    _pending_scans[target_id] = {
        "target_url": target_url,
        "clean_origin": clean_origin,
        "created_at": time.time(),
        "user_id": user.id,
    }

    resolved_note = f" (IP: <code>{resolved_ip}</code>)" if resolved_ip else ""
    await update_screen(
        event=message,
        state=state,
        text=(
            f"🎯 <b>Цель подтверждена:</b> <code>{html.escape(target_url)}</code>{resolved_note}\n\n"
            f"Выберите тип и глубину аудита безопасности:"
        ),
        reply_markup=get_scan_mode_keyboard(target_id=target_id),
    )


@zap_router.callback_query(ZapScanModeCallback.filter())
async def handle_scan_mode_selection(
    callback: CallbackQuery,
    callback_data: ZapScanModeCallback,
    state: FSMContext,
) -> None:
    """
    Обработчик выбора режима сканирования:
    1) Пассивный (5-10 сек)
    2) Быстрый (90 сек)
    3) Глубокий (5-10 мин)
    4) Отмена
    """
    mode = callback_data.mode
    target_id = callback_data.target_id

    if mode == "cancel":
        _pending_scans.pop(target_id, None)
        await update_screen(
            event=callback,
            state=state,
            text="❌ Сканирование отменено.",
        )
        return

    scan_info = _pending_scans.pop(target_id, None)
    if not scan_info:
        await callback.answer("⚠️ Сессия выбора устарела. Отправьте URL заново.", show_alert=True)
        return

    target_url = scan_info["target_url"]
    clean_origin = scan_info["clean_origin"]

    # Проверка семафора ресурсов
    if _scan_semaphore.locked():
        await callback.answer(
            "⚠️ Сканер уже выполняет другую задачу. Дождитесь ее завершения или остановите кнопкой Стоп.",
            show_alert=True,
        )
        return

    await callback.answer("🚀 Запуск сканирования...")

    scan_token = uuid.uuid4().hex[:8]
    stop_event = asyncio.Event()

    mode_titles = {
        "passive": "🛡 Пассивный аудит (Passive Scan)",
        "fast": "⚡ Быстрый аудит (Fast Scan, 90с)",
        "full": "🔍 Глубокий аудит (Full Scan)",
    }
    mode_name = mode_titles.get(mode, "Аудит ZAP")

    status_msg = await update_screen(
        event=callback,
        state=state,
        text=(
            f"<b>{mode_name}</b>\n"
            f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
            f"⏳ Инициализация сканера и прогрев дерева узлов..."
        ),
        reply_markup=get_scan_stop_keyboard(token=scan_token),
    )
    if not status_msg:
        status_msg = callback.message

    # Регистрируем активный скан
    _active_scans[scan_token] = {
        "spider_id": "",
        "ascan_id": "",
        "stop_event": stop_event,
        "status_msg": status_msg,
        "user_id": callback.from_user.id,
        "target_url": target_url,
        "clean_origin": clean_origin,
    }

    # Запуск выполнения в фоне с захватом семафора
    asyncio.create_task(
        _execute_scan_worker(
            scan_token=scan_token,
            target_url=target_url,
            clean_origin=clean_origin,
            mode=mode,
            mode_name=mode_name,
            status_msg=status_msg,
            stop_event=stop_event,
            callback=callback,
            state=state,
        )
    )


async def _execute_scan_worker(
    scan_token: str,
    target_url: str,
    clean_origin: str,
    mode: str,
    mode_name: str,
    status_msg: Message,
    stop_event: asyncio.Event,
    callback: CallbackQuery,
    state: FSMContext | None = None,
) -> None:
    """Фоновый воркер выполнения сканирования с семафором и кнопкой Stop."""
    zap = get_zap_service()
    deadline_hit = False

    async with _scan_semaphore:
        try:
            # 1. Настройка профиля
            if mode == "passive":
                await zap.configure_passive_scan()
            elif mode == "fast":
                await zap.configure_fast_scan()
            elif mode == "full":
                await zap.configure_full_scan()

            if stop_event.is_set():
                return

            # 2. Фоновый прогрев через ZAP прокси без блокировки основного потока
            asyncio.create_task(zap.access_url(target_url))

            # 3. Краулинг / Паук (Spider) запускается немедленно
            spider_id = await zap.start_spider(target_url)
            if not spider_id.isdigit():
                spider_id = await zap.start_spider(clean_origin)

            if spider_id.isdigit():
                _active_scans[scan_token]["spider_id"] = spider_id
                # Сразу отображаем индикатор паука 0% для мгновенного отклика интерфейса
                await safe_edit_message(
                    message=status_msg,
                    text=(
                        f"<b>{mode_name}</b>\n"
                        f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                        f"🕷 <b>Паук:</b> {render_progress_bar(0)}"
                    ),
                    reply_markup=get_scan_stop_keyboard(token=scan_token),
                )

                last_spider_percent = 0
                max_spider_time = 12 if mode == "passive" else 180
                spider_start = time.monotonic()

                while not stop_event.is_set():
                    await asyncio.sleep(2.5)
                    if time.monotonic() - spider_start > max_spider_time:
                        await zap.stop_spider(spider_id)
                        break

                    percent = await zap.get_spider_status(spider_id)
                    if percent != last_spider_percent:
                        last_spider_percent = percent
                        await safe_edit_message(
                            message=status_msg,
                            text=(
                                f"<b>{mode_name}</b>\n"
                                f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                                f"🕷 <b>Паук:</b> {render_progress_bar(percent)}"
                            ),
                            reply_markup=get_scan_stop_keyboard(token=scan_token),
                        )

                    if percent >= 100:
                        break

            if stop_event.is_set():
                return

            # 4. В пассивном режиме пропускаем активный скан инъекций
            if mode == "passive":
                await safe_edit_message(
                    message=status_msg,
                    text=(
                        f"<b>{mode_name}</b>\n"
                        f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                        f"✔ <b>Паук:</b> 100%\n"
                        f"🛡 <b>Пассивный анализ заголовков и кук...</b>"
                    ),
                    reply_markup=get_scan_stop_keyboard(token=scan_token),
                )
                await zap.wait_for_passive_scan(timeout=8)

            elif mode in ("fast", "full"):
                if stop_event.is_set():
                    return

                await safe_edit_message(
                    message=status_msg,
                    text=(
                        f"<b>{mode_name}</b>\n"
                        f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                        f"✔ <b>Паук:</b> 100%\n"
                        f"🔥 <b>Активное сканирование:</b> {render_progress_bar(0)}"
                    ),
                    reply_markup=get_scan_stop_keyboard(token=scan_token),
                )

                recurse = (mode == "full")
                ascan_id = await zap.start_active_scan(
                    target_url=target_url,
                    base_domain=clean_origin,
                    recurse=recurse,
                )

                if ascan_id.isdigit():
                    _active_scans[scan_token]["ascan_id"] = ascan_id
                    last_ascan_percent = -1
                    ascan_start = time.monotonic()
                    max_ascan_time = 90 if mode == "fast" else 600

                    while not stop_event.is_set():
                        await asyncio.sleep(3.0)
                        elapsed = time.monotonic() - ascan_start

                        if elapsed > max_ascan_time:
                            logger.warning("Active Scan превысил лимит времени %dc. Остановка...", max_ascan_time)
                            deadline_hit = True
                            await zap.stop_active_scan(ascan_id)
                            break

                        percent = await zap.get_active_scan_status(ascan_id)
                        if percent != last_ascan_percent:
                            last_ascan_percent = percent
                            await safe_edit_message(
                                message=status_msg,
                                text=(
                                    f"<b>{mode_name}</b>\n"
                                    f"🎯 Цель: <code>{html.escape(target_url)}</code>\n\n"
                                    f"✔ <b>Паук:</b> 100%\n"
                                    f"🔥 <b>Активное сканирование:</b> {render_progress_bar(percent)}"
                                ),
                                reply_markup=get_scan_stop_keyboard(token=scan_token),
                            )

                        if percent >= 100:
                            break

            if stop_event.is_set():
                return

            # 5. Выгрузка результатов
            alerts_summary, alerts_list = await zap.get_alerts_summary(clean_origin=clean_origin)
            html_report = await zap.generate_html_report()

            # Сохраняем в кэш для AI-аудита
            cache_id = uuid.uuid4().hex[:12]
            _audit_cache[cache_id] = {
                "alerts": alerts_list,
                "target_url": target_url,
                "clean_origin": clean_origin,
                "created_at": time.time(),
            }

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
                raw_name = item.get("alert", "Неизвестная уязвимость")
                name, _ = translate_zap_alert(raw_name)
                param = f" (параметр: <code>{html.escape(item['param'])}</code>)" if item.get("param") else ""
                issues_lines.append(f"{emoji} <b>[{r}]</b> {html.escape(name)}{param}")

            issues_block = "\n".join(issues_lines) if issues_lines else "<i>Замечаний не обнаружено.</i>"
            deadline_note = "\n⏱ <i>Сканирование завершено по лимиту времени.</i>" if deadline_hit else ""

            summary_text = (
                f"✅ <b>{mode_name} завершен!</b>{deadline_note}\n\n"
                f"🎯 <b>Цель:</b> <code>{html.escape(target_url)}</code>\n"
                f"🌐 <b>Origin:</b> <code>{html.escape(clean_origin)}</code>\n\n"
                f"📊 <b>Сводка уязвимостей:</b>\n"
                f"🔴 Высокий риск (High): <b>{alerts_summary.get('High', 0)}</b>\n"
                f"🟠 Средний риск (Medium): <b>{alerts_summary.get('Medium', 0)}</b>\n"
                f"🟡 Низкий риск (Low): <b>{alerts_summary.get('Low', 0)}</b>\n"
                f"🔵 Информационные: <b>{alerts_summary.get('Informational', 0)}</b>\n\n"
                f"📋 <b>Ключевые обнаруженные проблемы:</b>\n"
                f"{issues_block}\n\n"
                f"📄 <i>Полный HTML-отчет ZAP прикреплен ниже.</i>"
            )

            await safe_edit_message(
                message=status_msg,
                text=summary_text,
                reply_markup=get_ai_audit_keyboard(cache_id=cache_id),
            )

            # Отправляем HTML документ и регистрируем для последующей очистки
            parsed = urlparse(target_url)
            clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", parsed.netloc)
            report_filename = f"zap_report_{clean_name}.html"

            doc_msg = await callback.message.answer_document(
                document=BufferedInputFile(html_report, filename=report_filename),
                caption=f"📋 Детальный HTML-отчет OWASP ZAP для <code>{html.escape(clean_origin)}</code>",
            )
            if state and doc_msg:
                await track_extra_message(state=state, message_id=doc_msg.message_id)

        except Exception as exc:
            logger.exception("Ошибка при выполнении ZAP аудита: %s", exc)
            await safe_edit_message(
                message=status_msg,
                text=f"❌ <b>Произошла ошибка во время сканирования:</b>\n<code>{html.escape(str(exc))}</code>",
            )
        finally:
            _active_scans.pop(scan_token, None)


@zap_router.callback_query(ZapScanStopCallback.filter())
async def handle_scan_stop_callback(
    callback: CallbackQuery,
    callback_data: ZapScanStopCallback,
    state: FSMContext,
) -> None:
    """
    Экстренная остановка активного сканирования по кнопке 'Стоп'.
    """
    token = callback_data.token
    scan_ctx = _active_scans.get(token)

    if not scan_ctx:
        await callback.answer("Сканирование уже завершено или не найдено.", show_alert=True)
        return

    # Проверка прав: останавливать может запустивший пользователь или администратор
    if callback.from_user.id != scan_ctx.get("user_id") and not is_admin(callback.from_user.id):
        await callback.answer("⛔ Только инициатор проверки или администратор может остановить скан.", show_alert=True)
        return

    scan_ctx["stop_event"].set()
    zap = get_zap_service()

    # Точечная остановка в ZAP API
    spider_id = scan_ctx.get("spider_id")
    ascan_id = scan_ctx.get("ascan_id")
    if spider_id:
        await zap.stop_spider(spider_id)
    if ascan_id:
        await zap.stop_active_scan(ascan_id)
    await zap.stop_all_scans()

    await callback.answer("🛑 Сканирование останавливается...", show_alert=False)

    target_url = scan_ctx.get("target_url", "")
    clean_origin = scan_ctx.get("clean_origin", "")

    # Регистрируем заново target_id, чтобы пользователь мог выбрать другой режим или отменить
    target_id = uuid.uuid4().hex[:10]
    _pending_scans[target_id] = {
        "target_url": target_url,
        "clean_origin": clean_origin,
        "created_at": time.time(),
        "user_id": callback.from_user.id,
    }

    await update_screen(
        event=callback,
        state=state,
        text=(
            f"⛔ <b>Сканирование остановлено.</b>\n\n"
            f"🎯 <b>Цель:</b> <code>{html.escape(target_url)}</code>\n\n"
            f"Выберите тип и глубину аудита безопасности:"
        ),
        reply_markup=get_scan_mode_keyboard(target_id=target_id),
    )

    _active_scans.pop(token, None)


# --------------------------------------------------------------------------
# ЭТАП 2: AI-аудит безопасности и генерация кода исправлений
# --------------------------------------------------------------------------


@zap_router.callback_query(ZapAiAuditCallback.filter())
async def handle_ai_audit_callback(
    callback: CallbackQuery,
    callback_data: ZapAiAuditCallback,
    state: FSMContext,
) -> None:
    """
    Обработка нажатия инлайн-кнопки «💡 Получить аудит и код исправлений от ИИ».
    """
    user = callback.from_user
    if not user or not is_admin(user.id):
        await callback.answer("⛔ Доступ запрещен.", show_alert=True)
        return

    cache_data = _audit_cache.pop(callback_data.cache_id, None)
    if not cache_data:
        await callback.answer(
            "⏳ Запрос на аудит уже выполняется или отчет уже сформирован.",
            show_alert=True,
        )
        return

    if callback.message:
        try:
            await callback.message.edit_reply_markup(reply_markup=None)
        except Exception as e:
            logger.debug("Не удалось скрыть кнопку аудита: %s", e)

    await callback.answer("🧠 Запускаю анализ уязвимостей через нейросеть...")

    if callback.message:
        try:
            await callback.message.bot.send_chat_action(
                chat_id=callback.message.chat.id,
                action=ChatAction.TYPING,
            )
        except Exception:
            pass

    advisor = get_llm_advisor()
    chunks = await advisor.analyze_vulnerabilities(
        alerts=cache_data["alerts"],
        target_url=cache_data["target_url"],
    )

    chat_id = callback.message.chat.id if callback.message else user.id

    for chunk in chunks:
        clean_chunk = format_telegram_html(chunk)
        sent_msg = None
        try:
            sent_msg = await callback.bot.send_message(
                chat_id=chat_id,
                text=clean_chunk,
                parse_mode="HTML",
                disable_web_page_preview=True,
            )
        except Exception as exc:
            logger.warning("Сбой HTML-разметки сообщения Gemini, fallback на plain-text: %s", exc)
            plain_text = re.sub(r"<[^>]+>", "", clean_chunk)
            sent_msg = await callback.bot.send_message(
                chat_id=chat_id,
                text=plain_text[:4000],
                disable_web_page_preview=True,
            )
        if sent_msg:
            await track_extra_message(state=state, message_id=sent_msg.message_id)
        await asyncio.sleep(0.3)
