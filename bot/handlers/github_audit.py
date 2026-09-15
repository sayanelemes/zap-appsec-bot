import html
import logging
from aiogram import F, Router
from aiogram.enums import ChatAction
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.types import Message

from bot.services.sast import GithubSastAuditor, extract_github_owner_repo
from bot.utils.ui import safe_edit_message, update_screen

logger = logging.getLogger(__name__)

github_sast_router = Router(name="github_sast")
_auditor = GithubSastAuditor()


@github_sast_router.message(Command("sast"))
@github_sast_router.message(F.text.regexp(r"(?i)https?://(?:www\.)?github\.com/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+"))
async def handle_github_repo_audit(
    message: Message,
    state: FSMContext,
    command: CommandObject | None = None,
) -> None:
    """
    Обработчик ссылок на репозитории GitHub для проведения SAST-аудита зависимостей:
    1. Удаляет входящее сообщение пользователя и предыдущий экран бота.
    2. Выводит статус анализа как единый экран.
    3. Опрашивает API OSV.dev и обновляет экран отчетом на месте.
    """
    raw_text = command.args if command and command.args else (message.text or "")
    parsed = extract_github_owner_repo(raw_text)

    if not parsed:
        await update_screen(
            event=message,
            state=state,
            text=(
                "⚠️ <b>Укажите корректную ссылку на GitHub репозиторий!</b>\n\n"
                "<i>Пример:</i>\n"
                "<code>https://github.com/pallets/jinja</code>\n"
                "или\n"
                "<code>/sast https://github.com/expressjs/express</code>"
            ),
        )
        return

    owner, repo = parsed

    status_text = (
        f"🔍 <b>Запущен SAST-аудит зависимостей GitHub</b>\n"
        f"📁 Репозиторий: <code>{html.escape(owner)}/{html.escape(repo)}</code>\n\n"
        f"⏳ Проверка веток <code>main</code> и <code>master</code>, поиск манифестов и опрос базы OSV.dev..."
    )
    status_msg = await update_screen(
        event=message,
        state=state,
        text=status_text,
    )

    if not status_msg:
        return

    try:
        await message.bot.send_chat_action(chat_id=message.chat.id, action=ChatAction.TYPING)
    except Exception:
        pass

    try:
        report, vulns, total_pkgs = await _auditor.audit_repository(owner, repo)
        await safe_edit_message(
            message=status_msg,
            text=report,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    except Exception as e:
        logger.exception("Ошибка при проведении SAST аудита %s/%s: %s", owner, repo, e)
        error_text = (
            f"❌ <b>Произошла ошибка при анализе репозитория {html.escape(owner)}/{html.escape(repo)}:</b>\n"
            f"<code>{html.escape(str(e))}</code>"
        )
        await safe_edit_message(
            message=status_msg,
            text=error_text,
        )
