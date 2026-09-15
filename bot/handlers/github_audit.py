import html
import logging
from aiogram import F, Router
from aiogram.enums import ChatAction
from aiogram.filters import Command, CommandObject
from aiogram.types import Message

from bot.services.sast import GithubSastAuditor, extract_github_owner_repo

logger = logging.getLogger(__name__)

github_sast_router = Router(name="github_sast")
_auditor = GithubSastAuditor()


@github_sast_router.message(Command("sast"))
@github_sast_router.message(F.text.regexp(r"(?i)https?://(?:www\.)?github\.com/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+"))
async def handle_github_repo_audit(message: Message, command: CommandObject | None = None) -> None:
    """
    Обработчик ссылок на репозитории GitHub для проведения SAST-аудита зависимостей:
    1. Извлекает owner и repo.
    2. Загружает манифесты requirements.txt / package.json (ветки main/master).
    3. Опрашивает API OSV.dev на предмет известных CVE и рассчитывает CVSS score.
    4. Отправляет структурированный отчет с прямыми ссылками и безопасными версиями.
    """
    raw_text = command.args if command and command.args else (message.text or "")
    parsed = extract_github_owner_repo(raw_text)

    if not parsed:
        await message.answer(
            "⚠️ <b>Укажите корректную ссылку на GitHub репозиторий!</b>\n\n"
            "<i>Пример:</i>\n"
            "<code>https://github.com/pallets/jinja</code>\n"
            "или\n"
            "<code>/sast https://github.com/expressjs/express</code>"
        )
        return

    owner, repo = parsed

    status_msg = await message.answer(
        f"🔍 <b>Запущен SAST-аудит зависимостей GitHub</b>\n"
        f"📁 Репозиторий: <code>{html.escape(owner)}/{html.escape(repo)}</code>\n\n"
        f"⏳ Проверка веток <code>main</code> и <code>master</code>, поиск манифестов и опрос базы OSV.dev..."
    )

    try:
        await message.bot.send_chat_action(chat_id=message.chat.id, action=ChatAction.TYPING)
    except Exception:
        pass

    try:
        report, vulns, total_pkgs = await _auditor.audit_repository(owner, repo)
        await status_msg.edit_text(
            text=report,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    except Exception as e:
        logger.exception("Ошибка при проведении SAST аудита %s/%s: %s", owner, repo, e)
        try:
            await status_msg.edit_text(
                f"❌ <b>Произошла ошибка при анализе репозитория {html.escape(owner)}/{html.escape(repo)}:</b>\n"
                f"<code>{html.escape(str(e))}</code>"
            )
        except Exception:
            pass
