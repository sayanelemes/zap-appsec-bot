import asyncio
import html
import json
import logging
import re
from typing import Any
import aiohttp

from bot.services.sast.osv_client import OsvClient, OsvVulnerability

logger = logging.getLogger(__name__)

GITHUB_REPO_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)(?:/.*)?",
    re.IGNORECASE,
)


def extract_github_owner_repo(url_or_text: str) -> tuple[str, str] | None:
    """Извлекает (owner, repo) из ссылки на GitHub."""
    match = GITHUB_REPO_REGEX.search(url_or_text.strip())
    if not match:
        return None
    owner = match.group(1).strip()
    repo = match.group(2).strip()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """
    Парсит requirements.txt, извлекая пары (package_name, version).
    Поддерживает ==, >=, <=, ~=, а также очищает extras [email].
    """
    packages: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--", "-i", "-f")):
            continue

        # Игнорируем ссылки git+https:// или пути к локальным файлам
        if "://" in line or "/" in line or "\\" in line:
            continue

        # Регулярка для имени пакета и версии
        # примеры: flask==2.0.1, requests>=2.25.1, pydantic[email]~=1.8.2
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|===)\s*([0-9a-zA-Z_\-\.]+)", line)
        if m:
            pkg_name = m.group(1).strip()
            ver = m.group(2).strip()
            packages.append((pkg_name, ver))
    return packages


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """
    Парсит package.json, извлекая зависимости из dependencies и devDependencies.
    Очищает semver-префиксы (^, ~, >=, v, =).
    """
    packages: list[tuple[str, str]] = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})

        all_deps: dict[str, str] = {}
        if isinstance(deps, dict):
            all_deps.update(deps)
        if isinstance(dev_deps, dict):
            all_deps.update(dev_deps)

        for pkg, ver_raw in all_deps.items():
            if not isinstance(ver_raw, str):
                continue
            ver_clean = re.sub(r"^[\^~>=<v= ]+", "", ver_raw).strip()
            # Берем первую чистую версию (до пробела или разделителя)
            ver_clean = ver_clean.split()[0] if ver_clean else ""
            if ver_clean and not ver_clean.startswith(("http", "git", "*", "latest", "workspace")):
                packages.append((pkg, ver_clean))
    except Exception as e:
        logger.warning("Ошибка парсинга package.json: %s", e)
    return packages


class GithubSastAuditor:
    """Сервис для SAST-аудита зависимостей GitHub-репозиториев через OSV.dev."""

    def __init__(self, timeout_sec: float = 12.0) -> None:
        self.timeout_sec = timeout_sec
        self.osv = OsvClient(timeout_sec=timeout_sec)

    async def fetch_file(self, owner: str, repo: str, branch: str, filename: str) -> str | None:
        """Загружает файл манифеста через raw.githubusercontent.com."""
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
        timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(raw_url) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    return None
        except Exception as e:
            logger.debug("Не удалось загрузить %s из %s/%s (%s): %s", filename, owner, repo, branch, e)
            return None

    async def audit_repository(self, owner: str, repo: str) -> tuple[str, list[OsvVulnerability], int]:
        """
        Проверяет манифесты репозитория и возвращает:
        (форматированный_отчет_html, список_уязвимостей, всего_проверенных_библиотек).
        """
        branches = ["main", "master"]
        found_reqs: str | None = None
        found_pkg_json: str | None = None

        for b in branches:
            if not found_reqs:
                found_reqs = await self.fetch_file(owner, repo, b, "requirements.txt")
            if not found_pkg_json:
                found_pkg_json = await self.fetch_file(owner, repo, b, "package.json")
            if found_reqs and found_pkg_json:
                break

        if not found_reqs and not found_pkg_json:
            msg = (
                f"⚠️ <b>Манифесты зависимостей не найдены</b> в репозитории <code>{html.escape(owner)}/{html.escape(repo)}</code>.\n\n"
                f"Поддерживаемые форматы (ветки <code>main</code> / <code>master</code>):\n"
                f"• <code>requirements.txt</code> (Python / PyPI)\n"
                f"• <code>package.json</code> (Node.js / npm)\n\n"
                f"Убедитесь, что репозиторий публичный и содержит один из этих файлов."
            )
            return msg, [], 0

        pypi_pkgs = parse_requirements_txt(found_reqs) if found_reqs else []
        npm_pkgs = parse_package_json(found_pkg_json) if found_pkg_json else []

        total_pkgs = len(pypi_pkgs) + len(npm_pkgs)
        if total_pkgs == 0:
            msg = (
                f"ℹ️ В найденных манифестах репозитория <code>{html.escape(owner)}/{html.escape(repo)}</code> "
                f"не обнаружено зафиксированных версий пакетов для проверки."
            )
            return msg, [], 0

        semaphore = asyncio.Semaphore(5)
        all_vulns: list[OsvVulnerability] = []

        async def _check(pkg_name: str, ver: str, eco: str) -> None:
            async with semaphore:
                vulns = await self.osv.query_package(pkg_name, ver, eco)
                if vulns:
                    all_vulns.extend(vulns)

        tasks = []
        for pkg, ver in pypi_pkgs:
            tasks.append(_check(pkg, ver, "PyPI"))
        for pkg, ver in npm_pkgs:
            tasks.append(_check(pkg, ver, "npm"))

        await asyncio.gather(*tasks)

        # Дедупликация уязвимостей по (pkg, vuln_id)
        seen_keys = set()
        deduped_vulns: list[OsvVulnerability] = []
        for v in all_vulns:
            k = (v.package_name, v.vuln_id)
            if k not in seen_keys:
                seen_keys.add(k)
                deduped_vulns.append(v)

        deduped_vulns.sort(key=lambda x: x.cvss_score, reverse=True)

        # Форматирование итогового отчета
        report = self.format_report(owner, repo, deduped_vulns, total_pkgs, bool(found_reqs), bool(found_pkg_json))
        return report, deduped_vulns, total_pkgs

    def format_report(
        self,
        owner: str,
        repo: str,
        vulns: list[OsvVulnerability],
        total_pkgs: int,
        has_python: bool,
        has_node: bool,
    ) -> str:
        """Форматирует структурированный отчет в Telegram HTML."""
        ecosystems = []
        if has_python:
            ecosystems.append("PyPI (requirements.txt)")
        if has_node:
            ecosystems.append("npm (package.json)")
        eco_str = ", ".join(ecosystems)

        if not vulns:
            return (
                f"✅ <b>SAST-аудит зависимостей завершен!</b>\n\n"
                f"📁 Репозиторий: <a href=\"https://github.com/{html.escape(owner)}/{html.escape(repo)}\"><b>{html.escape(owner)}/{html.escape(repo)}</b></a>\n"
                f"📦 Проверено библиотек: <b>{total_pkgs}</b> ({eco_str})\n\n"
                f"🎉 <b>Уязвимостей не обнаружено!</b> Все проверенные зависимости безопасны по данным базы OSV.dev."
            )

        # Сводка по критичности
        crit_count = sum(1 for v in vulns if v.cvss_score >= 9.0)
        high_count = sum(1 for v in vulns if 7.0 <= v.cvss_score < 9.0)
        med_count = sum(1 for v in vulns if 4.0 <= v.cvss_score < 7.0)
        low_count = sum(1 for v in vulns if 0.0 < v.cvss_score < 4.0)

        lines = [
            f"🔍 <b>SAST-аудит зависимостей GitHub (OSV.dev)</b>\n",
            f"📁 Репозиторий: <a href=\"https://github.com/{html.escape(owner)}/{html.escape(repo)}\"><b>{html.escape(owner)}/{html.escape(repo)}</b></a>",
            f"📦 Проверено библиотек: <b>{total_pkgs}</b> ({eco_str})\n",
            f"📊 <b>Найдено уязвимостей:</b> <b>{len(vulns)}</b>",
            f"🔴 Critical: <b>{crit_count}</b> | 🟠 High: <b>{high_count}</b> | 🟡 Medium: <b>{med_count}</b> | 🔵 Low: <b>{low_count}</b>\n",
            f"────────────────────────",
        ]

        # Выводим до 8 наиболее критичных проблем
        for idx, v in enumerate(vulns[:8], 1):
            score_str = f"{v.cvss_score:.1f}" if v.cvss_score > 0 else "N/A"
            link_text = f"<a href=\"{v.url}\">{html.escape(v.vuln_id)}</a>"

            card = (
                f"<b>#{idx}</b> 📦 <b>{html.escape(v.package_name)}</b> <code>{html.escape(v.installed_version)}</code>\n"
                f"🆔 {link_text}\n"
                f"📊 <b>CVSS:</b> <code>{score_str}</code> [{v.cvss_level}]\n"
                f"🛡 <b>Безопасная версия:</b> <code>{html.escape(v.fixed_version)}</code>"
            )
            if v.summary:
                card += f"\n<i>{html.escape(v.summary[:100])}...</i>"
            lines.append(card)
            lines.append("────────────────────────")

        if len(vulns) > 8:
            lines.append(f"<i>...и еще {len(vulns) - 8} уязвимостей меньшей критичности.</i>")

        return "\n".join(lines)
