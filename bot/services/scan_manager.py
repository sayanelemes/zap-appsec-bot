import asyncio
from datetime import datetime
import html
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from bot.config.config import settings
from bot.services.ai import deduplicate_alerts
from bot.services.sast import GithubSastAuditor, extract_github_owner_repo
from bot.services.security import validate_url_safe
from bot.services.zap import ZapService

logger = logging.getLogger(__name__)


def extract_clean_url(raw_text: str | None) -> str:
    """Извлекает и нормализует URL из текста."""
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


class ScanManager:
    """
    Единый менеджер состояния сканирования (DAST / SAST).
    Обеспечивает синхронизацию между Telegram-ботом и TMA (FastAPI).
    """

    def __init__(self) -> None:
        self._state: str = "idle"  # "idle" | "running" | "stopped" | "finished"
        self._progress: int = 0
        self._logs: list[str] = []
        self._findings: list[dict[str, Any]] = []
        self._target: str = ""
        self._mode: str = "fast"
        self._scan_type: str = "dast"  # "dast" | "sast"
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._spider_id: str = ""
        self._ascan_id: str = ""
        self._zap_service: ZapService | None = None
        self._sast_auditor: GithubSastAuditor | None = None

    def _get_zap(self) -> ZapService:
        if self._zap_service is None:
            api_key = settings.ZAP_API_KEY.get_secret_value() if (settings and settings.ZAP_API_KEY) else ""
            proxy_url = settings.ZAP_PROXY if settings else "http://127.0.0.1:8090"
            self._zap_service = ZapService(proxy_url=proxy_url, api_key=api_key)
        return self._zap_service

    def _get_sast(self) -> GithubSastAuditor:
        if self._sast_auditor is None:
            self._sast_auditor = GithubSastAuditor()
        return self._sast_auditor

    @property
    def is_running(self) -> bool:
        return self._state == "running"

    def add_log(self, message: str) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{now}] {message}"
        self._logs.append(log_line)
        if len(self._logs) > 200:
            self._logs = self._logs[-200:]
        logger.info("[ScanManager] %s", message)

    def get_status(self) -> dict[str, Any]:
        return {
            "state": self._state,
            "progress": self._progress,
            "logs": list(self._logs),
            "findings": list(self._findings),
            "target": self._target,
            "mode": self._mode,
            "scan_type": self._scan_type,
        }

    async def start_scan(self, target: str, mode: str = "fast", user_id: int | None = None) -> dict[str, Any]:
        """Запуск сканирования DAST или SAST."""
        async with self._lock:
            if self.is_running:
                raise RuntimeError("Сканер уже выполняет задачу. Дождитесь завершения или остановите текущий скан.")

            target = target.strip()
            if not target:
                raise ValueError("Укажите адрес цели для сканирования.")

            if mode not in ("passive", "fast", "full"):
                mode = "fast"

            # Сброс состояния
            self._state = "running"
            self._progress = 0
            self._logs.clear()
            self._findings.clear()
            self._target = target
            self._mode = mode
            self._spider_id = ""
            self._ascan_id = ""
            self._stop_event.clear()

            # Определение типа цели: GitHub SAST или Web DAST
            github_parsed = extract_github_owner_repo(target)
            if github_parsed:
                self._scan_type = "sast"
                self.add_log(f"Инициализация SAST-аудита репозитория GitHub: {github_parsed[0]}/{github_parsed[1]}")
                self._task = asyncio.create_task(self._run_sast_worker(github_parsed[0], github_parsed[1]))
            else:
                self._scan_type = "dast"
                clean_target = extract_clean_url(target)
                self._target = clean_target
                self.add_log(f"Инициализация DAST-сканирования ZAP (режим: {mode.upper()}): {clean_target}")
                self._task = asyncio.create_task(self._run_dast_worker(clean_target, mode))

            return self.get_status()

    async def stop_scan(self) -> dict[str, Any]:
        """Экстренная остановка текущего сканирования."""
        async with self._lock:
            if not self.is_running:
                self._state = "stopped"
                self.add_log("Сканирование уже не активно.")
                return self.get_status()

            self._stop_event.set()
            self.add_log("🛑 Получен сигнал экстренной остановки сканирования...")

            if self._scan_type == "dast":
                zap = self._get_zap()
                if self._spider_id:
                    await zap.stop_spider(self._spider_id)
                if self._ascan_id:
                    await zap.stop_active_scan(self._ascan_id)
                await zap.stop_all_scans()

            if self._task and not self._task.done():
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass

            self._state = "stopped"
            self.add_log("🛑 Сканирование успешно остановлено пользователем.")
            return self.get_status()

    async def _run_sast_worker(self, owner: str, repo: str) -> None:
        """Воркер статического анализа зависимостей через OSV.dev."""
        try:
            self._progress = 10
            self.add_log(f"Поиск файлов манифестов (requirements.txt, package.json) в {owner}/{repo}...")
            auditor = self._get_sast()

            if self._stop_event.is_set():
                self._state = "stopped"
                return

            self._progress = 30
            self.add_log("Проверка манифестов и опрос базы уязвимостей OSV.dev...")
            report_text, vulns, total_pkgs = await auditor.audit_repository(owner, repo)

            if self._stop_event.is_set():
                self._state = "stopped"
                return

            self._progress = 80
            self.add_log(f"Проверено библиотек: {total_pkgs}. Обнаружено уязвимостей: {len(vulns)}")

            # Конвертация в унифицированный формат
            findings: list[dict[str, Any]] = []
            for v in vulns:
                # Определение severity
                score = v.cvss_score or 0.0
                if score >= 9.0:
                    sev = "CRITICAL"
                elif score >= 7.0:
                    sev = "HIGH"
                elif score >= 4.0:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"

                findings.append({
                    "title": f"{v.package_name}@{v.installed_version} ({v.vuln_id})",
                    "severity": sev,
                    "description": f"{v.summary}\nБезопасная версия (Fixed in): {v.fixed_version}",
                    "param": v.package_name,
                    "cwe": "",
                    "cve": v.vuln_id,
                    "cvss": score,
                })

            self._findings = findings
            self._progress = 100
            self._state = "finished"
            self.add_log("✅ SAST-аудит успешно завершен!")

        except asyncio.CancelledError:
            self._state = "stopped"
            self.add_log("SAST задача отменена.")
        except Exception as e:
            logger.exception("Ошибка SAST воркера: %s", e)
            self._state = "finished"
            self.add_log(f"❌ Ошибка SAST анализа: {e}")

    async def _run_dast_worker(self, target_url: str, mode: str) -> None:
        """Воркер динамического анализа через OWASP ZAP."""
        zap = self._get_zap()
        try:
            # 1. SSRF-фильтрация
            self._progress = 5
            self.add_log("Проверка цели SSRF-фильтром и резолв DNS...")
            is_safe, reason, resolved_ip = await validate_url_safe(target_url)
            if not is_safe:
                self.add_log(f"❌ Защита от SSRF: Запрос отклонен! {reason}")
                self._state = "stopped"
                return

            ip_info = f" (IP: {resolved_ip})" if resolved_ip else ""
            self.add_log(f"Цель безопасна{ip_info}. Проверка доступности ZAP демона...")

            # 2. Проверка доступности ZAP
            is_alive = await zap.check_health()
            if not is_alive:
                self.add_log("❌ Ошибка: демон OWASP ZAP недоступен. Проверьте порт 8080/8090.")
                self._state = "stopped"
                return

            parsed = urlparse(target_url)
            clean_origin = f"{parsed.scheme}://{parsed.netloc}"

            # 3. Настройка конфигурации сканирования
            self._progress = 10
            self.add_log(f"Применение профиля '{mode.upper()}' в OWASP ZAP...")
            if mode == "passive":
                await zap.configure_passive_scan()
            elif mode == "fast":
                await zap.configure_fast_scan()
            elif mode == "full":
                await zap.configure_full_scan()

            if self._stop_event.is_set():
                self._state = "stopped"
                return

            # Прогрев ZAP
            asyncio.create_task(zap.access_url(target_url))

            # 4. Запуск паука (Spider)
            self._progress = 15
            self.add_log("Запуск краулера (Spider) для построения карты сайта...")
            spider_id = await zap.start_spider(target_url)
            if not spider_id.isdigit():
                spider_id = await zap.start_spider(clean_origin)

            if spider_id.isdigit():
                self._spider_id = spider_id
                max_spider_time = 12 if mode == "passive" else 180
                spider_start = time.monotonic()

                while not self._stop_event.is_set():
                    await asyncio.sleep(2.0)
                    if time.monotonic() - spider_start > max_spider_time:
                        self.add_log("Краулинг завершен по тайм-ауту.")
                        await zap.stop_spider(spider_id)
                        break

                    percent = await zap.get_spider_status(spider_id)
                    # Spider занимает 15% - 40%
                    self._progress = min(40, 15 + int(percent * 0.25))
                    self.add_log(f"Краулер (Spider): {percent}%")
                    if percent >= 100:
                        break

            if self._stop_event.is_set():
                self._state = "stopped"
                return

            # 5. Пассивный или активный скан
            if mode == "passive":
                self._progress = 60
                self.add_log("Анализ пассивных правил (Headers, Cookies, CSP, Information Disclosure)...")
                await zap.wait_for_passive_scan(timeout=8)
                self._progress = 90
            elif mode in ("fast", "full"):
                self._progress = 40
                self.add_log(f"Запуск активного сканирования уязвимостей (SQLi, XSS, RCE, IDOR)...")
                recurse = (mode == "full")
                ascan_id = await zap.start_active_scan(
                    target_url=target_url,
                    base_domain=clean_origin,
                    recurse=recurse,
                )

                if ascan_id.isdigit():
                    self._ascan_id = ascan_id
                    ascan_start = time.monotonic()
                    max_ascan_time = 90 if mode == "fast" else 600

                    while not self._stop_event.is_set():
                        await asyncio.sleep(2.5)
                        elapsed = time.monotonic() - ascan_start
                        if elapsed > max_ascan_time:
                            self.add_log(f"Активное сканирование превысило лимит времени {max_ascan_time}с. Остановка...")
                            await zap.stop_active_scan(ascan_id)
                            break

                        percent = await zap.get_active_scan_status(ascan_id)
                        # Ascan занимает 40% - 90%
                        self._progress = min(90, 40 + int(percent * 0.5))
                        self.add_log(f"Активное сканирование: {percent}%")
                        if percent >= 100:
                            break

            if self._stop_event.is_set():
                self._state = "stopped"
                return

            # 6. Сбор результатов
            self._progress = 95
            self.add_log("Сбор и категоризация обнаруженных уязвимостей...")
            alerts_summary, alerts_list = await zap.get_alerts_summary(clean_origin=clean_origin)
            deduped = deduplicate_alerts(alerts_list)

            risk_map = {
                "High": ("HIGH", 8.5),
                "Medium": ("MEDIUM", 5.5),
                "Low": ("LOW", 3.0),
                "Informational": ("LOW", 1.0),
            }

            findings: list[dict[str, Any]] = []
            for a in deduped:
                raw_risk = str(a.get("risk", "Low")).capitalize()
                sev, score = risk_map.get(raw_risk, ("LOW", 2.0))
                cwe_id = a.get("cweid", "")
                cwe_str = f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else ""

                findings.append({
                    "title": a.get("alert", "Уязвимость ZAP"),
                    "severity": sev,
                    "description": a.get("description", "") or a.get("solution", ""),
                    "param": a.get("param", ""),
                    "cwe": cwe_str,
                    "cve": "",
                    "cvss": score,
                })

            self._findings = findings
            self._progress = 100
            self._state = "finished"
            self.add_log(f"✅ Сканирование ZAP успешно завершено! Найдено проблем: {len(findings)}")

        except asyncio.CancelledError:
            self._state = "stopped"
            self.add_log("DAST задача отменена.")
        except Exception as e:
            logger.exception("Ошибка DAST воркера: %s", e)
            self._state = "finished"
            self.add_log(f"❌ Ошибка во время DAST сканирования: {e}")


# Глобальный синглтон менеджера сканирования
scan_manager = ScanManager()
