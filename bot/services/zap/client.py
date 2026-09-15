import asyncio
import logging
from typing import Any
import requests
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)


class ZapService:
    """
    Асинхронный сервис-обертка над официальной библиотекой python-owasp-zap-v2.4.
    Все блокирующие сетевые вызовы выполняются в отдельных потоках через asyncio.to_thread.
    """

    def __init__(self, proxy_url: str, api_key: str):
        self.proxy_url = proxy_url
        self.api_key = api_key
        self._proxies = {"http": self.proxy_url, "https": self.proxy_url}
        self._zap = ZAPv2(
            proxies=self._proxies,
            apikey=self.api_key,
        )

    async def check_health(self) -> bool:
        """Проверка доступности ZAP демона."""
        try:
            version = await asyncio.to_thread(lambda: self._zap.core.version)
            logger.info("Успешное подключение к OWASP ZAP (версия: %s)", version)
            return bool(version)
        except Exception as e:
            logger.error("Ошибка подключения к OWASP ZAP API: %s", e)
            return False

    async def configure_fast_scan(self) -> None:
        """
        Конфигурирует ZAP для режима быстрого сканирования (Fast Scan):
        - Ограничение времени проверки одного правила: 1 минута
        - Максимальное время всего сканирования: 2 минуты
        - Потоков на хост: 10
        - Хостов на скан: 2
        - Глубина паука (spider max_depth): 2
        """
        def _configure() -> None:
            try:
                self._zap.ascan.set_option_max_rule_duration_in_mins(1)
            except Exception as e:
                logger.warning("Не удалось установить max_rule_duration_in_mins: %s", e)
            try:
                self._zap.ascan.set_option_max_scan_duration_in_mins(2)
            except Exception as e:
                logger.warning("Не удалось установить max_scan_duration_in_mins: %s", e)
            try:
                self._zap.ascan.set_option_thread_per_host(10)
            except Exception as e:
                logger.warning("Не удалось установить thread_per_host: %s", e)
            try:
                self._zap.ascan.set_option_host_per_scan(2)
            except Exception as e:
                logger.warning("Не удалось установить host_per_scan: %s", e)
            try:
                self._zap.spider.set_option_max_depth(2)
            except Exception as e:
                logger.warning("Не удалось установить max_depth: %s", e)

        await asyncio.to_thread(_configure)
        logger.info("Параметры Fast Scan успешно применены к ZAP.")

    async def access_url(self, target_url: str) -> None:
        """
        Предварительный прогрев URL для инициализации дерева сайтов ZAP:
        1. Вызов zap.core.access_url
        2. Прямой HTTP-запрос через локальный прокси ZAP (гарантирует фиксацию в дереве узлов)
        """
        try:
            await asyncio.to_thread(self._zap.core.access_url, url=target_url)
        except Exception as e:
            logger.warning("Ошибка при вызове core.access_url для %s: %s", target_url, e)

        try:
            await asyncio.to_thread(
                requests.get,
                target_url,
                proxies=self._proxies,
                timeout=10,
                verify=False,
            )
            logger.info("Успешный HTTP прогрев через ZAP прокси для: %s", target_url)
        except Exception as e:
            logger.warning("Прокси-запрос прогрева не удался для %s: %s", target_url, e)

    async def start_spider(self, target_url: str) -> str:
        """Запуск паука (Spider) для краулинга ссылок и структуры сайта."""
        try:
            scan_id = await asyncio.to_thread(self._zap.spider.scan, url=target_url)
            logger.info("Запущен Spider для %s (Scan ID: %s)", target_url, scan_id)
            return str(scan_id)
        except Exception as e:
            logger.error("Ошибка запуска Spider для %s: %s", target_url, e)
            return "error"

    async def get_spider_status(self, scan_id: str) -> int:
        """Получение прогресса краулинга (0-100%)."""
        if not scan_id.isdigit():
            return 100
        try:
            status = await asyncio.to_thread(self._zap.spider.status, scan_id)
            return int(status)
        except Exception as e:
            logger.warning("Ошибка получения статуса Spider %s: %s", scan_id, e)
            return 100

    async def start_active_scan(self, target_url: str, base_domain: str | None = None) -> str:
        """
        Запуск активного сканирования (Active Scan) в режиме Fast Scan (recurse=False, inscopeonly=False).
        Если целевой leaf URL возвращает url_not_found, пробуем сканировать от base_domain.
        """
        try:
            scan_id = await asyncio.to_thread(
                self._zap.ascan.scan,
                url=target_url,
                recurse=False,
                inscopeonly=False,
            )
            scan_id_str = str(scan_id)
            logger.info("Запуск Fast Active Scan (recurse=False) для %s -> результат: %s", target_url, scan_id_str)

            # Если вернулась ошибка url_not_found и указан базовый домен, запускаем от корня домена
            if (not scan_id_str.isdigit()) and base_domain and base_domain != target_url:
                logger.info("Повторная попытка запуска Active Scan по base_domain: %s", base_domain)
                fallback_scan_id = await asyncio.to_thread(
                    self._zap.ascan.scan,
                    url=base_domain,
                    recurse=False,
                    inscopeonly=False,
                )
                scan_id_str = str(fallback_scan_id)
                logger.info("Результат Active Scan для %s: %s", base_domain, scan_id_str)

            return scan_id_str
        except Exception as e:
            logger.error("Ошибка запуска Active Scan для %s: %s", target_url, e)
            return "error"

    async def get_active_scan_status(self, scan_id: str) -> int:
        """Получение прогресса активного аудита (0-100%)."""
        if not scan_id.isdigit():
            return 100
        try:
            status = await asyncio.to_thread(self._zap.ascan.status, scan_id)
            return int(status)
        except Exception as e:
            logger.warning("Ошибка получения статуса Active Scan %s: %s", scan_id, e)
            return 100

    async def stop_all_scans(self) -> None:
        """Аварийная остановка всех сканирований при наступлении дедлайна."""
        try:
            await asyncio.to_thread(self._zap.ascan.stop_all_scans)
            logger.info("Вызвана аварийная остановка активных сканирований ZAP.")
        except Exception as e:
            logger.warning("Ошибка при вызове ascan.stop_all_scans: %s", e)
        try:
            await asyncio.to_thread(self._zap.spider.stop_all_scans)
        except Exception:
            pass

    async def get_alerts_summary(self, clean_origin: str) -> tuple[dict[str, int], list[dict[str, Any]]]:
        """
        Выгрузка обнаруженных алертов:
        1. Сначала фильтруем по чистому origin (схема + хост[:порт]), исключая path и query string.
        2. Если результат пуст — выполняем резервный вызов alerts() без фильтрации baseurl.
        Возвращает кортеж (сводка_по_рискам, список_алертов).
        """
        summary = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }
        alerts: list[dict[str, Any]] = []

        try:
            # 1. Запрос по чистому origin
            alerts = await asyncio.to_thread(
                self._zap.core.alerts,
                baseurl=clean_origin,
            )

            # 2. Если пусто — запасной вызов без параметров фильтрации
            if not alerts:
                logger.info("Алерты по baseurl=%s не найдены, вызываем общий zap.core.alerts()", clean_origin)
                alerts = await asyncio.to_thread(self._zap.core.alerts)

            for alert in alerts:
                risk = alert.get("risk", "Informational")
                if risk in summary:
                    summary[risk] += 1
                else:
                    summary["Informational"] += 1

            logger.info("Успешно выгружено %d алертов (High: %d, Med: %d, Low: %d, Info: %d)",
                        len(alerts), summary["High"], summary["Medium"], summary["Low"], summary["Informational"])
        except Exception as e:
            logger.error("Ошибка при получении списка алертов: %s", e)

        return summary, alerts

    async def generate_html_report(self) -> bytes:
        """Генерация и выгрузка отчета сканирования в формате HTML."""
        try:
            report = await asyncio.to_thread(self._zap.core.htmlreport)
            if isinstance(report, str):
                return report.encode("utf-8")
            return report
        except Exception as e:
            logger.error("Ошибка при генерации HTML-отчета: %s", e)
            return b"<html><body><h1>Error generating report</h1></body></html>"
