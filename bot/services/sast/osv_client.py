import asyncio
import logging
import math
import re
from dataclasses import dataclass
from typing import Any, Optional
import aiohttp

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"


@dataclass
class OsvVulnerability:
    vuln_id: str             # CVE-XXXX-XXXXX or GHSA-XXXX
    primary_id: str          # Original OSV/GHSA ID
    url: str                 # Link to advisory / CVE
    summary: str
    cvss_score: float        # e.g. 8.1
    cvss_level: str          # "🔴 Critical", "🟠 High", "🟡 Medium", "🔵 Low"
    fixed_version: str       # e.g. ">= 2.11.3" or "Не указана"
    package_name: str
    installed_version: str


def calculate_cvss3_score(vector_str: str) -> Optional[float]:
    """
    Вычисляет Base Score по спецификации CVSS v3.0 / v3.1 из векторной строки.
    Пример: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    """
    try:
        metrics = dict(item.split(":") for item in vector_str.split("/") if ":" in item)

        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map = {"L": 0.77, "H": 0.44}
        ui_map = {"N": 0.85, "R": 0.62}
        scope = metrics.get("S", "U")

        if scope == "U":
            pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
        else:
            pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}

        cia_map = {"H": 0.56, "L": 0.22, "N": 0.0}

        av = av_map.get(metrics.get("AV", "N"), 0.85)
        ac = ac_map.get(metrics.get("AC", "L"), 0.77)
        pr = pr_map.get(metrics.get("PR", "N"), 0.85)
        ui = ui_map.get(metrics.get("UI", "N"), 0.85)

        c = cia_map.get(metrics.get("C", "N"), 0.0)
        i = cia_map.get(metrics.get("I", "N"), 0.0)
        a = cia_map.get(metrics.get("A", "N"), 0.0)

        # Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if scope == "U":
            score = impact + exploitability
        else:
            score = 1.08 * (impact + exploitability)

        # Округление вверх до 1 знака (Roundup по CVSS спецификации)
        rounded = math.ceil(min(10.0, score) * 10.0) / 10.0
        return round(rounded, 1)
    except Exception as e:
        logger.debug("Ошибка парсинга вектора CVSS %s: %s", vector_str, e)
        return None


def get_risk_level(score: float) -> str:
    """
    Сопоставляет числовой балл CVSS со шкалой риска:
    * 9.0–10.0: 🔴 Critical
    * 7.0–8.9: 🟠 High
    * 4.0–6.9: 🟡 Medium
    * 0.1–3.9: 🔵 Low
    """
    if score >= 9.0:
        return "🔴 Critical"
    elif score >= 7.0:
        return "🟠 High"
    elif score >= 4.0:
        return "🟡 Medium"
    elif score > 0.0:
        return "🔵 Low"
    return "⚪ Info"


def parse_vuln_item(
    vuln_data: dict[str, Any],
    package_name: str,
    installed_version: str,
) -> OsvVulnerability:
    """Парсит одну уязвимость из ответа OSV.dev API."""
    raw_id = vuln_data.get("id", "UNKNOWN")
    aliases = vuln_data.get("aliases", [])

    # Приоритет: ищем алиас CVE (CVE-YYYY-XXXXX)
    cve_id = None
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    display_id = cve_id or raw_id

    # Ссылка на базу уязвимостей
    if display_id.startswith("CVE-"):
        url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={display_id}"
    elif raw_id.startswith("GHSA-"):
        url = f"https://github.com/advisories/{raw_id}"
    else:
        url = f"https://osv.dev/vulnerability/{raw_id}"

    # Парсинг CVSS
    cvss_score = 0.0
    for sev in vuln_data.get("severity", []):
        sev_type = str(sev.get("type", ""))
        score_val = sev.get("score")
        if not score_val:
            continue

        if isinstance(score_val, (int, float)):
            cvss_score = float(score_val)
            break
        elif isinstance(score_val, str):
            # Пробуем как число
            try:
                cvss_score = float(score_val)
                break
            except ValueError:
                pass
            # Пробуем распарсить вектор CVSS 3.x
            if "CVSS:3" in score_val:
                calc = calculate_cvss3_score(score_val)
                if calc is not None:
                    cvss_score = calc
                    break

    # Fallback на database_specific или качественную оценку
    if cvss_score == 0.0:
        db_spec = vuln_data.get("database_specific", {})
        if isinstance(db_spec, dict):
            sub_cvss = db_spec.get("cvss", {})
            if isinstance(sub_cvss, dict) and "score" in sub_cvss:
                try:
                    cvss_score = float(sub_cvss["score"])
                except (ValueError, TypeError):
                    pass
            if cvss_score == 0.0 and "severity" in db_spec:
                sev_text = str(db_spec["severity"]).upper()
                if "CRIT" in sev_text:
                    cvss_score = 9.5
                elif "HIGH" in sev_text:
                    cvss_score = 8.0
                elif "MED" in sev_text:
                    cvss_score = 5.5
                elif "LOW" in sev_text:
                    cvss_score = 3.0

    cvss_level = get_risk_level(cvss_score)

    # Извлечение безопасной версии (fixed)
    fixed_version = "Не указана"
    for aff in vuln_data.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed_version = f">= {ev['fixed']}"
                    break
            if fixed_version != "Не указана":
                break
        if fixed_version != "Не указана":
            break

    summary = vuln_data.get("summary") or vuln_data.get("details", "")[:120].replace("\n", " ")

    return OsvVulnerability(
        vuln_id=display_id,
        primary_id=raw_id,
        url=url,
        summary=summary,
        cvss_score=cvss_score,
        cvss_level=cvss_level,
        fixed_version=fixed_version,
        package_name=package_name,
        installed_version=installed_version,
    )


class OsvClient:
    """Асинхронный клиент для запросов к OSV.dev API."""

    def __init__(self, timeout_sec: float = 10.0) -> None:
        self.timeout_sec = timeout_sec

    async def query_package(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[OsvVulnerability]:
        """
        Запрашивает известные уязвимости для конкретного пакета и версии.
        ecosystem: 'PyPI' или 'npm'
        """
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
            "version": version,
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
        results: list[OsvVulnerability] = []

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(OSV_API_URL, json=payload) as resp:
                    if resp.status != 200:
                        logger.warning("OSV API вернул статус %s для %s@%s", resp.status, package_name, version)
                        return []
                    data = await resp.json()
                    vulns = data.get("vulns", [])
                    for v in vulns:
                        item = parse_vuln_item(v, package_name=package_name, installed_version=version)
                        results.append(item)
        except Exception as e:
            logger.warning("Ошибка запроса к OSV API для %s@%s: %s", package_name, version, e)
            return []

        # Сортируем по убыванию критичности CVSS
        results.sort(key=lambda x: x.cvss_score, reverse=True)
        return results
