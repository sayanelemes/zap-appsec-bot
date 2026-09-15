import unittest
from bot.services.sast.osv_client import (
    calculate_cvss3_score,
    get_risk_level,
    parse_vuln_item,
)


class TestOsvClient(unittest.TestCase):
    """Тестирование парсинга OSV.dev ответов и расчета CVSS."""

    def test_calculate_cvss3_score(self):
        # Критическая уязвимость (Score 9.8)
        vector_crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score_crit = calculate_cvss3_score(vector_crit)
        self.assertEqual(score_crit, 9.8)
        self.assertEqual(get_risk_level(score_crit), "🔴 Critical")

        # Высокая уязвимость с Scope Changed (Score 8.6)
        vector_high = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
        score_high = calculate_cvss3_score(vector_high)
        self.assertEqual(score_high, 8.6)
        self.assertEqual(get_risk_level(score_high), "🟠 High")

        # Средняя уязвимость (Low/Medium)
        self.assertEqual(get_risk_level(5.5), "🟡 Medium")
        self.assertEqual(get_risk_level(2.5), "🔵 Low")

    def test_parse_vuln_item_cve_alias(self):
        raw_osv_data = {
            "id": "GHSA-462w-v97r-4m45",
            "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
            "summary": "Jinja2 sandbox escape via string formatting",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"}
            ],
            "affected": [
                {
                    "package": {"name": "jinja2", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.10.1"}
                            ]
                        }
                    ]
                }
            ]
        }

        parsed = parse_vuln_item(raw_osv_data, package_name="jinja2", installed_version="2.10")
        self.assertEqual(parsed.vuln_id, "CVE-2019-10906")
        self.assertIn("cve.mitre.org", parsed.url)
        self.assertEqual(parsed.cvss_score, 8.6)
        self.assertEqual(parsed.cvss_level, "🟠 High")
        self.assertEqual(parsed.fixed_version, ">= 2.10.1")


if __name__ == "__main__":
    unittest.main()
