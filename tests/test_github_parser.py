import unittest
from bot.services.sast.github_audit import (
    extract_github_owner_repo,
    parse_package_json,
    parse_requirements_txt,
)


class TestGithubParser(unittest.TestCase):
    """Тестирование парсинга репозиториев и файлов манифестов."""

    def test_extract_github_owner_repo(self):
        urls = [
            ("https://github.com/pallets/jinja", ("pallets", "jinja")),
            ("https://github.com/expressjs/express.git", ("expressjs", "express")),
            ("http://www.github.com/torvalds/linux/blob/main/README", ("torvalds", "linux")),
            ("github.com/aiogram/aiogram", ("aiogram", "aiogram")),
        ]
        for url, expected in urls:
            self.assertEqual(extract_github_owner_repo(url), expected)

        # Некорректные ссылки
        self.assertIsNone(extract_github_owner_repo("https://gitlab.com/user/repo"))
        self.assertIsNone(extract_github_owner_repo("not_a_url"))

    def test_parse_requirements_txt(self):
        content = """
        # Comments should be ignored
        flask==2.0.1
        requests>=2.25.1
        pydantic[email]==1.8.2
        jinja2~=3.0.0
        -r other_reqs.txt
        --extra-index-url https://example.com
        git+https://github.com/owner/repo.git
        """
        packages = parse_requirements_txt(content)
        pkg_dict = dict(packages)

        self.assertIn("flask", pkg_dict)
        self.assertEqual(pkg_dict["flask"], "2.0.1")

        self.assertIn("requests", pkg_dict)
        self.assertEqual(pkg_dict["requests"], "2.25.1")

        self.assertIn("pydantic", pkg_dict)
        self.assertEqual(pkg_dict["pydantic"], "1.8.2")

        self.assertIn("jinja2", pkg_dict)
        self.assertEqual(pkg_dict["jinja2"], "3.0.0")

    def test_parse_package_json(self):
        content = """{
            "name": "sample-app",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "~4.17.21",
                "axios": ">=0.21.1"
            },
            "devDependencies": {
                "mocha": "8.3.2"
            }
        }"""
        packages = parse_package_json(content)
        pkg_dict = dict(packages)

        self.assertEqual(pkg_dict.get("express"), "4.17.1")
        self.assertEqual(pkg_dict.get("lodash"), "4.17.21")
        self.assertEqual(pkg_dict.get("axios"), "0.21.1")
        self.assertEqual(pkg_dict.get("mocha"), "8.3.2")


if __name__ == "__main__":
    unittest.main()
