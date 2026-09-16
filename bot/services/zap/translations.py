"""
Модуль перевода и локализации отчетов и уязвимостей OWASP ZAP на русский язык.
"""

from typing import Tuple

# Словарь точных переводов названий уязвимостей OWASP ZAP
ZAP_ALERT_TRANSLATIONS: dict[str, str] = {
    # JavaScript & клиентские уязвимости
    "vulnerable js library": "Уязвимая библиотека JavaScript (Vulnerable JS Library)",
    "vulnerable js component": "Уязвимый компонент JavaScript",
    "cross-domain javascript source file inclusion": "Подключение внешнего JavaScript с другого домена (Cross-Domain JS)",
    "sub resource integrity attribute missing": "Отсутствует проверка целостности внешних скриптов (SRI)",
    "user controllable html element (script cross-site scripting)": "Контролируемый пользователем HTML (вектор XSS)",

    # Заголовки безопасности
    "x-content-type-options header missing": "Отсутствует заголовок X-Content-Type-Options (MIME-защита)",
    "content security policy (csp) header not set": "Отсутствует политика безопасности контента (CSP Header Not Set)",
    "content security policy (csp) header missing": "Отсутствует заголовок Content-Security-Policy",
    "missing anti-clickjacking header": "Отсутствует заголовок защиты от кликджекинга (X-Frame-Options)",
    "anti-clickjacking header": "Заголовок защиты от кликджекинга (Clickjacking)",
    "strict-transport-security header not set": "Отсутствует принудительный HTTPS (HSTS / Strict-Transport-Security)",
    "strict-transport-security header missing": "Отсутствует заголовок Strict-Transport-Security (HSTS)",
    "permissions policy header not set": "Отсутствует заголовок Permissions-Policy (контроль API браузера)",
    "permissions policy header missing": "Отсутствует заголовок Permissions-Policy",
    "x-frame-options header not set": "Отсутствует заголовок X-Frame-Options",
    "x-frame-options header missing": "Отсутствует заголовок X-Frame-Options",
    "referrer-policy header not set": "Отсутствует заголовок Referrer-Policy",
    "insecure http referrer policy": "Небезопасная политика Referrer-Policy",
    "sec-fetch-* headers missing": "Отсутствуют мета-заголовки запросов Sec-Fetch-*",

    # Утечки информации и отладки
    "server leaks information via 'server' http response header field": "Утечка версии сервера в заголовке 'Server'",
    "server leaks version information via \"server\" http response header field": "Утечка версии веб-сервера через заголовок 'Server'",
    "x-backend-server header information leak": "Утечка имени внутреннего бэкенд-сервера в заголовке",
    "x-powered-by header information leak": "Утечка используемых технологий в заголовке 'X-Powered-By'",
    "application error disclosure": "Раскрытие внутренних ошибок приложения (Debug Leak)",
    "timestamp disclosure": "Раскрытие временных меток (Timestamp Disclosure)",
    "timestamp disclosure - unix": "Раскрытие Unix-таймштампов",
    "information disclosure - sensitive information in url": "Утечка конфиденциальных данных через URL",
    "information disclosure - suspicious comments": "Подозрительные комментарии в исходном коде HTML/JS",
    "information disclosure - debug error messages": "Раскрытие отладочных сообщений об ошибках",
    "source code disclosure": "Утечка исходного кода",
    "source code disclosure - git": "Доступность репозитория Git (.git)",
    "backup file disclosure": "Доступность резервных файлов (.bak / .old)",
    "hidden file finder": "Обнаружение скрытых конфигурационных файлов (.env / .git)",
    "directory browsing": "Просмотр содержимого каталогов (Directory Browsing / Indexing)",

    # Cookie & Сессии
    "cookie no httponly flag": "Cookie без флага HttpOnly (риск перехвата через XSS)",
    "cookie without httponly flag": "Cookie без флага HttpOnly",
    "cookie without secure flag": "Cookie без флага Secure (передача в открытом виде)",
    "cookie without samesite attribute": "Cookie без атрибута SameSite (риск CSRF)",
    "cookie loosely scoped": "Недостаточно строгая область действия Cookie (Domain/Path)",
    "session fixation": "Фиксация сессии (Session Fixation)",

    # Инъекции и XSS
    "cross site scripting (reflected)": "Отраженный межсайтовый скриптинг (Reflected XSS)",
    "cross site scripting (persistent)": "Хранимый межсайтовый скриптинг (Stored XSS)",
    "cross site scripting (dom based)": "DOM-ориентированный межсайтовый скриптинг (DOM XSS)",
    "sql injection": "Внедрение SQL-кода (SQL Injection)",
    "sql injection - sqlite": "Внедрение SQL-кода (SQLite Injection)",
    "sql injection - mysql": "Внедрение SQL-кода (MySQL Injection)",
    "sql injection - postgresql": "Внедрение SQL-кода (PostgreSQL Injection)",
    "sql injection - oracle": "Внедрение SQL-кода (Oracle Injection)",
    "sql injection - ms sql": "Внедрение SQL-кода (MS SQL Injection)",
    "sql injection - hypersql": "Внедрение SQL-кода (HSQLDB Injection)",
    "path traversal": "Обход каталога / выход за пределы корня (Path Traversal)",
    "remote code execution": "Удаленное выполнение кода (RCE)",
    "command injection": "Внедрение системных команд (Command Injection)",
    "remote file inclusion": "Удаленное включение файлов (RFI)",
    "server-side template injection": "Внедрение серверных шаблонов (SSTI)",
    "xml external entity attack": "Атака через внешние сущности XML (XXE)",

    # CSRF, CORS & Аутентификация
    "absence of anti-csrf tokens": "Отсутствие CSRF-токенов защиты веб-форм",
    "csrf token not found": "Отсутствует CSRF-токен в форме",
    "cors (cross-origin resource sharing) misconfiguration": "Небезопасная конфигурация CORS (Cross-Origin Resource Sharing)",
    "cross-domain misconfiguration": "Небезопасная междоменная конфигурация",
    "insecure http method": "Небезопасные HTTP-методы (PUT / DELETE / TRACE)",
    "weak authentication method": "Слабый или устаревший метод аутентификации",
    "open redirect": "Небезопасное открытое перенаправление (Open Redirect)",
    "charset mismatch": "Несовпадение кодировок (Charset Mismatch)",
    "pii (personally identifiable information) disclosure": "Утечка персональных данных (PII)",
    "re-examine cache-control directives": "Некорректные директивы кэширования чувствительных данных (Cache-Control)",
    "modern web application": "Современное одностраничное веб-приложение (SPA)",
}

# Шаблоны для частичного перевода
_PARTIAL_RULES = [
    ("sql injection", "Внедрение SQL-кода (SQL Injection)"),
    ("cross site scripting", "Межсайтовый скриптинг (XSS)"),
    ("cross-site scripting", "Межсайтовый скриптинг (XSS)"),
    ("path traversal", "Обход каталога (Path Traversal)"),
    ("directory browsing", "Просмотр содержимого директорий (Directory Browsing)"),
    ("information disclosure", "Утечка информации (Information Disclosure)"),
    ("header not set", "Отсутствует заголовок безопасности"),
    ("header missing", "Отсутствует заголовок безопасности"),
    ("cookie without", "Небезопасные параметры Cookie"),
    ("vulnerable js", "Уязвимость в JavaScript библиотеке"),
    ("open redirect", "Небезопасное перенаправление (Open Redirect)"),
    ("anti-csrf", "Отсутствие защиты от CSRF"),
    ("remote code", "Удаленное выполнение кода (RCE)"),
]

# Словарь типовых фрагментов описания
_DESC_SNIPPETS = {
    "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'":
        "Заголовок X-Content-Type-Options не установлен в 'nosniff'. Браузеры могут интерпретировать файлы некорректно, что открывает вектор для XSS-атак.",
    "The following image is vulnerable to MIME sniffing":
        "Изображение уязвимо к MIME-sniffing. Браузер может исполнить вредоносный код внутри файла.",
    "Content Security Policy (CSP) is an added layer of security":
        "Политика безопасности контента (CSP) не настроена. Это повышает риск успешного проведения атак межсайтового скриптинга (XSS) и внедрения данных.",
    "The Content-Security-Policy HTTP response header can be used to declare approved sources of content":
        "Отсутствует заголовок Content-Security-Policy. Рекомендуется настроить белый список доверенных источников скриптов и стилей.",
    "The Page is vulnerable to Clickjacking":
        "Страница уязвима к кликджекингу (Clickjacking). Злоумышленник может внедрить сайт во внешний iframe и перехватить действия пользователя.",
    "The Server header contains information about the server software":
        "Заголовок ответа 'Server' раскрывает информацию о версии веб-сервера, что упрощает злоумышленникам поиск известных CVE.",
    "A vulnerable JavaScript library was detected":
        "Обнаружена устаревшая клиентская JavaScript-библиотека с известными уязвимостями (CVE). Рекомендуется обновление пакета.",
}


def translate_zap_alert(alert_name: str, description: str = "") -> Tuple[str, str]:
    """
    Переводит название уязвимости OWASP ZAP и её описание на русский язык.
    Возвращает (translated_title, translated_description).
    """
    if not alert_name:
        return "Неизвестная уязвимость ZAP", description

    clean_name = alert_name.strip()
    key = clean_name.lower()

    # 1. Точное совпадение по словарю
    translated_title = ZAP_ALERT_TRANSLATIONS.get(key)

    # 2. Поиск по префиксам/подстрокам если точного нет
    if not translated_title:
        for pattern, ru_title in _PARTIAL_RULES:
            if pattern in key:
                translated_title = f"{ru_title} — {clean_name}"
                break

    # 3. Если перевод не найден, оставляем оригинал
    if not translated_title:
        translated_title = clean_name

    # 4. Перевод описания
    translated_desc = description
    if description:
        for en_snippet, ru_snippet in _DESC_SNIPPETS.items():
            if en_snippet.lower() in description.lower():
                translated_desc = ru_snippet
                break

    return translated_title, translated_desc
