import html
import re


def format_telegram_html(text: str) -> str:
    """
    Преобразует текст от LLM (смесь Markdown и HTML) в валидный, безопасный Telegram HTML.
    Гарантирует:
    1. Красивый моноширинный шрифт для блоков кода (<pre><code>) и параметров (<code>).
    2. Стильное отображение цитат (<blockquote>) и акцентов (<b>).
    3. Полное исключение ошибок парсера Telegram ('can't parse entities'),
       экранируя посторонние теги вроде <script>, <input>, <?php>, а также символы <, > и &.
    4. Автоматическую балансировку и закрытие незакрытых HTML-тегов.
    """
    if not text:
        return ""

    # 1. Защита от разрыва промпта /goal при наличии вложенных ``` внутри него
    parts = text.split("────────────────────────")
    cleaned_parts = []
    for part in parts:
        if "/goal" in part:
            goal_pos = part.find("/goal")
            first_fence = part.rfind("```", 0, goal_pos)
            last_fence = part.rfind("```")
            if first_fence != -1 and last_fence > first_fence:
                inner = part[first_fence + 3 : last_fence]
                inner_cleaned = inner.replace("```", "// ")
                part = part[: first_fence + 3] + inner_cleaned + part[last_fence :]
        cleaned_parts.append(part)
    text = "────────────────────────".join(cleaned_parts)

    # 2. Извлекаем и экранируем блоки кода ```lang\ncode\n```
    code_blocks: list[str] = []

    def _save_code_block(match: re.Match) -> str:
        lang = (match.group(1) or "").strip()
        code = match.group(2)
        # Внутри <pre><code> все символы <, >, & обязаны быть экранированы
        escaped_code = html.escape(code.strip("\r\n"), quote=False)
        idx = len(code_blocks)
        if lang:
            tag = f'<pre><code class="language-{html.escape(lang, quote=False)}">{escaped_code}</code></pre>'
        else:
            tag = f'<pre><code>{escaped_code}</code></pre>'
        code_blocks.append(tag)
        return f"___CODE_BLOCK_{idx}___"

    text = re.sub(
        r"```([a-zA-Z0-9_+-]*)\r?\n?(.*?)```",
        _save_code_block,
        text,
        flags=re.DOTALL,
    )

    # 2. Извлекаем и экранируем инлайн код `code`
    inline_codes: list[str] = []

    def _save_inline_code(match: re.Match) -> str:
        c = match.group(1)
        escaped = html.escape(c, quote=False)
        idx = len(inline_codes)
        inline_codes.append(f"<code>{escaped}</code>")
        return f"___INLINE_CODE_{idx}___"

    text = re.sub(r"`([^`\r\n]+)`", _save_inline_code, text)

    # 3. Нормализуем Markdown заголовки: ### Заголовок -> <b>Заголовок</b>
    text = re.sub(r"^#{1,6}\s*(.+)$", r"<b>\1</b>", text, flags=re.MULTILINE)

    # 4. Нормализуем Markdown жирный: **текст** -> <b>текст</b>
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text, flags=re.DOTALL)

    # 5. Разрешенные теги Telegram Bot API
    allowed_pattern = re.compile(
        r"<\/?(?:b|strong|i|em|u|ins|s|strike|del|code|pre|blockquote|tg-spoiler)(?:\s+[^>]*?)?>|"
        r'<a\s+href="[^"]*">|<\/a>',
        re.IGNORECASE,
    )

    tokens: list[str] = []
    last_idx = 0
    for m in allowed_pattern.finditer(text):
        start, end = m.span()
        if start > last_idx:
            chunk = text[last_idx:start]
            tokens.append(html.escape(chunk, quote=False))
        tokens.append(m.group(0))
        last_idx = end

    if last_idx < len(text):
        tokens.append(html.escape(text[last_idx:], quote=False))

    escaped_text = "".join(tokens)

    # 6. Возвращаем блоки кода и инлайн код
    for idx, tag in enumerate(code_blocks):
        escaped_text = escaped_text.replace(f"___CODE_BLOCK_{idx}___", tag)

    for idx, tag in enumerate(inline_codes):
        escaped_text = escaped_text.replace(f"___INLINE_CODE_{idx}___", tag)

    # 7. Балансировка открытых тегов Telegram: предотвращает ошибки незакрытых тегов
    open_tags: list[str] = []
    tag_regex = re.compile(r"<\/?([a-zA-Z0-9_-]+)(?:\s+[^>]*?)?>")
    valid_tag_names = {
        "b", "strong", "i", "em", "u", "ins", "s", "strike", "del",
        "code", "pre", "blockquote", "tg-spoiler", "a"
    }

    for m in tag_regex.finditer(escaped_text):
        full_tag = m.group(0)
        tag_name = m.group(1).lower()
        if tag_name in valid_tag_names:
            if full_tag.startswith("</"):
                if open_tags and open_tags[-1] == tag_name:
                    open_tags.pop()
                elif tag_name in open_tags:
                    while open_tags:
                        popped = open_tags.pop()
                        if popped == tag_name:
                            break
            elif not full_tag.endswith("/>"):
                open_tags.append(tag_name)

    for t in reversed(open_tags):
        escaped_text += f"</{t}>"

    return escaped_text
