"""
HTML to plain text with the standard-library parser.

Good enough for a vendor blog post or advisory: tags are dropped, script and
style contents are skipped, block-level tags become line breaks, and HTML
entities (&amp;, &#46;) are decoded by the parser itself. Nothing is fetched
and no attribute values are kept, so a page full of navigation links does not
flood the extraction with every linked host.
"""

from html.parser import HTMLParser

_SKIP = {"script", "style", "noscript", "template", "svg"}
_BLOCK = {
    "p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table", "pre",
    "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header",
    "footer", "blockquote", "hr", "dd", "dt", "title",
}


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP:
            self._skip_depth += 1
        elif tag in _BLOCK:
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BLOCK:
            self._parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def html_to_text(html: str) -> str:
    parser = _TextParser()
    parser.feed(html)
    parser.close()
    return parser.text()
