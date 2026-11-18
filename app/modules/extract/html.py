"""
HTML to plain text with the standard-library parser.

Good enough for a vendor blog post or advisory: tags are dropped, script and
style contents are skipped, block-level tags become line breaks, and HTML
entities (&amp;, &#46;) are decoded by the parser itself. Nothing is fetched
and no attribute values are kept, so a page full of navigation links does not
flood the extraction with every linked host.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser

_SKIP = {"script", "style", "noscript", "template", "svg"}
_BLOCK = {
    "p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table", "pre",
    "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header",
    "footer", "blockquote", "hr", "dd", "dt", "title",
}


@dataclass
class Table:
    caption: str = ""
    rows: list[list[str]] = field(default_factory=list)


@dataclass
class Document:
    text: str
    tables: list[Table] = field(default_factory=list)
    hash_context: dict[str, list[str]] = field(default_factory=dict)


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0
        self.tables: list[Table] = []
        self._depth = 0
        self._table: Table | None = None
        self._row: list[tuple[str, int, int]] = []
        self._spans: dict[int, tuple[str, int]] = {}
        self._capture: tuple[str, int, int, list[str]] | None = None

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in _BLOCK:
            self._parts.append("\n")
        if tag == "table":
            if self._depth == 0:
                self._table, self._spans = Table(), {}
            self._depth += 1
        if self._depth != 1:
            return
        if tag == "tr":
            self._finish_row()
        if tag in ("caption", "td", "th"):
            self._finish_cell()
            attributes = dict(attrs)
            self._capture = (tag, _span(attributes.get("rowspan")), _span(attributes.get("colspan")), [])
        elif self._capture and tag in _BLOCK:
            self._capture[3].append(" ")

    def handle_endtag(self, tag):
        if tag in _SKIP and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in _BLOCK:
            self._parts.append("\n")
        if self._depth == 1:
            if tag in ("caption", "td", "th"):
                self._finish_cell()
            elif tag == "tr":
                self._finish_row()
            elif tag == "table":
                self._finish_table()
            elif self._capture and tag in _BLOCK:
                self._capture[3].append(" ")
        if tag == "table" and self._depth:
            self._depth -= 1

    def handle_data(self, data):
        if not self._skip_depth:
            self._parts.append(data)
            if self._depth == 1 and self._capture:
                self._capture[3].append(data)

    def _finish_cell(self) -> None:
        if not self._capture:
            return
        tag, rowspan, colspan, parts = self._capture
        self._capture = None
        text = " ".join("".join(parts).split())[:4000]
        if tag == "caption":
            self._table.caption = text
        elif len(self._row) < 32:
            self._row.append((text, rowspan, colspan))

    def _finish_row(self) -> None:
        self._finish_cell()
        if not self._row or len(self._table.rows) >= 2000:
            self._row = []
            return
        cells = {index: text for index, (text, _) in self._spans.items()}
        self._spans = {index: (text, remaining - 1) for index, (text, remaining) in self._spans.items()
                       if remaining > 1}
        column = 0
        for text, rowspan, colspan in self._row:
            for _ in range(colspan):
                while column in cells:
                    column += 1
                if column >= 32:
                    break
                cells[column] = text
                if rowspan > 1:
                    self._spans[column] = (text, rowspan - 1)
                column += 1
        self._table.rows.append([cells.get(index, "") for index in range(max(cells) + 1)])
        self._row = []

    def _finish_table(self) -> None:
        self._finish_row()
        if self._table.rows and len(self.tables) < 200:
            self.tables.append(self._table)
        self._table = None

    def document(self) -> Document:
        if self._table is not None:
            self._finish_table()
        return Document("".join(self._parts), self.tables)


def _span(value: str | None) -> int:
    return max(1, min(32, int(value))) if value and len(value) < 3 and value.isascii() and value.isdigit() else 1


def parse_document(html: str) -> Document:
    parser = _TextParser()
    parser.feed(html)
    parser.close()
    return parser.document()


def html_to_text(html: str) -> str:
    return parse_document(html).text
