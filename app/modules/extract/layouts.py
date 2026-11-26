"""Bounded visible HTML structure for report procedure extraction.

This supplements the existing table parser. It neither renders JavaScript
nor retrieves links, styles or remote resources.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser

from .html import Document, Table

MAX_NODES = 20000
MAX_DEPTH = 64
MAX_BLOCKS = 200
_SKIP = {"script", "style", "noscript", "template", "svg"}
_VOID = {"br", "hr", "img", "input", "meta", "link", "wbr", "source", "embed", "area", "base", "col", "param", "track"}
_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_GRID_BLOCKS = _HEADINGS | {"table", "ul", "ol", "pre", "article", "section"}


@dataclass
class Node:
    tag: str
    children: list = field(default_factory=list)
    attrs: dict = field(default_factory=dict)

    def raw(self) -> str:
        return "".join(child if isinstance(child, str) else
                       "\n" if child.tag == "br" else child.raw() for child in self.children)

    def text(self) -> str:
        return " ".join(self.raw().split())[:4000]


class StructureParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.stack = [self.root]
        self.skipping = 0
        self.count = 0
        self.limited = False

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP:
            self.skipping += 1
        if self.skipping or self.limited:
            return
        if self.count >= MAX_NODES or len(self.stack) >= MAX_DEPTH:
            self.limited = True
            return
        if tag in {"li", "p"} and self.stack[-1].tag == tag:
            self.stack.pop()
        node = Node(tag, attrs={key: value for key, value in attrs if key in {"src", "href", "alt", "class", "data-language"}})
        self.stack[-1].children.append(node)
        self.count += 1
        if tag not in _VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in _SKIP and self.skipping:
            self.skipping -= 1
            return
        if self.skipping or self.limited:
            return
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if not self.skipping and not self.limited:
            self.stack[-1].children.append(data)


def line_table(text: str, kind: str, caption: str = "") -> Table:
    """Retain physical lines; the catalog-aware extractor aligns them later."""
    return Table(caption, [[line.strip()] for line in text.splitlines()[:2000]], kind)


def _grid_cell(node: Node) -> bool:
    """A cell can wrap inline text, but cannot contain whole report sections."""
    if node.tag in _GRID_BLOCKS:
        return False
    return all(_grid_cell(child) for child in node.children if isinstance(child, Node))


def enrich_html(document: Document, source: str) -> None:
    from .attack import ids

    parser = StructureParser()
    parser.feed(source)
    parser.close()
    document.layout_limited = parser.limited
    document.prose = []
    existing = iter(document.tables)
    additions = []

    def add(table):
        if len(additions) + len(document.tables) < MAX_BLOCKS:
            additions.append(table)
        else:
            document.layout_limited = True

    def walk(parent: Node, heading: str = ""):
        nodes = [child for child in parent.children if isinstance(child, Node) or child.strip()]
        index = 0
        while index < len(nodes):
            node = nodes[index]
            index += 1
            if isinstance(node, str):
                document.prose.append(node[:4000])
                continue
            text = node.text()
            if node.tag in _HEADINGS:
                heading = text[:300]
                if any(ident.startswith("T") for ident in ids(text)):
                    body = []
                    following = index
                    while following < len(nodes) and isinstance(nodes[following], Node) and nodes[following].tag == "p" and len(body) < 8:
                        body.append(nodes[following].text())
                        following += 1
                    if body:
                        add(Table(heading, [["ID", "Use"], [text, " ".join(body)[:4000]]], "HTML Heading Block"))
                        index = following
                continue
            if node.tag == "table":
                table = next(existing, None)
                if table is not None and not table.caption:
                    table.caption = heading
                continue
            if node.tag in {"ul", "ol"}:
                rows = []
                for item in node.children:
                    if not isinstance(item, Node) or item.tag != "li":
                        continue
                    content = Node("li", [part for part in item.children if not isinstance(part, Node) or part.tag not in {"ul", "ol"}]).text()
                    rows.append([content])
                    document.prose.append(content)
                    for nested in item.children:
                        if isinstance(nested, Node) and nested.tag in {"ul", "ol"}:
                            walk(Node("container", [nested]), heading)
                if any(ids(row[0]) for row in rows):
                    add(Table(heading, rows[:2000], "HTML List"))
                continue
            if node.tag == "pre":
                add(line_table(node.raw(), "Preformatted Lines", heading))
                continue
            if node.tag == "p":
                if any(isinstance(child, Node) and child.tag == "br" for child in node.children):
                    add(line_table(node.raw(), "HTML Line Block", heading))
                else:
                    document.prose.append(text)
                # A standalone bold paragraph can introduce a tactic block.
                if len(text) < 120 and any(isinstance(child, Node) and child.tag in {"b", "strong"} for child in node.children):
                    heading = text
                continue
            children = [child for child in node.children if isinstance(child, Node)]
            grid = []
            if node.tag in {"div", "section"}:
                for row in children:
                    cells = [child for child in row.children if isinstance(child, Node)]
                    if row.tag == "div" and 2 <= len(cells) <= 32 and all(_grid_cell(cell) for cell in cells):
                        grid.append([cell.text() for cell in cells])
                if sum(any(ids(cell) for cell in row) for row in grid) >= 2:
                    add(Table(heading, grid[:2000], "HTML Grid"))
                    continue
            walk(node, heading)

    walk(parser.root)
    document.tables.extend(additions)
