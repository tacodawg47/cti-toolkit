"""Preserve explicit ATLAS references separately from ATT&CK identifiers."""

import re

PATTERN = re.compile(r"(?<![\w.])AML\.T[0-9]{4}(?:\.[0-9]{3})?(?![\w.])", re.I)


def extract(document):
    output = {}
    for match in PATTERN.finditer(document.text):
        ident = match[0].upper()
        output.setdefault(ident, {"id": ident, "url": f"https://atlas.mitre.org/techniques/{ident}",
                                  "context": document.text[max(0, match.start()-100):match.end()+200].strip()})
    for table in document.tables:
        for row in table.rows:
            text = " | ".join(row)
            for match in PATTERN.finditer(text):
                ident = match[0].upper()
                output[ident] = {"id": ident, "url": f"https://atlas.mitre.org/techniques/{ident}",
                                 "context": " | ".join(value for value in (table.caption, text) if value)[:1500]}
    return list(output.values())
