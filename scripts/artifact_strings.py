"""Bounded offline strings/destination review. Never execute artifact code."""

import ast
import base64
import binascii
import hashlib
import ipaddress
import re
import zlib
from urllib.parse import urlsplit

MAX_STRINGS = 10000
MAX_STRING = 16384
MAX_RESULTS = 2000
MAX_TRANSFORMS = 256
MAX_DECODED = 65536
MAX_DECODE_TOTAL = 4 * 1024 * 1024
MAX_AST = 128 * 1024
_ASCII = re.compile(rb"[\x20-\x7e]{4,16384}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,8192}")
_UTF16_BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,8192}")
_URL = re.compile(r"https?://[^\s<>\"'`]+", re.I)
_HOST = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})(?![\w.-])", re.I)
_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])[a-f0-9:]{3,39}(?![\w:])", re.I)
_ENCODED = re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_-]{24,16384}={0,2}(?![\w+/=-])")
_HEX = re.compile(r"(?<!\w)(?:[0-9a-fA-F]{2}){8,8192}(?!\w)")
_NOT_DOMAINS = {"py", "pyc", "pyd", "so", "dll", "exe", "json", "xml", "html", "txt", "md", "cfg", "ini", "toml", "whl", "png", "jpg"}


def redact(text: str) -> str:
    """Keep host/path context, remove URL credentials and parameter values."""
    def url(match):
        try:
            parsed = urlsplit(match[0])
            host = parsed.hostname or "invalid-host"
            host = "[" + host + "]" if ":" in host else host
            port = f":{parsed.port}" if parsed.port else ""
            return f"{parsed.scheme}://{host}{port}{parsed.path}" + ("?[redacted]" if parsed.query else "")
        except ValueError:
            return "[invalid URL]"
    text = _URL.sub(url, text)
    return re.sub(r'''(?i)((?:["']?(?:password|token|secret|api[_-]?key)["']?)\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^,;\s]+)''',
                  r"\1[redacted]", text)


def _literal(node, depth=0):
    if depth > 8:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= MAX_STRING else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left, depth + 1), _literal(node.right, depth + 1)
        if left is not None and right is not None and len(left) + len(right) <= MAX_STRING:
            return left + right
    return None


class Review:
    def __init__(self):
        self.destinations = []
        self.strings = []
        self.members = {}
        self.issues = []
        self._seen = set()
        self._strings_seen = 0
        self._transforms = 0
        self._decoded = 0

    def issue(self, value):
        if value not in self.issues:
            self.issues.append(value)

    def member(self, name: str, data: bytes):
        self.members[name] = hashlib.sha256(data).hexdigest()
        if name.endswith(".dist-info/RECORD"):
            return  # Integrity is checked separately; manifest digests are not payload candidates.
        if name.lower().endswith((".zip", ".whl", ".tar", ".gz", ".7z", ".rar")):
            self.issue(f"{name}: nested archive not expanded")
        self._bytes(name, data, "raw", 0, 0)
        if name.lower().endswith(".py"):
            if len(data) > MAX_AST:
                self.issue(f"{name}: literal reconstruction skipped above {MAX_AST} bytes")
                return
            try:
                tree = ast.parse(data)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self.issue(f"{name}: Python literals could not be parsed")
                return
            for number, node in enumerate(ast.walk(tree)):
                if number >= 10000:
                    self.issue(f"{name}: Python syntax-node limit reached")
                    break
                # AST objects are inspected, never compiled or evaluated.
                if isinstance(node, (ast.Constant, ast.BinOp)):
                    value = _literal(node)
                    if value:
                        self._text(name, value, "python-literal", 0, 0, line=node.lineno)

    def _bytes(self, name, data, chain, origin, depth, *, line=None):
        for pattern, encoding in ((_ASCII, "ascii"), (_UTF16, "utf-16-le"), (_UTF16_BE, "utf-16-be")):
            for match in pattern.finditer(data):
                if self._strings_seen >= MAX_STRINGS:
                    self.issue("Artifact string limit reached; coverage is incomplete")
                    return
                value = match[0].decode(encoding)
                self._text(name, value, chain + "/" + encoding,
                           match.start() if depth == 0 else origin, depth,
                           line=line,
                           decoded_offset=match.start() if depth else None)
        # A first decoding layer may expose compressed bytes rather than text.
        if data.startswith((b"\x1f\x8b", b"x\x9c", b"x\xda", b"x\x01")) and depth < 2:
            self._transform(name, data, "gzip" if data.startswith(b"\x1f\x8b") else "zlib", chain, origin, depth, line=line)

    def _text(self, name, value, chain, origin, depth, *, line=None, decoded_offset=None):
        if self._strings_seen >= MAX_STRINGS:
            self.issue("Artifact string limit reached; coverage is incomplete")
            return
        self._strings_seen += 1
        # Samples are deliberately bounded; they are review evidence, not a
        # promise to list every printable byte or every possible secret format.
        if len(self.strings) < 200 and chain != "python-literal":
            self.strings.append({"member": name, "offset": origin, "line": line,
                                 "transform": chain, "text": redact(value[:500])})
        hosts = []
        for match in _URL.finditer(value):
            try:
                host = urlsplit(match[0]).hostname
            except ValueError:
                host = None
            if host:
                hosts.append((host.lower(), match.start(), "URL Host"))
        # Python attributes such as os.environ are not domain evidence.
        # Inspect bare hosts in its actual literals; raw URL hosts still count.
        if not (name.lower().endswith(".py") and chain == "raw/ascii"):
            for match in _HOST.finditer(value):
                if match[0].rsplit(".", 1)[-1].lower() not in _NOT_DOMAINS:
                    hosts.append((match[0].lower(), match.start(), "Domain Candidate"))
        for match in list(_IP.finditer(value)) + list(_IPV6.finditer(value)):
            try:
                host = str(ipaddress.ip_address(match[0]))
            except ValueError:
                continue
            hosts.append((host, match.start(), "IP Literal"))
        for host, position, kind in hosts:
            key = (name, host, chain, origin, line)
            if key in self._seen:
                continue
            if len(self.destinations) >= MAX_RESULTS:
                self.issue("Destination limit reached; coverage is incomplete")
                break
            self._seen.add(key)
            parts = name.lower().split("/")
            hint = "Test/Example" if any(p in {"tests", "test", "examples"} or p.startswith("test_") for p in parts) else (
                "Documentation/Metadata" if any(p in {"docs", "doc"} or p.endswith((".md", ".dist-info")) for p in parts) else "Source/Data")
            self.destinations.append({"host": host, "kind": kind, "member": name,
                                      "offset": origin, "line": line, "decoded_offset": decoded_offset,
                                      "transform": chain, "usage_hint": hint,
                                      "context": redact(value[max(0, position - 70):position + 180])})
        if depth >= 2:
            return
        if name.lower().endswith(".py") and chain == "raw/ascii":
            return  # Decode actual string constants below, not every source identifier.
        for pattern, transform in ((_HEX, "hex"), (_ENCODED, "base64")):
            for match in pattern.finditer(value):
                if self._transforms >= MAX_TRANSFORMS:
                    self.issue("Decode-attempt limit reached; further encoded content not examined")
                    return
                encoded = match[0]
                self._transform(name, encoded, transform, chain, origin, depth, line=line)

    def _transform(self, name, encoded, transform, chain, origin, depth, *, line=None):
        if self._transforms >= MAX_TRANSFORMS or self._decoded >= MAX_DECODE_TOTAL:
            self.issue("Decode resource limit reached; coverage is incomplete")
            return
        self._transforms += 1
        try:
            if transform == "hex":
                decoded = bytes.fromhex(encoded)
            elif transform == "base64":
                padded = encoded + "=" * (-len(encoded) % 4)
                decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
            else:
                decoder = zlib.decompressobj(31 if transform == "gzip" else 15)
                decoded = decoder.decompress(encoded, MAX_DECODED + 1)
                if not decoder.eof or decoder.unused_data:
                    self.issue(f"{name}: compressed decoding incomplete or has trailing data")
                    return
            if len(decoded) > MAX_DECODED or self._decoded + len(decoded) > MAX_DECODE_TOTAL:
                self.issue(f"{name}: decoded-output limit exceeded")
                return
        except (ValueError, binascii.Error, zlib.error):
            return
        self._decoded += len(decoded)
        self._bytes(name, decoded, chain + "/" + transform, origin, depth + 1, line=line)

    def result(self):
        return {"schema_version": 1, "members": self.members, "destinations": self.destinations,
                "string_samples": self.strings, "strings_examined": self._strings_seen,
                "decode_attempts": self._transforms, "decoded_bytes": self._decoded,
                "coverage_issues": self.issues,
                "limitations": ["Candidates are not observed connections or malware verdicts.",
                                "No arbitrary code execution, network lookup, XOR solving, unpacking or universal deobfuscation.",
                                "At most two decoding layers; no archive recursion. String samples are a bounded preview.",
                                "Context redaction is best effort; keep reports local and review before sharing."]}
