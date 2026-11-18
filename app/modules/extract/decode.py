"""Bounded local text decoding for the indicator extractor."""

import base64
import binascii
import json
import re
import zlib

MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MODES = {
    "base64": "Base64 to UTF-8",
    "powershell": "PowerShell Base64 to UTF-16LE",
    "compressed": "Base64 with Gzip or Deflate",
    "charcodes": "Character Codes",
    "jwt": "JWT Header and Payload",
}


def _base64(text: str) -> bytes:
    text = "".join(text.split())
    raw = text.encode("ascii")
    if len(raw) > MAX_INPUT:
        raise ValueError("Encoded input exceeds 1 MB.")
    raw += b"=" * (-len(raw) % 4)
    return base64.b64decode(raw, altchars=b"-_", validate=True)


def _inflate(raw: bytes) -> bytes:
    # Gzip and zlib carry headers. Raw deflate is used in some scripts.
    zlib_header = len(raw) > 1 and raw[0] & 15 == 8 and int.from_bytes(raw[:2]) % 31 == 0
    wrapped = raw.startswith(b"\x1f\x8b") or zlib_header
    inflater = zlib.decompressobj(32 + zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
    decoded = inflater.decompress(raw, MAX_OUTPUT + 1)
    if len(decoded) > MAX_OUTPUT or inflater.unconsumed_tail:
        raise ValueError("Decoded output exceeds 2 MB.")
    if not inflater.eof or inflater.unused_data:
        raise ValueError("Expected one complete compressed stream.")
    return decoded


def decode(text: str, mode: str) -> str:
    if mode not in MODES:
        raise ValueError("Choose a supported decoding format.")
    if not text.strip():
        raise ValueError("Paste an encoded value.")
    if len(text) > MAX_INPUT:
        raise ValueError("Encoded input exceeds 1 MB.")
    try:
        if mode == "jwt":
            parts = text.strip().split(".")
            if len(parts) != 3:
                raise ValueError("Expected a three-part JWT.")
            header, payload = (json.loads(_base64(part)) for part in parts[:2])
            if not isinstance(header, dict) or not isinstance(payload, dict):
                raise ValueError("Expected JSON objects in the JWT header and payload.")
            decoded = json.dumps({"header": header, "payload": payload}, ensure_ascii=False, indent=2)
        elif mode == "charcodes":
            tokens = re.split(r"[\s,]+", text.strip())
            if any(not re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,6}|[0-9]{1,7})", token) for token in tokens):
                raise ValueError("Use decimal or 0x-prefixed character codes separated by commas or spaces.")
            codes = [int(token, 16 if token.lower().startswith("0x") else 10) for token in tokens]
            if any(code > 0x10FFFF or 0xD800 <= code <= 0xDFFF for code in codes):
                raise ValueError("A character code is outside the Unicode range.")
            decoded = "".join(chr(code) for code in codes)
        else:
            raw = _base64(text)
            if mode == "compressed":
                raw = _inflate(raw)
            decoded = raw.decode("utf-16le" if mode == "powershell" else "utf-8-sig")
        if len(decoded.encode("utf-8")) > MAX_OUTPUT:
            raise ValueError("Decoded output exceeds 2 MB.")
        return decoded
    except (binascii.Error, UnicodeError, zlib.error, json.JSONDecodeError, RecursionError):
        raise ValueError("The value does not match the selected format.") from None
