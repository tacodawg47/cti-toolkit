"""Local decoding and wrapped PDF digest recovery, with no network."""

import base64
import gzip
import json
import unittest
import zlib
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.modules.extract import decode, extractor, pdf
from tests.test_extract import MD5, SHA1, SHA256, minimal_pdf, values


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class DecodeTests(unittest.TestCase):
    def test_plain_and_powershell_and_character_codes(self):
        text = "https://example.org/a CVE-2026-12345"
        for mode, encoded in (
            ("base64", b64(text.encode())),
            ("powershell", b64(text.encode("utf-16le"))),
            ("charcodes", ", ".join(str(ord(char)) for char in text)),
            ("charcodes", " ".join(hex(ord(char)) for char in text)),
        ):
            with self.subTest(mode=mode):
                self.assertEqual(decode.decode(encoded, mode), text)

    def test_three_compression_formats(self):
        text = b"IOC hxxps://example[.]org/a"
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw = compressor.compress(text) + compressor.flush()
        for data in (gzip.compress(text), zlib.compress(text), raw):
            self.assertEqual(decode.decode(b64(data), "compressed"), text.decode())

    def test_jwt_fields_are_decoded_without_trusting_signature(self):
        token = b64(b'{"alg":"HS256"}') + "." + b64(b'{"host":"example.org"}') + ".invalid"
        output = json.loads(decode.decode(token, "jwt"))
        self.assertEqual(output["payload"]["host"], "example.org")
        self.assertNotIn("signature", output)

    def test_limits_and_invalid_inputs(self):
        for mode, value in (("base64", "@@@"), ("base64", b64(b"\xff")), ("powershell", b64(b"a")),
                            ("charcodes", "1114112"), ("charcodes", "0xd800"), ("charcodes", "[char]65"),
                            ("jwt", "a.b"), ("jwt", b64(b"[]") + "." + b64(b"{}") + ".x"),
                            ("compressed", b64(gzip.compress(b"abc")[:-2])),
                            ("compressed", b64(gzip.compress(b"a") + gzip.compress(b"b"))),
                            ("unknown", "abc")):
            with self.subTest(mode=mode, value=value), self.assertRaises(ValueError):
                decode.decode(value, mode)
        with self.assertRaisesRegex(ValueError, "1 MB"):
            decode.decode("A" * (decode.MAX_INPUT + 1), "base64")
        with patch.object(decode, "MAX_OUTPUT", 1024), self.assertRaisesRegex(ValueError, "2 MB"):
            decode.decode(b64(gzip.compress(b"a" * 4096)), "compressed")

    def test_route_extracts_and_escapes_without_external_requests(self):
        client = TestClient(app, base_url="http://127.0.0.1")
        text = '<script>alert(1)</script> hxxps://example[.]org/a CVE-2026-12345'
        with patch("httpx.AsyncClient.send", side_effect=AssertionError("Unexpected network request")):
            response = client.post("/extract/decode", data={"mode": "base64", "encoded": b64(text.encode())})
            self.assertEqual(response.status_code, 200)
            self.assertIn("https://example.org/a", response.text)
            self.assertIn("CVE-2026-12345", response.text)
            self.assertNotIn("<script>alert(1)</script>", response.text)
            self.assertIn("&lt;script&gt;", response.text)
            response = client.post("/extract/decode", data={"mode": "jwt", "encoded": "a.b.c"})
            self.assertEqual(response.status_code, 200)
            self.assertIn("does not match", response.text)
            self.assertEqual(client.post("/extract/decode", data={"encoded": "YQ=="},
                                         headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)


class WrappedPdfTests(unittest.TestCase):
    def test_three_hash_lengths_keep_heading_and_annotation(self):
        for heading, value, split in (("SHA256 Malware.Example", SHA256, 36),
                                      ("SHA1 Detection Name", SHA1, 20), ("MD5", MD5, 16),
                                      ("SHA256", SHA256, 60)):
            with self.subTest(heading=heading):
                document = pdf.hash_document(f"{heading}\n{value[:split]}\n{value[split:]} (abused)")
                self.assertEqual(values(extractor.extract(document.text), "hash"), [value])
                self.assertIn(heading, document.hash_context[value][0])
                self.assertIn("(abused)", document.hash_context[value][0])

    def test_page_breaks_and_footer(self):
        document = pdf.hash_document(f"SHA256\n{SHA256[:32]}\n12\n\fSHA256\n{SHA256[32:]}")
        self.assertEqual(values(extractor.extract(document.text), "hash"), [SHA256])
        self.assertIn("Rejoined PDF lines", document.hash_context[SHA256][0])

    def test_adjacent_complete_hashes_and_separators_are_preserved(self):
        second = "a" * 32
        document = pdf.hash_document(f"{MD5}\n{second}\n{SHA1}")
        self.assertEqual(values(extractor.extract(document.text), "hash"), [MD5, second, SHA1])
        document = pdf.hash_document(f"SHA256\n{SHA256[:32]}\nUnrelated Text\n{SHA256[32:]}")
        self.assertNotIn(SHA256, values(extractor.extract(document.text), "hash"))

    def test_pdf_upload_runs_repair_and_shows_context(self):
        # PDF text operators create two physical lines in a real text-layer PDF.
        body = minimal_pdf(f"SHA256 Malware.Example) Tj 0 -14 Td ({SHA256[:36]}) Tj 0 -14 Td ({SHA256[36:]}")
        client = TestClient(app, base_url="http://127.0.0.1")
        response = client.post("/extract", files={"file": ("report.pdf", body, "application/pdf")})
        self.assertEqual(response.status_code, 200)
        self.assertIn(SHA256, response.text)
        self.assertIn("PDF Row Context", response.text)
        self.assertIn("SHA256 Malware.Example", response.text)
