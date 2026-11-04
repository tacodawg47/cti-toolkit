"""
Tests for the Phase 2 IOC extraction module. Pure logic except the fetch
tests, which use an httpx mock transport. No network, no database.

Run from the project root:
    .venv/Scripts/python.exe -m unittest tests.test_extract -v
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import httpx

from app.core.allowlist import allowlist
from app.core.indicators import canonical, detect_type
from app.modules.enrich import base
from app.modules.extract import extractor, fetch, pdf
from app.modules.extract.extractor import extract, refang_text
from app.modules.extract.html import html_to_text

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def values(result, itype):
    return [i.value for i in result.by_type(itype)]


class CveIndicatorTypeTests(unittest.TestCase):
    def test_detect_and_canonical(self):
        self.assertEqual(detect_type("CVE-2023-4966"), "cve")
        self.assertEqual(detect_type("cve-2021-44228"), "cve")
        self.assertEqual(canonical("cve", "cve-2021-44228"), "CVE-2021-44228")

    def test_near_misses(self):
        self.assertEqual(detect_type("CVE-2023-123"), "unknown")     # too short
        self.assertEqual(detect_type("CVE-23-4966"), "unknown")      # bad year


class RefangTextTests(unittest.TestCase):
    def test_document_wide(self):
        s = "C2 at hxxps://evil[.]com/x and fxp://drop(.)net, mail user[at]bad{dot}org"
        self.assertEqual(refang_text(s),
                         "C2 at https://evil.com/x and ftp://drop.net, mail user@bad.org")

    def test_spelled_out_dot(self):
        self.assertEqual(refang_text("see evil dot com now"), "see evil.com now")

    def test_hxxp_only_with_separator(self):
        self.assertEqual(refang_text("shxxp.example.com hxxpfoo"), "shxxp.example.com hxxpfoo")


class ExtractTests(unittest.TestCase):
    def test_mixed_report(self):
        text = f"""
        The actor used hxxps://evil[.]com/payload.exe (SHA256 {SHA256.upper()})
        and beaconed to 203[.]0[.]113[.]10 on port 443. Also seen: 2001:db8::1,
        drop[.]example[.]org and the sender fake[@]mail[.]example. Exploits
        cve-2023-4966 and CVE-2024-3400. Internal pivot: 10.0.0.5.
        """
        r = extract(text)
        self.assertEqual(values(r, "url"), ["https://evil.com/payload.exe"])
        self.assertEqual(values(r, "hash"), [SHA256])
        self.assertEqual(r.by_type("hash")[0].note, "sha256")
        self.assertEqual(values(r, "ip"), ["203.0.113.10", "2001:db8::1", "10.0.0.5"])
        self.assertEqual(values(r, "domain"), ["evil.com", "drop.example.org"])
        self.assertEqual(values(r, "email"), ["fake@mail.example"])
        self.assertEqual(values(r, "cve"), ["CVE-2023-4966", "CVE-2024-3400"])
        self.assertEqual(r.counts, {"ip": 3, "domain": 2, "url": 1, "hash": 1, "email": 1, "cve": 2})
        self.assertFalse(r.truncated)

    def test_defanged_flag_and_counts(self):
        r = extract("evil[.]com evil[.]com evil.com and bad[.]net")
        evil = r.by_type("domain")[0]
        self.assertEqual(evil.value, "evil.com")
        self.assertEqual(evil.count, 3)
        self.assertFalse(evil.defanged)            # seen plain once
        bad = r.by_type("domain")[1]
        self.assertTrue(bad.defanged)              # never seen plain

    def test_ip_notes(self):
        r = extract("beacon 192.168.1.20 and 127.0.0.1 and 8.8.8.8; sanitised 203.0.113.9 and 2001:db8::5")
        notes = {i.value: i.note for i in r.by_type("ip")}
        self.assertEqual(notes, {
            "192.168.1.20": "private", "127.0.0.1": "loopback", "8.8.8.8": None,
            "203.0.113.9": "documentation", "2001:db8::5": "documentation",
        })

    def test_bad_octet_and_version_strings(self):
        r = extract("not an ip: 999.1.1.1; but 1.2.3.4 is extracted even if a version")
        self.assertEqual(values(r, "ip"), ["1.2.3.4"])

    def test_ipv4_with_sentence_dot_and_port(self):
        r = extract("C2 was 203.0.113.7. Then 203.0.113.8:8443 appeared.")
        self.assertEqual(values(r, "ip"), ["203.0.113.7", "203.0.113.8"])

    def test_ipv6_candidates_are_validated(self):
        r = extract("at 12:30:45 the MAC 00:11:22:33:44:55 and fe80::1 and ::1 and std::string")
        self.assertEqual(values(r, "ip"), ["fe80::1", "::1"])

    def test_filenames_are_not_domains(self):
        r = extract("dropped payload.exe, README.md, loader.ps1, config.json and a.dll")
        self.assertEqual(values(r, "domain"), [])

    def test_url_trailing_punctuation(self):
        r = extract("(see https://evil.com/a). And <https://evil.com/b>, then https://x.org/wiki/Foo_(bar).")
        self.assertEqual(values(r, "url"),
                         ["https://evil.com/a", "https://evil.com/b", "https://x.org/wiki/Foo_(bar)"])

    def test_url_host_listed_once_as_domain(self):
        r = extract("https://evil.com/a and https://evil.com/b and evil.com")
        self.assertEqual(values(r, "domain"), ["evil.com"])
        self.assertEqual(r.by_type("domain")[0].count, 3)

    def test_ip_url_host_listed_as_ip(self):
        r = extract("hxxp://203[.]0[.]113[.]9/x.php")
        self.assertEqual(values(r, "url"), ["http://203.0.113.9/x.php"])
        self.assertEqual(values(r, "ip"), ["203.0.113.9"])
        self.assertTrue(r.by_type("ip")[0].defanged)

    def test_hash_kinds_and_case(self):
        r = extract(f"{MD5.upper()} {SHA1} {SHA256}")
        self.assertEqual([i.note for i in r.by_type("hash")], ["md5", "sha1", "sha256"])   # text order
        self.assertIn(MD5, values(r, "hash"))

    def test_hash_inside_longer_hex_is_not_a_hash(self):
        r = extract(SHA256 + "ab")
        self.assertEqual(values(r, "hash"), [])

    def test_email_domain_not_listed_separately(self):
        r = extract("from attacker@gmail.com")
        self.assertEqual(values(r, "email"), ["attacker@gmail.com"])
        self.assertEqual(values(r, "domain"), [])

    def test_truncation(self):
        old = extractor.MAX_TEXT_CHARS
        extractor.MAX_TEXT_CHARS = 20
        try:
            r = extract("evil.com " * 10)
            self.assertTrue(r.truncated)
            self.assertEqual(r.chars, 20)
        finally:
            extractor.MAX_TEXT_CHARS = old

    def test_empty_and_odd_input(self):
        self.assertEqual(extract("").items, [])
        self.assertEqual(extract("...:::///[[[]]]").items, [])

    def test_plain_list(self):
        r = extract("a.com b.com")
        self.assertEqual(extractor.plain_list(r.by_type("domain")), "a.com\nb.com")


class ExtractTrancoFlagTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        p = Path(self._tmp) / "tranco.csv"
        p.write_text("1,microsoft.com\n2,google.com\n", encoding="utf-8")
        allowlist.load(p, top_n=10)

    def tearDown(self):
        allowlist.load(Path(self._tmp) / "missing.csv")    # back to "gate off"
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_popular_hosts_flagged(self):
        r = extract("ref https://www.microsoft.com/security/blog and evil.com")
        url = r.by_type("url")[0]
        self.assertEqual(url.popular_rank, 1)
        ranks = {i.value: i.popular_rank for i in r.by_type("domain")}
        self.assertEqual(ranks, {"www.microsoft.com": 1, "evil.com": None})


class HtmlToTextTests(unittest.TestCase):
    def test_strips_tags_and_scripts(self):
        html = ("<html><head><title>T</title><style>p{}</style></head><body>"
                "<script>var x = 'script.evil.com';</script>"
                "<p>C2: evil[.]com &amp; 1.2.3.4</p><ul><li>a</li><li>b</li></ul></body></html>")
        text = html_to_text(html)
        self.assertNotIn("script.evil.com", text)
        self.assertNotIn("<p>", text)
        self.assertIn("C2: evil[.]com & 1.2.3.4", text)
        self.assertIn("\na\n", text)


class FetchRefusalTests(unittest.TestCase):
    def test_refusals(self):
        self.assertIsNotNone(fetch._refusal("http://example.com/report"))
        self.assertIsNotNone(fetch._refusal("https://localhost/x"))
        self.assertIsNotNone(fetch._refusal("https://app.localhost/x"))
        self.assertIsNotNone(fetch._refusal("https://127.0.0.1/x"))
        self.assertIsNotNone(fetch._refusal("https://10.0.0.1/x"))
        self.assertIsNotNone(fetch._refusal("https://[::1]/x"))
        self.assertIsNotNone(fetch._refusal("https:///nohost"))
        self.assertIsNone(fetch._refusal("https://example.com/report"))
        # 203.0.113.0/24 is the documentation range and counts as reserved, so
        # a public address is used here.
        self.assertIsNotNone(fetch._refusal("https://203.0.113.5/report"))
        self.assertIsNone(fetch._refusal("https://1.1.1.1/report"))


class FetchTests(unittest.IsolatedAsyncioTestCase):
    def _install(self, handler):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    async def asyncTearDown(self):
        await base.aclose()

    async def test_html_page(self):
        self._install(lambda req: httpx.Response(
            200, headers={"content-type": "text/html; charset=utf-8"},
            content=b"<html><body><p>C2 hxxp://evil[.]com</p></body></html>"))
        text, kind, err = await fetch.fetch_text("https://example.com/post")
        self.assertIsNone(err)
        self.assertEqual(kind, "html")
        self.assertIn("hxxp://evil[.]com", text)

    async def test_plain_text(self):
        self._install(lambda req: httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"evil.com"))
        text, kind, err = await fetch.fetch_text("https://example.com/iocs.txt")
        self.assertEqual((text, kind, err), ("evil.com", "text", None))

    async def test_non_200(self):
        self._install(lambda req: httpx.Response(404))
        text, kind, err = await fetch.fetch_text("https://example.com/missing")
        self.assertIsNone(text)
        self.assertIn("404", err)

    async def test_redirect_to_http_refused(self):
        def handler(req):
            if req.url.scheme == "https":
                return httpx.Response(302, headers={"location": "http://example.com/plain"})
            return httpx.Response(200, content=b"evil.com")
        self._install(handler)
        text, kind, err = await fetch.fetch_text("https://example.com/r")
        self.assertIsNone(text)
        self.assertIn("non-HTTPS", err)

    async def test_oversized_body(self):
        self._install(lambda req: httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"x" * (base.MAX_BODY_BYTES + 1)))
        text, kind, err = await fetch.fetch_text("https://example.com/big")
        self.assertIsNone(text)
        self.assertIn("too large", err)

    async def test_transport_error_does_not_leak_url(self):
        def handler(req):
            raise httpx.ConnectError("boom https://secret.example/token")
        self._install(handler)
        text, kind, err = await fetch.fetch_text("https://example.com/x")
        self.assertIsNone(text)
        self.assertEqual(err, "fetch failed: ConnectError")

    async def test_refused_before_any_request(self):
        def handler(req):
            raise AssertionError("must not be called")
        self._install(handler)
        text, kind, err = await fetch.fetch_text("http://example.com/x")
        self.assertIsNone(text)
        self.assertIn("https", err)


def minimal_pdf(text: str) -> bytes:
    """A one-page PDF with one Helvetica text object and a correct xref
    table, built by hand so the test needs no fixture file."""
    content = f"BT /F1 12 Tf 40 700 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


class PdfTests(unittest.TestCase):
    def test_text_is_extracted(self):
        try:
            import pypdf  # noqa: F401
        except ImportError:
            self.skipTest("pypdf is not installed")
        text, err = pdf.pdf_text(minimal_pdf("C2 hxxps://evil[.]com/x and CVE-2024-3400"))
        self.assertIsNone(err)
        self.assertIn("hxxps://evil[.]com/x", text)
        r = extract(text)
        self.assertEqual(values(r, "url"), ["https://evil.com/x"])
        self.assertEqual(values(r, "cve"), ["CVE-2024-3400"])

    def test_garbage_is_an_error_not_a_crash(self):
        text, err = pdf.pdf_text(b"not a pdf at all")
        self.assertIsNone(text)
        self.assertIsNotNone(err)

    def test_message_mentions_pypdf_when_missing(self):
        try:
            import pypdf  # noqa: F401
        except ImportError:
            text, err = pdf.pdf_text(b"%PDF-1.4")
            self.assertIn("pypdf", err)
        else:
            self.skipTest("pypdf is installed")


class ExtractRouteTests(unittest.TestCase):
    """The /extract route end to end, with FastAPI's test client. The app
    lifespan is not entered (no `with`), so no database or HTTP client is
    created; the route under test needs neither."""

    def setUp(self):
        from fastapi.testclient import TestClient
        from app.main import app
        # The default base URL "http://testserver" fails the local-only Host
        # check (TrustedHostMiddleware), so talk to the app as the browser does.
        self.client = TestClient(app, base_url="http://127.0.0.1")

    def test_get_page(self):
        r = self.client.get("/extract")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Extract IOCs", r.text)

    def test_post_text(self):
        r = self.client.post("/extract", data={"text": "see hxxp://evil[.]com/a and CVE-2024-3400"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("http://evil.com/a", r.text)
        self.assertIn("CVE-2024-3400", r.text)
        self.assertIn("defanged", r.text)

    def test_post_text_file(self):
        r = self.client.post("/extract", files={"file": ("iocs.txt", b"bad.example 203.0.113.1", "text/plain")})
        self.assertEqual(r.status_code, 200)
        self.assertIn("bad.example", r.text)
        self.assertIn("203.0.113.1", r.text)

    def test_post_pdf_file(self):
        try:
            import pypdf  # noqa: F401
        except ImportError:
            self.skipTest("pypdf is not installed")
        data = minimal_pdf("beacon 203.0.113.44 see CVE-2024-3400")
        r = self.client.post("/extract", files={"file": ("report.pdf", data, "application/pdf")})
        self.assertEqual(r.status_code, 200)
        self.assertIn("PDF report.pdf", r.text)
        self.assertIn("203.0.113.44", r.text)
        self.assertIn("CVE-2024-3400", r.text)

    def test_post_nothing(self):
        r = self.client.post("/extract", data={"text": "   "})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Paste some text", r.text)

    def test_cross_site_rejected(self):
        r = self.client.post("/extract", data={"text": "evil.com"}, headers={"sec-fetch-site": "cross-site"})
        self.assertEqual(r.status_code, 403)

    def test_enrich_route_recognises_cve(self):
        r = self.client.post("/enrich", data={"indicator": "cve-2023-4966"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("CVE-2023-4966", r.text)
        self.assertIn("Vulnerability Intelligence", r.text)


if __name__ == "__main__":
    unittest.main()
