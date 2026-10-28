"""
Tests for refang and indicator type detection. Pure logic, no network.

Run from the project root:
    .venv/Scripts/python.exe -m unittest discover -s tests -t . -v
"""

import unittest

from app.core.indicators import detect_type, hash_kind, refang


class RefangTests(unittest.TestCase):
    def test_bracketed_dot(self):
        self.assertEqual(refang("evil[.]com"), "evil.com")
        self.assertEqual(refang("evil(.)com"), "evil.com")
        self.assertEqual(refang("evil{.}com"), "evil.com")

    def test_hxxp_scheme(self):
        self.assertEqual(refang("hxxp://bad[.]com"), "http://bad.com")
        self.assertEqual(refang("hxxps://bad[.]com/x"), "https://bad.com/x")
        self.assertEqual(refang("hXXp://bad[.]com"), "http://bad.com")

    def test_defanged_at_and_colon(self):
        self.assertEqual(refang("user[@]mail[.]com"), "user@mail.com")
        self.assertEqual(refang("10.0.0.1[:]8080"), "10.0.0.1:8080")

    def test_strips_whitespace(self):
        self.assertEqual(refang("  8.8.8.8  "), "8.8.8.8")


class DetectTypeTests(unittest.TestCase):
    def test_hashes(self):
        self.assertEqual(detect_type("d41d8cd98f00b204e9800998ecf8427e"), "hash")           # md5
        self.assertEqual(detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "hash")   # sha1
        self.assertEqual(
            detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "hash",
        )

    def test_ipv4_and_ipv6(self):
        self.assertEqual(detect_type("8.8.8.8"), "ip")
        self.assertEqual(detect_type("2001:4860:4860::8888"), "ip")

    def test_url(self):
        self.assertEqual(detect_type("http://example.com"), "url")
        self.assertEqual(detect_type("https://example.com/path?q=1"), "url")

    def test_domain(self):
        self.assertEqual(detect_type("example.com"), "domain")
        self.assertEqual(detect_type("sub.example.co.uk"), "domain")

    def test_unknown(self):
        self.assertEqual(detect_type("not an ioc"), "unknown")
        self.assertEqual(detect_type("just-a-word"), "unknown")

    def test_near_miss_hashes_are_not_hashes(self):
        # 31 hex chars (one short of md5) must not be a hash
        self.assertNotEqual(detect_type("d41d8cd98f00b204e9800998ecf8427"), "hash")


class HashKindTests(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(hash_kind("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        self.assertEqual(hash_kind("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "sha1")
        self.assertIsNone(hash_kind("xyz"))


if __name__ == "__main__":
    unittest.main()
