"""Offline checks for the C2IntelFeeds integration."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from app.core.config import settings
from app.modules.enrich import base
from app.modules.infrastructure import c2feed


class C2FeedTests(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_reads_fixed_csvs_and_searches_local_snapshot(self):
        urls = []
        content = {
            "IPC2s.csv": b"#ip,ioc\n1.1.1.1,Example checked\n127.0.0.1,Skip local\n",
            "domainC2s-filter-abused.csv": b"#domain,ioc\nexample.org,Example publisher label\n",
            "unverified/IPC2s.csv": b"#ip,ioc\n1.1.1.1,Example unverified\n",
        }
        broken = False

        def handler(request):
            url = str(request.url)
            urls.append(url)
            self.assertNotIn("authorization", request.headers)
            self.assertEqual(request.method, "GET")
            path = url.removeprefix(c2feed.RAW + "/")
            if broken and path == "unverified/IPC2s.csv":
                return httpx.Response(302, headers={"location": "https://unexpected.invalid/"})
            return httpx.Response(200, content=content[path])

        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        try:
            with tempfile.TemporaryDirectory() as directory, patch.object(settings, "data_dir", Path(directory)):
                c2feed.init_schema()
                await c2feed.refresh()
                from fastapi.testclient import TestClient
                from app.main import app
                client = TestClient(app, base_url="http://127.0.0.1")
                page = client.get("/infrastructure", params={"q": "1[.]1[.]1[.]1"})
                self.assertIn("Example checked", page.text)
                self.assertNotIn("Example unverified", page.text)
                page = client.get("/infrastructure", params={"q": "1[.]1[.]1[.]1", "scope": "all"})
                self.assertIn("Example unverified", page.text)
                self.assertEqual(len(urls), 3)
                self.assertEqual(c2feed.page("", "all", 1)["total"], 3)
                broken = True
                await c2feed.refresh()
                saved = c2feed.page("", "all", 1)
                self.assertEqual(saved["total"], 3)
                self.assertIn("302", saved["status"]["error"])
                self.assertEqual(len(urls), 6)
        finally:
            await base.aclose()
