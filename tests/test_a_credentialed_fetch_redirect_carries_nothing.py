# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""A route handler never sees a redirect hop: Chromium follows `Location`
itself and replays the request's headers onto the next host. GET document
navigations are pre-flighted; a page's own `fetch()` and a non-GET form
navigation were let through with the operator's headers attached, so an
in-scope redirect handed them to whoever it pointed at.

Real browser, two local servers, and the only question that matters: what
did the other server receive.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from playwright.sync_api import sync_playwright  # noqa: F401
    HAVE_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    HAVE_PLAYWRIGHT = False

from sekuscan.protocol.models import CaptureRules


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class TestACredentialedRedirectCarriesNothing(unittest.TestCase):

    def setUp(self):
        test = self
        self.elsewhere_got = []
        self.final_auth = None

        class Elsewhere(BaseHTTPRequestHandler):
            def _any(self):
                test.elsewhere_got.append({k.lower(): v for k, v in self.headers.items()})
                body = b"elsewhere"
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = _any

            def log_message(self, *args):
                return

        class Target(BaseHTTPRequestHandler):
            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                if self.path.startswith("/inside"):
                    self.send_response(302)
                    self.send_header("Location", "/final")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/final"):
                    test.final_auth = self.headers.get("Authorization")
                    body = b"final-body"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path.startswith("/keep"):
                    self.send_response(307)
                    self.send_header("Location", "http://127.0.0.1:%d/landed" % test.elsewhere_port)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/hop"):
                    self.send_response(307)
                    self.send_header("Location", "http://127.0.0.1:%d/landed" % test.elsewhere_port)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = (b"<html><body><form id=f method=post action=/hop>"
                        b"<input name=a value=1></form>"
                        b"<form id=g method=post action=/inside><input name=a value=1></form>"
                        b"<form id=k method=post action=/keep><input name=a value=1></form>"
                        b"</body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = _any

            def log_message(self, *args):
                return

        self.elsewhere, self.elsewhere_port = _serve(Elsewhere)
        self.target, self.target_port = _serve(Target)
        self.addCleanup(self.elsewhere.server_close)
        self.addCleanup(self.elsewhere.shutdown)
        self.addCleanup(self.target.server_close)
        self.addCleanup(self.target.shutdown)

    def _session(self):
        from sekuscan.agent.browser import BrowserSession

        url = "http://127.0.0.1:%d/" % self.target_port
        session = BrowserSession(headless=True, timeout_ms=8000, capture=CaptureRules(),
                                 extra_headers={"Authorization": "Bearer supersecret",
                                                "X-Tenant": "acme"},
                                 scope_origins=[url])
        session.start()
        self.addCleanup(session.stop)
        session.page.goto(url, wait_until="load")
        return session

    def _leaked(self):
        return [h for h in self.elsewhere_got if "authorization" in h or "x-tenant" in h]

    def test_a_page_fetch_redirect(self):
        session = self._session()
        session.page.evaluate("fetch('/hop', {method: 'POST', body: 'x=1'}).catch(() => 0)")
        session.page.wait_for_timeout(800)
        self.assertEqual(self._leaked(), [])

    def test_an_in_scope_redirect_still_works_and_keeps_the_session(self):
        session = self._session()
        text = session.page.evaluate("fetch('/inside').then(r => r.text())")
        self.assertEqual(text, "final-body")
        self.assertEqual(self.final_auth, "Bearer supersecret")

    def test_an_in_scope_post_redirect_lands_with_the_session(self):
        session = self._session()
        with session.page.expect_navigation(url="**/final", timeout=6000):
            session.page.evaluate("document.getElementById('g').submit()")
        self.assertEqual(session.page.content().count("final-body"), 1)
        self.assertEqual(self.final_auth, "Bearer supersecret")

    def test_a_307_form_post_never_reaches_the_other_host(self):
        session = self._session()
        try:
            session.page.evaluate("document.getElementById('k').submit()")
        except Exception:
            pass
        session.page.wait_for_timeout(800)
        self.assertEqual(self.elsewhere_got, [])

    def test_a_post_form_navigation_redirect(self):
        session = self._session()
        try:
            with session.page.expect_navigation(timeout=4000):
                session.page.evaluate("document.getElementById('f').submit()")
        except Exception:
            pass
        session.page.wait_for_timeout(500)
        self.assertEqual(self._leaked(), [])


if __name__ == "__main__":
    unittest.main()
