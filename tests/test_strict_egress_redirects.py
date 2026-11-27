# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""--strict-egress and server redirects, in a real Chromium. Playwright never
asks a route handler about a redirect hop, so an in-scope URL that 302s to
another origin (directly or through further in-scope hops) must be refused
by the agent's own walk. The only question: what did the OTHER server get."""

from __future__ import annotations

from tests import pytest_style
import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("playwright.sync_api")

from sekuscan.agent.browser import BrowserSession  # noqa: E402
from sekuscan.protocol.models import CaptureRules  # noqa: E402


def _serve(cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@contextlib.contextmanager
def _servers():
    other_hits = []

    class Other(BaseHTTPRequestHandler):
        def do_GET(self):
            other_hits.append(self.path)
            body = b"window.__other=1;"
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    other = _serve(Other)
    oport = other.server_address[1]

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            p = self.path
            off = "http://127.0.0.1:%d" % oport
            if p.startswith("/r/"):                       # direct redirect off-scope
                return self._redir(off + "/direct" + p)
            if p.startswith("/c1/"):                      # in -> in -> off
                return self._redir("/c2" + p[3:])
            if p.startswith("/c2/"):
                return self._redir(off + "/chain" + p)
            if p == "/":
                body = (b"<html><body><img src=/r/img><script src=/r/js></script>"
                        b"<script src=/c1/js></script></body></html>")
            else:
                body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _redir(self, to):
            self.send_response(302)
            self.send_header("Location", to)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    target = _serve(Target)
    yield other_hits, target.server_address[1]
    for s in (other, target):
        s.shutdown()
        s.server_close()


def _run(port, strict, action):
    base = "http://127.0.0.1:%d/" % port
    s = BrowserSession(headless=True, timeout_ms=8000, capture=CaptureRules(),
                       scope_origins=[base], strict_egress=strict)
    s.start()
    try:
        s.page.goto(base, wait_until="load")
        action(s.page)
        s.page.wait_for_timeout(700)
    finally:
        s.stop()


def _nav(page, path):
    try:
        page.goto(page.url.rstrip("/") + path,
                  wait_until="load")
    except Exception:
        pass  # refused navigation is the expected outcome


def _everything(page):
    page.evaluate("fetch('/r/fetch').catch(()=>0)")
    page.evaluate("fetch('/c1/fetch').catch(()=>0)")
    for path in ("/r/nav", "/c1/nav"):
        _nav(page, path)


def test_strict_egress_off_scope_server_gets_nothing():
    with _servers() as (hits, port):
        _run(port, True, _everything)    # the page itself also loads img + 2 scripts
        assert hits == []


def test_strict_egress_still_serves_in_scope_resources():
    got = []
    with _servers() as (hits, port):
        _run(port, True, lambda p: got.append(p.evaluate("fetch('/ok').then(r => r.text())")))
        assert hits == [] and got == ["ok"]


def test_control_without_strict_egress_the_subresource_leak_is_detectable():
    with _servers() as (hits, port):
        _run(port, False, lambda p: None)
        assert any(h.startswith("/direct/r/") for h in hits)


def test_control_without_strict_egress_the_chain_leaks_too():
    with _servers() as (hits, port):
        _run(port, False, _everything)
        assert any(h.startswith("/chain/c2/fetch") for h in hits)


TestStrictEgressRedirects = pytest_style.collect(globals(), "TestStrictEgressRedirects", __doc__)
