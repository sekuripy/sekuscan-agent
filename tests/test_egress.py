# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Credentials must not leave the target's origin, and neither must the browser.

These are the only tests in the suite that drive a real browser, because they
are the only claims that cannot be checked any other way: whether a header
reaches a third party is a property of Playwright's context, not of our code
reading nicely.

Two local servers stand in for "the target" and "somebody else". The target
serves a page that pulls an image and a script from the other one, exactly as
a real application pulls analytics and fonts. The question each test asks is
what the third party received.

Skipped when Playwright or its browser binary is unavailable, because a
missing browser must not read as a passing security test.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from playwright.sync_api import sync_playwright
    HAVE_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    HAVE_PLAYWRIGHT = False

from sekuscan.protocol.models import CaptureRules


class _Recorder(BaseHTTPRequestHandler):
    """Records every request it receives, headers included."""

    received: list = []

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
        type(self).received.append({
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        })
        body = self._body()
        self.send_response(200)
        self.send_header("Content-Type", self._mime())
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _mime(self) -> str:
        if self.path.endswith(".js"):
            return "application/javascript"
        if self.path.endswith(".png"):
            return "image/png"
        return "text/html"

    def _body(self) -> bytes:
        return b"// third party"

    def log_message(self, *args):  # silence the default stderr spam
        return


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class TestCredentialEgress(unittest.TestCase):
    """The leak: `extra_http_headers` is set on the whole browser context, so
    Playwright attaches it to every request the page makes - including the
    ones to somebody else's CDN."""

    def setUp(self):
        class ThirdParty(_Recorder):
            received = []

        class Target(_Recorder):
            received = []

            def _body(inner):  # noqa: N805
                return (
                    "<html><body>target"
                    "<img src='http://127.0.0.1:%d/pixel.png'>"
                    "<script src='http://127.0.0.1:%d/tracker.js'></script>"
                    "</body></html>" % (self.third_port, self.third_port)
                ).encode()

        self.third_cls = ThirdParty
        self.third, self.third_port = _serve(ThirdParty)
        self.target_cls = Target
        self.target, self.target_port = _serve(Target)

    def tearDown(self):
        for server in (self.third, self.target):
            server.shutdown()
            server.server_close()

    def _run(self, **kwargs):
        from sekuscan.agent.browser import BrowserSession

        target_url = "http://127.0.0.1:%d/" % self.target_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret",
                           "X-Tenant": "acme"},
            scope_origins=[target_url], **kwargs)
        session.start()
        try:
            session.page.goto(target_url, wait_until="load")
            session.page.wait_for_timeout(400)
        finally:
            session.stop()
        return target_url

    def test_the_target_still_receives_the_credentials(self):
        """The fix must not break handing over a session, which is the whole
        reason those headers exist."""
        self._run()
        got = [r for r in self.target_cls.received]
        self.assertTrue(got, "the target was never reached")
        self.assertEqual(got[0]["headers"].get("authorization"),
                         "Bearer supersecret")

    def test_a_third_party_never_receives_the_bearer_token(self):
        self._run()
        leaked = [r for r in self.third_cls.received
                  if "authorization" in r["headers"]]
        self.assertEqual(
            leaked, [],
            "Authorization reached a third-party origin: %s"
            % [r["path"] for r in leaked])

    def test_a_third_party_never_receives_custom_tenant_headers(self):
        """`X-Tenant: acme` names the customer. Sending it to an analytics
        host discloses who is being tested, to somebody who was not asked."""
        self._run()
        leaked = [r for r in self.third_cls.received
                  if "x-tenant" in r["headers"]]
        self.assertEqual(leaked, [],
                         "X-Tenant reached a third-party origin")

    def test_an_out_of_scope_navigation_is_blocked(self):
        """A redirect, a `target=_blank` or one line of JavaScript can walk
        the browser out of the engagement without any directive being wrong.
        Subresources render the page; a navigation leaves it."""
        from sekuscan.agent.browser import BrowserSession

        target_url = "http://127.0.0.1:%d/" % self.target_port
        away = "http://127.0.0.1:%d/elsewhere" % self.third_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret"},
            scope_origins=[target_url])
        session.start()
        try:
            session.page.goto(target_url, wait_until="load")
            before = len(self.third_cls.received)
            try:
                session.page.goto(away, wait_until="load")
            except Exception:
                pass  # an aborted navigation raises, which is the point
            session.page.wait_for_timeout(200)
            navigated = [r for r in self.third_cls.received[before:]
                         if r["path"] == "/elsewhere"]
            self.assertEqual(navigated, [],
                             "the browser navigated out of scope")
        finally:
            session.stop()

    def test_third_party_subresources_still_load(self):
        """Stripping credentials must not blind the scanner: a page whose
        analytics and fonts fail to load is not the page under test, and
        a client-side check has nothing left to inventory."""
        self._run()
        self.assertTrue(self.third_cls.received,
                        "third-party requests were blocked entirely")

    def test_secondary_form_login_creates_a_distinct_read_only_session(self):
        """The second identity is authenticated locally, never by the engine."""
        class TwoAccountFixture(BaseHTTPRequestHandler):
            def do_GET(inner):  # noqa: N802
                if inner.path == "/login":
                    body = (b"<form action='/login' method='post'>"
                            b"<input name='username' type='text'>"
                            b"<input name='password' type='password'>"
                            b"<button type='submit'>Sign in</button></form>")
                    inner.send_response(200)
                    inner.send_header("Content-Type", "text/html")
                    inner.send_header("Content-Length", str(len(body)))
                    inner.end_headers()
                    inner.wfile.write(body)
                    return
                if inner.path.startswith("/account"):
                    cookie = inner.headers.get("Cookie", "")
                    if "session=bob" not in cookie:
                        inner.send_response(303)
                        inner.send_header("Location", "/login")
                        inner.end_headers()
                        return
                    body = b"Alice Example\nsigned in as bob"
                    inner.send_response(200)
                    inner.send_header("Content-Type", "text/plain")
                    inner.send_header("Content-Length", str(len(body)))
                    inner.end_headers()
                    inner.wfile.write(body)
                    return
                inner.send_response(404)
                inner.end_headers()

            def do_POST(inner):  # noqa: N802
                length = int(inner.headers.get("Content-Length") or 0)
                values = inner.rfile.read(length).decode("utf-8")
                if "username=bob" not in values or "password=bob-pass" not in values:
                    inner.send_response(401)
                    inner.end_headers()
                    return
                inner.send_response(303)
                inner.send_header("Location", "/account?user=alice")
                inner.send_header("Set-Cookie", "session=bob; Path=/")
                inner.end_headers()

            def log_message(inner, *args):
                return

        server, port = _serve(TwoAccountFixture)
        from sekuscan.agent.browser import BrowserSession
        target = "http://127.0.0.1:%d" % port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target], secondary_username="bob",
            secondary_password="bob-pass",
            secondary_login_url=target + "/login")
        try:
            session.start()
            self.assertIsNone(session.secondary_login_error)
            secondary = session.secondary_request_context()
            self.assertIsNotNone(secondary)
            response = secondary.get(target + "/account?user=alice")
            self.assertEqual(response.status, 200)
            self.assertIn("Alice Example", response.text())
            self.assertIn("signed in as bob", response.text())
        finally:
            session.stop()
            server.shutdown()
            server.server_close()

    def test_secondary_api_login_keeps_module_cookies_across_followups(self):
        """Module-scoped APIs may mint one secondary cookie per endpoint."""
        class SecondaryApiFixture(BaseHTTPRequestHandler):
            def do_POST(inner):  # noqa: N802
                length = int(inner.headers.get("Content-Length") or 0)
                values = inner.rfile.read(length).decode("utf-8")
                if "username=bob" not in values or "password=bob-pass" not in values:
                    inner.send_response(401)
                    inner.end_headers()
                    return
                level = inner.path.rsplit("/", 1)[-1]
                inner.send_response(200)
                inner.send_header("Set-Cookie", "session%s=bob; Path=/" % level)
                inner.end_headers()

            def do_GET(inner):  # noqa: N802
                inner.send_response(200)
                inner.end_headers()

            def log_message(inner, *args):
                return

        server, port = _serve(SecondaryApiFixture)
        from sekuscan.agent.browser import BrowserSession
        target = "http://127.0.0.1:%d" % port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target], secondary_username="bob",
            secondary_password="bob-pass",
            secondary_login_url=target + "/level1",
            secondary_login_fields=(
                '{"username":"{username}","password":"{password}"}'),
            secondary_additional_login_urls=[target + "/level2",
                                             target + "/level3"])
        try:
            session.start()
            self.assertIsNone(session.secondary_login_error)
            self.assertEqual(session.secondary_cookies,
                             {"sessionlevel1": "bob",
                              "sessionlevel2": "bob",
                              "sessionlevel3": "bob"})
        finally:
            session.stop()
            server.shutdown()
            server.server_close()

    def test_deny_substrings_block_every_resource_type_not_just_navigation(self):
        """Regression: a External review found the browser route handler
        never received `deny_substrings` at all, so a deny rule (e.g. for a
        logout path) was enforced everywhere else in the stack except here.
        Fixed by threading it through and, since the CLI's promise is "never
        request URLs containing this substring" rather than merely "don't
        navigate there", aborting a deny match in every resource type - not
        only top-level navigation."""
        from sekuscan.agent.browser import BrowserSession

        target_url = "http://127.0.0.1:%d/" % self.target_port
        third_party_beacon = "http://127.0.0.1:%d/logout-beacon" % self.third_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target_url, "http://127.0.0.1:%d/" % self.third_port],
            deny_substrings=["logout"])
        session.start()
        try:
            session.page.goto(target_url, wait_until="load")
            before = len(self.third_cls.received)
            session.page.evaluate(
                "u => fetch(u).catch(() => {})", third_party_beacon)
            session.page.wait_for_timeout(300)
            hit = [r for r in self.third_cls.received[before:]
                  if r["path"] == "/logout-beacon"]
            self.assertEqual(hit, [], "a deny-listed subresource request went through")
        finally:
            session.stop()

    def test_navigation_containment_applies_even_without_credentials(self):
        """Regression: the route guard installed only when BOTH credentials
        and scope were present, so an anonymous or cookie-only scan got no
        containment at all - an in-scope page that redirected off-site was
        never noticed or blocked."""
        from sekuscan.agent.browser import BrowserSession

        target_url = "http://127.0.0.1:%d/" % self.target_port
        away = "http://127.0.0.1:%d/elsewhere" % self.third_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target_url])  # no extra_headers at all
        session.start()
        try:
            session.page.goto(target_url, wait_until="load")
            before = len(self.third_cls.received)
            try:
                session.page.goto(away, wait_until="load")
            except Exception:
                pass
            session.page.wait_for_timeout(200)
            navigated = [r for r in self.third_cls.received[before:]
                        if r["path"] == "/elsewhere"]
            self.assertEqual(navigated, [],
                             "an anonymous session navigated out of scope")
        finally:
            session.stop()

    def test_drain_egress_returns_and_clears_recorded_out_of_scope_requests(self):
        """Regression: `self.egress` was collected and never read anywhere -
        the supply-chain visibility the docstring promised was silently
        thrown away. `drain_egress` is the fix, mirroring `drain_console`."""
        from sekuscan.agent.browser import BrowserSession

        target_url = "http://127.0.0.1:%d/" % self.target_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret"},
            scope_origins=[target_url])
        session.start()
        try:
            session.page.goto(target_url, wait_until="load")
            session.page.wait_for_timeout(400)
        finally:
            session.stop()
        egress = session.drain_egress()
        self.assertTrue(egress, "no out-of-scope request was recorded")
        self.assertEqual(session.drain_egress(), [],
                         "drain did not clear the buffer")

    def test_credential_origin_is_narrower_than_scan_scope(self):
        """Regression: a External review found EVERY in-scope origin got
        the operator's headers - a scan scope covering two origins (a
        `www.` app and its `api.` backend) sent the bearer belonging to one
        to both. `credential_origins` is a separate, narrower policy;
        `agent/cli.py` defaults it to exactly the target's own origin."""
        from sekuscan.agent.browser import BrowserSession

        # the third-party server stands in for a SECOND, also-in-scope
        # origin that does not own this credential
        target_url = "http://127.0.0.1:%d/" % self.target_port
        other_in_scope_origin = "http://127.0.0.1:%d/" % self.third_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret"},
            scope_origins=[target_url, other_in_scope_origin],
            credential_origins=[target_url])
        session.start()
        try:
            session.page.goto(target_url, wait_until="load")
            session.page.wait_for_timeout(400)
        finally:
            session.stop()
        # the third party is IN SCOPE (subresources still loaded), but must
        # not have received the credential that belongs only to the target
        leaked = [r for r in self.third_cls.received
                 if "authorization" in r["headers"]]
        self.assertEqual(leaked, [],
                         "the bearer reached an in-scope origin it does not belong to")
        self.assertTrue(self.third_cls.received,
                        "the second in-scope origin was not reached at all")

    def test_a_failed_secondary_login_that_stays_on_the_login_form_is_refused(self):
        """Regression: a External review found "any cookie/localStorage
        entry exists" too weak a success signal - a FAILED login commonly
        still sets an analytics or CSRF cookie, which made that failure
        read as success. This fixture's login page sets exactly such a
        cookie on every visit, including a failed attempt, and re-renders
        the same form with the password field still present rather than
        redirecting - the login must not be accepted."""
        class AlwaysReloadsTheForm(BaseHTTPRequestHandler):
            def do_GET(inner):  # noqa: N802
                if inner.path == "/login":
                    body = (b"<form action='/login' method='post'>"
                            b"<input name='username' type='text'>"
                            b"<input name='password' type='password'>"
                            b"<button type='submit'>Sign in</button></form>")
                    inner.send_response(200)
                    inner.send_header("Content-Type", "text/html")
                    inner.send_header("Set-Cookie", "analytics=1; Path=/")
                    inner.send_header("Content-Length", str(len(body)))
                    inner.end_headers()
                    inner.wfile.write(body)
                    return
                inner.send_response(404)
                inner.end_headers()

            def do_POST(inner):  # noqa: N802
                # every login attempt fails and re-renders the same form -
                # exactly the case a redirect-based heuristic would miss
                inner.send_response(303)
                inner.send_header("Location", "/login")
                inner.send_header("Set-Cookie", "analytics=2; Path=/")
                inner.end_headers()

            def log_message(inner, *args):
                return

        server, port = _serve(AlwaysReloadsTheForm)
        from sekuscan.agent.browser import BrowserSession
        target = "http://127.0.0.1:%d" % port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target], secondary_username="bob",
            secondary_password="wrong-password",
            secondary_login_url=target + "/login")
        try:
            session.start()
            self.assertIsNotNone(session.secondary_login_error)
            self.assertIn("did not appear to succeed", session.secondary_login_error)
            self.assertIsNone(session.secondary_request_context())
        finally:
            session.stop()
            server.shutdown()
            server.server_close()

    def test_secondary_headers_survive_username_password_login(self):
        """Regression: the request context rebuilt after a successful
        username/password login dropped `secondary_headers` entirely - an
        operator supplying both a header and form credentials silently
        lost the header the moment login succeeded."""
        class HeaderCheckingLogin(BaseHTTPRequestHandler):
            received: list = []

            def do_GET(inner):  # noqa: N802
                if inner.path == "/login":
                    body = (b"<form action='/login' method='post'>"
                            b"<input name='username' type='text'>"
                            b"<input name='password' type='password'>"
                            b"<button type='submit'>Sign in</button></form>")
                    inner.send_response(200)
                    inner.send_header("Content-Type", "text/html")
                    inner.send_header("Content-Length", str(len(body)))
                    inner.end_headers()
                    inner.wfile.write(body)
                    return
                type(inner).received.append(
                    {"path": inner.path,
                     "headers": {k.lower(): v for k, v in inner.headers.items()}})
                inner.send_response(200)
                body = b"ok"
                inner.send_header("Content-Length", str(len(body)))
                inner.end_headers()
                inner.wfile.write(body)

            def do_POST(inner):  # noqa: N802
                type(inner).received.append(
                    {"path": "POST " + inner.path,
                     "headers": {k.lower(): v for k, v in inner.headers.items()}})
                inner.send_response(303)
                inner.send_header("Location", "/account")
                inner.send_header("Set-Cookie", "session=bob; Path=/")
                inner.end_headers()

            def log_message(inner, *args):
                return

        server, port = _serve(HeaderCheckingLogin)
        from sekuscan.agent.browser import BrowserSession
        target = "http://127.0.0.1:%d" % port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target], secondary_username="bob",
            secondary_password="bob-pass",
            secondary_login_url=target + "/login",
            secondary_headers={"X-Secondary": "carried-through-login"})
        try:
            session.start()
            self.assertIsNone(session.secondary_login_error)
            response = session.secondary_request_context().get(target + "/account")
            self.assertEqual(response.status, 200)
        finally:
            session.stop()
            server.shutdown()
            server.server_close()
        # The rebuilt context does NOT bake the header in: `_probe_http` adds
        # it per request so a redirect hop cannot replay it off-scope. That
        # path is pinned by test_secondary_headers_do_not_follow_a_hop.
        gets = [r for r in HeaderCheckingLogin.received if not r["path"].startswith("POST")]
        self.assertNotIn("x-secondary", gets[-1]["headers"])

    def test_secondary_session_stays_in_the_agent_request_context(self):
        """Horizontal comparison credentials are available only to its GET."""
        from sekuscan.agent.browser import BrowserSession

        target_url = "http://127.0.0.1:%d/" % self.target_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            scope_origins=[target_url],
            secondary_headers={"X-Secondary": "user-b"},
            secondary_cookies={"sid": "user-b"},
            secondary_cookie_url=target_url)
        session.start()
        try:
            response = session.secondary_request_context().get(target_url)
            self.assertEqual(response.status, 200)
        finally:
            session.stop()
        got = [r for r in self.target_cls.received]
        self.assertTrue(got, "the secondary context never reached the target")
        # The context holds the second identity's cookies; its headers are
        # added per request by the callers, never by the context (a context
        # header is replayed on every redirect hop).
        self.assertIsNone(got[0]["headers"].get("x-secondary"))
        self.assertIn("sid=user-b", got[0]["headers"].get("cookie", ""))


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class TestNavigationRedirectContainment(unittest.TestCase):
    """The composition nobody tested, and it leaked.

    A direct navigation to an out-of-scope URL was tested and blocked
    (`test_an_out_of_scope_navigation_is_blocked`). `probe_http` following a
    redirect off-scope was tested and blocked
    (`TestProbeHttpRedirectContainment`). An in-scope NAVIGATION that gets
    REDIRECTED off-scope was neither, and Playwright does not invoke a route
    handler for a server redirect hop - it follows `Location` inside the
    network stack. So the guard saw the in-scope URL, allowed it, and never
    got another say.

    Found on a real web application: its own open redirect
    (`/redirect?to=https://github.com/juice-shop/juice-shop`) took the crawl
    to GitHub, which it then explored for three visits, loading 540KB pages
    and third-party assets - and an XSS probe appended a marker to a
    github.com URL, i.e. the scan sent a payload to a third party. Nothing
    was recorded, not even in `self.egress`.
    """

    def setUp(self):
        class ThirdParty(BaseHTTPRequestHandler):
            received: list = []

            def do_GET(self):
                type(self).received.append({"path": self.path})
                body = b"<html><title>THIRD PARTY</title><body>x</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        ThirdParty.received = []
        self.third_cls = ThirdParty
        self.third, self.third_port = _serve(ThirdParty)
        third_port = self.third_port

        class Target(BaseHTTPRequestHandler):
            received: list = []

            def do_GET(self):
                type(self).received.append({"path": self.path})
                if self.path.startswith("/leave"):
                    self.send_response(302)
                    self.send_header(
                        "Location", "http://127.0.0.1:%d/landed" % third_port)
                    self.end_headers()
                    return
                if self.path.startswith("/hop1"):
                    self.send_response(302)
                    self.send_header("Location", "/hop2")
                    self.end_headers()
                    return
                if self.path.startswith("/hop2"):
                    self.send_response(302)
                    self.send_header(
                        "Location", "http://127.0.0.1:%d/landed" % third_port)
                    self.end_headers()
                    return
                if self.path.startswith("/stay"):
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.end_headers()
                    return
                body = (b"<html><head><title>DASHBOARD</title></head>"
                        b"<body>in scope</body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        Target.received = []
        self.target_cls = Target
        self.target, self.target_port = _serve(Target)

    def tearDown(self):
        for server in (self.third, self.target):
            server.shutdown()
            server.server_close()

    def _session(self):
        from sekuscan.agent.browser import BrowserSession

        origins = ["http://127.0.0.1:%d/" % self.target_port]
        session = BrowserSession(headless=True, scope_origins=origins)
        session.start()
        self.addCleanup(session.stop)
        session.page.goto("http://127.0.0.1:%d/" % self.target_port,
                          wait_until="domcontentloaded")
        return session

    def _goto(self, session, path):
        try:
            session.page.goto("http://127.0.0.1:%d%s"
                              % (self.target_port, path),
                              wait_until="domcontentloaded")
        except Exception:
            pass  # an aborted navigation raises; that IS the containment

    def test_the_third_party_never_receives_the_request(self):
        """The whole point. Not "the page ended up somewhere acceptable" -
        the request must never leave."""
        session = self._session()
        self._goto(session, "/leave")
        self.assertEqual(
            self.third_cls.received, [],
            "an off-scope redirect target was requested: %r"
            % self.third_cls.received)
        self.assertEqual(session.safety_incidents, 0,
                         "a pre-network refusal consumed the safety budget")

    def test_the_browser_does_not_end_up_off_scope(self):
        session = self._session()
        self._goto(session, "/leave")
        self.assertIn("127.0.0.1:%d" % self.target_port, session.page.url)
        self.assertNotIn("THIRD PARTY", session.page.title() or "")

    def test_the_blocked_hop_is_recorded_with_where_it_came_from(self):
        """A silent block is the sibling failure: an operator has to be able
        to see that the application tried to send the scan away."""
        session = self._session()
        self._goto(session, "/leave")
        blocked = [row for row in session.egress if row.get("blocked")]
        self.assertTrue(blocked, "the block was not recorded at all")
        self.assertTrue(
            any("127.0.0.1:%d" % self.third_port in (row.get("url") or "")
                and "/leave" in (row.get("via_redirect_from") or "")
                for row in blocked),
            "the record does not name the redirect it came from: %r" % blocked)

    def test_an_in_scope_redirect_is_still_followed(self):
        """The half that must not break. A login that 302s to a dashboard is
        the most ordinary thing an application does, and the final url has to
        be the DASHBOARD - fulfilling the target's body at the original url
        would leave `page.url` wrong and break every relative link on it."""
        session = self._session()
        self._goto(session, "/stay")
        self.assertTrue(session.page.url.endswith("/dashboard"),
                        "landed on %s" % session.page.url)
        self.assertEqual(session.page.title(), "DASHBOARD")

    def test_a_chain_is_checked_at_every_hop(self):
        """In-scope, in-scope, then out - nothing smuggles a third party in
        behind two legitimate hops.

        This is why the guard walks the WHOLE chain itself instead of
        checking one `Location`. Handing an in-scope 3xx back to the browser
        and expecting to be asked again does not work: measured, Chromium
        follows a redirect it receives without re-entering the route
        handler, so a two-hop chain reached the third party even with the
        first hop checked.
        """
        session = self._session()
        self._goto(session, "/hop1")
        self.assertEqual(
            self.third_cls.received, [],
            "a two-hop chain reached the third party: %r"
            % self.third_cls.received)
        self.assertIn("127.0.0.1:%d" % self.target_port, session.page.url)
        self.assertEqual(session.safety_incidents, 0,
                         "a pre-network refusal consumed the safety budget")

    def test_the_operator_credentials_never_reach_the_third_party(self):
        """The reason this is a security bug and not a tidiness one.

        Chromium replays the original request's headers across a redirect,
        and the operator's headers were attached to the in-scope request by
        the guard - so the third party received
        `Authorization: Bearer supersecret` and `X-Tenant: acme`. Measured,
        before the fix, with this exact fixture. "Credentials for the
        target, and only for the target" is `_install_egress_guard`'s first
        line; a redirect walked straight through it.
        """
        from sekuscan.agent.browser import BrowserSession

        seen = []

        class Sniffer(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                return

        sniffer, sniff_port = _serve(Sniffer)
        self.addCleanup(sniffer.server_close)
        self.addCleanup(sniffer.shutdown)

        class Redirector(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/away"):
                    self.send_response(302)
                    self.send_header(
                        "Location", "http://127.0.0.1:%d/steal" % sniff_port)
                    self.end_headers()
                    return
                body = b"<html><title>HOME</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        home, home_port = _serve(Redirector)
        self.addCleanup(home.server_close)
        self.addCleanup(home.shutdown)

        origins = ["http://127.0.0.1:%d/" % home_port]
        session = BrowserSession(
            headless=True, scope_origins=origins,
            extra_headers={"Authorization": "Bearer supersecret",
                           "X-Tenant": "acme"})
        session.start()
        self.addCleanup(session.stop)
        session.page.goto(origins[0], wait_until="domcontentloaded")
        try:
            session.page.goto("http://127.0.0.1:%d/away" % home_port,
                              wait_until="domcontentloaded")
        except Exception:
            pass

        self.assertEqual(seen, [],
                         "the third party was reached at all: %r" % seen)
        for headers in seen:  # belt and braces if the above ever loosens
            self.assertIsNone(headers.get("authorization"))
            self.assertIsNone(headers.get("x-tenant"))

    def test_a_post_submit_that_lands_off_scope_is_contained_afterwards(self):
        """The second layer, and the one case only it can catch.

        A POST navigation is deliberately NOT pre-flighted: duplicating a
        form submit re-submits whatever the form does, which is a worse harm
        than the one being prevented. So the request does leave - what must
        not happen is the crawl CONTINUING there. On a web application that
        continuation was the real damage: GitHub recorded as a state,
        visited three times, an XSS marker appended to a github.com URL.

        This asserts the honest division of labour: the hop is not
        prevented, the landing is contained - the action fails, the page is
        put back in scope, and `capture_state` is cleared so an off-scope
        page can never become a state for the engine to explore from.
        """
        import os
        import tempfile

        from sekuscan.agent.browser import BrowserSession
        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import Directive, ScopeRules

        landed = []

        class Landing(BaseHTTPRequestHandler):
            def do_GET(self):
                landed.append(self.path)
                body = b"<html><title>THIRD PARTY</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        away, away_port = _serve(Landing)
        self.addCleanup(away.server_close)
        self.addCleanup(away.shutdown)

        class Form(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(303)
                self.send_header("Location",
                                 "http://127.0.0.1:%d/landed" % away_port)
                self.end_headers()

            def do_GET(self):
                body = (b"<html><body><form id='f' method='POST' "
                        b"action='/submit'><input name='q'>"
                        b"<button type='submit'>go</button></form></body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        host, host_port = _serve(Form)
        self.addCleanup(host.server_close)
        self.addCleanup(host.shutdown)

        origins = ["http://127.0.0.1:%d/" % host_port]
        session = BrowserSession(headless=True, scope_origins=origins)
        session.start()
        self.addCleanup(session.stop)
        session.page.goto(origins[0], wait_until="domcontentloaded")

        guard = ScopeGuard(ScopeRules(origins=origins))
        directive = Directive(id="d1", kind="fill_submit", url=origins[0],
                              selector="#f", values={"q": "x"},
                              submit_selector="button[type=submit]")
        outcome = execute(session, directive, guard, CaptureRules(),
                          tempfile.mkdtemp(), 1)

        self.assertTrue(landed, "fixture is wrong: the POST never redirected")
        self.assertFalse(outcome.action_result.ok,
                         "an off-scope landing must not read as a success")
        self.assertIn("out-of-scope landing",
                      outcome.action_result.error or "")
        self.assertFalse(outcome.capture_state,
                         "an off-scope page must never become a state")
        self.assertIn("127.0.0.1:%d" % host_port, session.page.url)
        self.assertTrue(
            any(row.get("blocked") and row.get("landed_after") == "fill_submit"
                for row in session.egress),
            "the landing was not recorded: %r" % session.egress)
        del os

    def test_a_direct_off_scope_navigation_is_still_blocked(self):
        """The case that already worked, kept honest - the restructure moved
        that branch."""
        session = self._session()
        try:
            session.page.goto("http://127.0.0.1:%d/landed" % self.third_port,
                              wait_until="domcontentloaded")
        except Exception:
            pass
        self.assertEqual(self.third_cls.received, [])


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class TestProbeHttpRedirectContainment(unittest.TestCase):
    """Regression: a External review found `_probe_http` let Playwright
    follow redirects automatically (its default is up to 20 hops), which
    forwards the probe's headers - including an Authorization override or a
    cookie override - to wherever `Location` points, before the agent ever
    gets a chance to scope-check that url. `execute()` only checked the
    directive's OWN url. Fixed by fetching one hop at a time and running
    every redirect target through the same `ScopeGuard` the initial url
    used.
    """

    def setUp(self):
        class ThirdParty(BaseHTTPRequestHandler):
            received: list = []

            def do_GET(self):
                type(self).received.append(
                    {"path": self.path,
                     "headers": {k.lower(): v for k, v in self.headers.items()}})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                return

        self.third_cls = ThirdParty
        self.third, self.third_port = _serve(ThirdParty)

        third_port = self.third_port

        class Target(BaseHTTPRequestHandler):
            received: list = []

            def do_GET(self):
                type(self).received.append(
                    {"path": self.path,
                     "headers": {k.lower(): v for k, v in self.headers.items()}})
                if self.path == "/redirect-away":
                    self.send_response(302)
                    self.send_header(
                        "Location", "http://127.0.0.1:%d/collect" % third_port)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                return

        self.target_cls = Target
        self.target, self.target_port = _serve(Target)

    def tearDown(self):
        for server in (self.third, self.target):
            server.shutdown()
            server.server_close()

    def test_a_redirect_to_an_out_of_scope_host_is_not_followed(self):
        from sekuscan.agent.browser import BrowserSession
        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import Directive, ScopeRules

        target_url = "http://127.0.0.1:%d/" % self.target_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret"},
            scope_origins=[target_url])
        guard = ScopeGuard(ScopeRules(origins=[target_url]))
        session.start()
        try:
            outcome = execute(
                session,
                Directive(id="d", kind="probe_http",
                         url="http://127.0.0.1:%d/redirect-away" % self.target_port,
                         headers={"Authorization": "Bearer supersecret"}),
                guard, CaptureRules(), "/tmp", 1)
        finally:
            session.stop()
        self.assertEqual(
            self.third_cls.received, [],
            "the redirect target was reached, with the probe's credentials")
        self.assertEqual(outcome.probe.status, 302,
                         "the probe should stop AT the refused redirect")

    def test_probe_http_carries_the_session_headers_a_check_did_not_set(self):
        """Regression: a External review found `context.request.fetch()`
        (what `_probe_http` uses) does NOT go through the browser's route
        guard at all - confirmed empirically. `_probe_http` built its
        headers from only `directive.headers`, so an operator session
        established via `--bearer`/`--header` authenticated ordinary page
        traffic while every direct probe (SQLi, XSS, authz...) replayed
        completely unauthenticated. Cookie auth happened to survive only
        because the request context shares the browser's cookie jar."""
        from sekuscan.agent.browser import BrowserSession
        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import Directive, ScopeRules

        target_url = "http://127.0.0.1:%d/" % self.target_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret"},
            scope_origins=[target_url])
        guard = ScopeGuard(ScopeRules(origins=[target_url]))
        session.start()
        try:
            outcome = execute(
                session,
                Directive(id="d", kind="probe_http", url=target_url),
                guard, CaptureRules(), "/tmp", 1)
        finally:
            session.stop()
        self.assertTrue(outcome.probe.ok)
        got = [r for r in self.target_cls.received]
        self.assertTrue(got)
        self.assertEqual(got[-1]["headers"].get("authorization"),
                         "Bearer supersecret")

    def test_probe_http_never_sends_session_headers_to_a_different_credential_origin(self):
        """The fix above must respect the SAME credential-origin boundary as
        the browser guard - a probe aimed at an in-scope-but-different
        origin must not carry the credential either."""
        from sekuscan.agent.browser import BrowserSession
        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import Directive, ScopeRules

        target_url = "http://127.0.0.1:%d/" % self.target_port
        other_origin = "http://127.0.0.1:%d/" % self.third_port
        session = BrowserSession(
            headless=True, timeout_ms=8000, capture=CaptureRules(),
            extra_headers={"Authorization": "Bearer supersecret"},
            scope_origins=[target_url, other_origin],
            credential_origins=[target_url])
        guard = ScopeGuard(ScopeRules(origins=[target_url, other_origin]))
        session.start()
        try:
            execute(session,
                   Directive(id="d", kind="probe_http", url=other_origin),
                   guard, CaptureRules(), "/tmp", 1)
        finally:
            session.stop()
        leaked = [r for r in self.third_cls.received
                 if "authorization" in r["headers"]]
        self.assertEqual(leaked, [])

    def test_a_redirect_that_stays_in_scope_is_still_followed(self):
        """The fix must not break ordinary in-scope redirect chains, which
        several checks rely on to see the page a redirect actually lands
        on."""
        from sekuscan.agent.browser import BrowserSession
        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import Directive, ScopeRules

        target_url = "http://127.0.0.1:%d/" % self.target_port

        class SelfRedirect(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/go":
                    self.send_response(302)
                    self.send_header("Location", "/landed")
                    self.end_headers()
                    return
                self.send_response(200)
                body = b"landed"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        server, port = _serve(SelfRedirect)
        session = BrowserSession(headless=True, timeout_ms=8000,
                                 capture=CaptureRules(),
                                 scope_origins=["http://127.0.0.1:%d/" % port])
        guard = ScopeGuard(ScopeRules(origins=["http://127.0.0.1:%d/" % port]))
        session.start()
        try:
            outcome = execute(
                session,
                Directive(id="d", kind="probe_http",
                         url="http://127.0.0.1:%d/go" % port),
                guard, CaptureRules(), "/tmp", 1)
        finally:
            session.stop()
            server.shutdown()
            server.server_close()
        self.assertEqual(outcome.probe.status, 200)
        self.assertEqual(outcome.probe.body_sample, "landed")


if __name__ == "__main__":
    unittest.main()
