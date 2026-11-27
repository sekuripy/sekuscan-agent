# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""The two probe transports that own their own socket - the literal-bytes
HTTP request and the websocket - must make the same two decisions the
ordinary HTTP probe makes: the operator's credentials go only where
`credentials_allowed` says, and every request pays the `--max-rps` claim.
A screenshot name from the engine stays a file name inside the run folder.
"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import websocket as ws_client

from sekuscan.agent import execute
from sekuscan.agent.scope import ScopeGuard
from sekuscan.protocol.models import CaptureRules, Directive, ScopeRules


class _Seen(BaseHTTPRequestHandler):
    headers_seen: list = []

    def do_GET(self):
        _Seen.headers_seen.append(dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        return


def _session(allowed: bool):
    session = Mock()
    session.extra_headers = {"Authorization": "Bearer operator-token"}
    session.secondary_headers = {"Authorization": "Bearer second-token"}
    session.secondary_cookies = {"sid": "second-cookie"}
    session.credentials_allowed.return_value = allowed
    session.ignore_https_errors = True
    session.relay_port = None
    session.cookies.return_value = []
    session.context.cookies.return_value = []
    return session


class TestRawQuery(unittest.TestCase):

    def setUp(self):
        _Seen.headers_seen = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Seen)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d/a?x=%%2e" % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _send(self, allowed):
        execute._probe_raw_query(_session(allowed), Directive(id="d", kind="probe_http", raw_query=True,
                                                                url=self.url), CaptureRules())
        return _Seen.headers_seen[-1]

    def test_operator_headers_only_where_credentials_are_allowed(self):
        self.assertNotIn("Authorization", self._send(False))
        self.assertEqual(self._send(True).get("Authorization"), "Bearer operator-token")

    def test_the_rate_limit_is_claimed(self):
        with patch.object(execute.pacing, "claim", return_value=0) as claim:
            self._send(True)
        claim.assert_called_once_with("127.0.0.1:%d" % self.server.server_address[1])


class TestAHostHeaderNamingAnotherHost(TestRawQuery):
    """Behind a shared front end the `Host` header, not the URL, decides who
    receives the request; the operator's credentials follow the URL only."""

    def _sent_with_host(self, host):
        session = _session(True)
        session.cookies.return_value = [{"name": "sid", "value": "operator-cookie",
                                         "domain": "127.0.0.1", "path": "/"}]
        directive = execute._credentials_only_for_its_own_host(Directive(
            id="d", kind="probe_http", raw_query=True, url=self.url, headers={"Host": host}))
        execute._probe_raw_query(session, directive, CaptureRules())
        return _Seen.headers_seen[-1]

    def test_another_host_gets_no_credentials(self):
        seen = self._sent_with_host("other-tenant.example")
        self.assertEqual(seen.get("Host"), "other-tenant.example")
        self.assertNotIn("Authorization", seen)
        self.assertNotIn("Cookie", seen)

    def test_its_own_host_keeps_them(self):
        seen = self._sent_with_host("127.0.0.1:%d" % self.server.server_address[1])
        self.assertEqual(seen.get("Authorization"), "Bearer operator-token")
        self.assertIn("operator-cookie", seen.get("Cookie", ""))


class TestWebsocket(unittest.TestCase):

    def _connect(self, allowed):
        connection = Mock()
        connection.recv.return_value = ""
        with patch.object(ws_client, "create_connection", return_value=connection) as create, \
                patch.object(execute.pacing, "claim", return_value=0) as claim:
            execute._probe_ws(_session(allowed),
                              Directive(id="d", kind="probe_ws", url="wss://target.test/s",
                                        auth_profile="secondary", body="{}"),
                              CaptureRules(), ScopeGuard(ScopeRules(origins=["wss://target.test"])))
        claim.assert_called_once_with("target.test:443")
        return create.call_args.kwargs

    def test_the_second_identity_only_where_credentials_are_allowed(self):
        refused = self._connect(False)
        self.assertNotIn("second-token", str(refused["header"]))
        self.assertIsNone(refused["cookie"])
        allowed = self._connect(True)
        self.assertIn("Authorization: Bearer second-token", allowed["header"])
        self.assertEqual(allowed["cookie"], "sid=second-cookie")


class TestWebsocketRedirect(unittest.TestCase):
    """websocket-client follows a 3xx handshake by default; the hop would
    take the operator's credentials to a URL nobody checked."""

    def test_a_handshake_redirect_is_not_followed(self):
        hits = []

        class Elsewhere(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(dict(self.headers))
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                return

        other = ThreadingHTTPServer(("127.0.0.1", 0), Elsewhere)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        self.addCleanup(other.server_close)
        self.addCleanup(other.shutdown)
        location = "ws://127.0.0.1:%d/steal" % other.server_address[1]

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                return

        here = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=here.serve_forever, daemon=True).start()
        self.addCleanup(here.server_close)
        self.addCleanup(here.shutdown)
        url = "ws://127.0.0.1:%d/socket" % here.server_address[1]
        session = _session(True)
        session.extra_headers = {"Authorization": "Bearer operator-token"}
        outcome = execute._probe_ws(session, Directive(id="d", kind="probe_ws", url=url, body="{}"),
                                    CaptureRules(), ScopeGuard(ScopeRules(origins=[url])))
        self.assertEqual(hits, [])
        self.assertIn("Redirect", outcome.probe.error or "")


class TestScreenshotName(unittest.TestCase):

    def test_an_engine_name_cannot_leave_the_run_folder(self):
        session = Mock()
        session.screenshot.side_effect = lambda path: path
        with tempfile.TemporaryDirectory() as out:
            for name in ("../../etc/cron.d/x", "/abs/path", "..", "a/../../b"):
                outcome = execute._screenshot(session, Directive(id="d", kind="screenshot", name=name), out, 7)
                saved = outcome.action_result.detail["path"]
                self.assertEqual(os.path.dirname(os.path.abspath(saved)),
                                 os.path.join(os.path.abspath(out), "screenshots"), name)


if __name__ == "__main__":
    unittest.main()
