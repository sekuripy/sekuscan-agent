# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""The engine names a secret by handle; the agent resolves it into the
request it sends to the target. Whatever then carries the value back - the
request as sent, a URL a GET form put it in, a captured cookie, a target that
echoes it - nothing the agent sends the engine may contain it.

One guard at the one road to the engine (`EngineClient._post_status`), not
one per path that might carry a value there.
"""

from __future__ import annotations

import json
import unittest

import httpx

from sekuscan.agent import redaction
from sekuscan.agent.api import EngineClient


class TestNoOperatorSecretReachesTheEngine(unittest.TestCase):

    def setUp(self):
        self.sent = []
        client = EngineClient("https://engine.test", "k")
        client._client = httpx.Client(transport=httpx.MockTransport(self._engine))
        self.client = client
        redaction.register_secret_values(["hunter22!x", "operator-bearer-token", "ab"])
        self.addCleanup(redaction.register_secret_values, [])

    def _engine(self, request):
        self.sent.append(request.content.decode())
        return httpx.Response(200, json={})

    def test_every_form_of_a_secret_is_removed_and_the_document_survives(self):
        self.client._post("/v1/x", {
            "raw_request": "POST /s HTTP/1.1\r\n\r\nq=hunter22!x",
            "url": "https://t.test/search?q=hunter22%21x",
            "plus": "q=hunter22%21x&a=1",
            "json": '{"p":"hunter22!x"}',
            "html": "<b>hunter22!x</b>",
            "hunter22!x": ["Bearer operator-bearer-token", 7, True, None],
            "short": "ab stays",
        })
        sent = self.sent[-1]
        for leaked in ("hunter22", "operator-bearer-token"):
            self.assertNotIn(leaked, sent)
        document = json.loads(sent)
        self.assertEqual(document[redaction.SECRET_REDACTED][1:], [7, True, None])
        self.assertEqual(document["short"], "ab stays")
        self.assertEqual(document["plus"], "q=%s&a=1" % redaction.SECRET_REDACTED)

    def test_inside_a_compressed_body(self):
        from sekuscan.agent.execute import compress_body
        import base64
        import zlib
        self.client._post("/v1/x", {"probe": {"body_z": compress_body("echo: hunter22!x end")}})
        sent = json.loads(self.sent[-1])
        inner = zlib.decompress(base64.b64decode(sent["probe"]["body_z"])).decode()
        self.assertNotIn("hunter22", inner)
        self.assertIn("echo:", inner)

    def test_a_secret_cut_off_at_either_end_of_a_string(self):
        self.client._post("/v1/x", {"raw_request": "A" * 50 + "hunter22",
                                    "body_sample": "r22!x tail"})
        sent = self.sent[-1]
        self.assertNotIn("hunter22", sent)
        self.assertNotIn("r22!x", sent)

    def test_in_a_browser_form_encoding(self):
        redaction.register_secret_values(["Pa~ss*wd!9"])
        self.client._post("/v1/x", {"url": "https://t.test/s?q=Pa%7Ess*wd%219"})
        self.assertNotIn("wd%219", self.sent[-1])

    def test_echoed_back_transformed(self):
        import base64
        self.client._post("/v1/x", {"a": "X-TOKEN: HUNTER22!X", "b": "hunter22!x".upper().lower(),
                                    "c": base64.b64encode(b"hunter22!x").decode()})
        sent = self.sent[-1]
        for leaked in ("HUNTER22", "hunter22", base64.b64encode(b"hunter22!x").decode().rstrip("=")):
            self.assertNotIn(leaked, sent)

    def test_structure_and_ubiquitous_words_survive(self):
        redaction.register_secret_values(["password", "S3cret-Value"])
        self.client._post("/v1/x", {"inputs": [{"type": "password", "name": "S3cret-Value"}],
                                    "body_sample": "<input type=password> S3cret-Value"})
        document = json.loads(self.sent[-1])
        self.assertEqual(document["inputs"][0], {"type": "password", "name": "S3cret-Value"})
        self.assertEqual(document["body_sample"],
                         "<input type=password> " + redaction.SECRET_REDACTED)

    def test_nothing_registered_changes_nothing(self):
        redaction.register_secret_values([])
        self.client._post("/v1/x", {"a": "hunter22!x"})
        self.assertIn("hunter22!x", self.sent[-1])



class TestASecretGoesOnlyWhereItBelongs(unittest.TestCase):
    """The engine names a secret by handle; where the agent may put it."""

    def _session(self, allowed=True):
        from unittest.mock import Mock
        session = Mock()
        session.credentials_allowed.return_value = allowed
        return session

    def test_a_probe_body_only_to_a_credential_origin_and_never_in_a_get(self):
        from sekuscan.agent.execute import _secret_in_body_refused
        from sekuscan.protocol.models import SECRET_PASSWORD, Directive
        body = '{"p":"%s"}' % SECRET_PASSWORD
        post = Directive(id="d", kind="probe_http", method="POST", url="https://t.test/", body=body)
        self.assertIsNone(_secret_in_body_refused(self._session(True), post))
        self.assertIsNotNone(_secret_in_body_refused(self._session(False), post))
        get = Directive(id="d", kind="probe_http", method="GET", url="https://t.test/", body=body)
        self.assertIsNotNone(_secret_in_body_refused(self._session(True), get))

    def test_an_operator_cookie_cannot_be_captured(self):
        from unittest.mock import Mock
        from sekuscan.agent.execute import _perform_capture
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import ScopeRules
        capture = Mock(url="https://t.test/", cookie_name="sid", pattern="^(.{5})", group=1)
        context = Mock()
        context.storage_state.return_value = {"cookies": [{"name": "sid", "value": "operator-cookie"}]}
        out = _perform_capture(context, capture, ScopeGuard(ScopeRules(origins=["https://t.test/"])),
                               operator_cookies={"sid": "operator-cookie"})
        self.assertFalse(out.action_result.ok)
        self.assertIn("operator cookie", out.action_result.error)

    def test_a_file_upload_or_delete_needs_risk_2_whatever_is_declared(self):
        from sekuscan.agent.execute import LocalExecutionPolicy, _authorize_locally
        from sekuscan.protocol.models import Directive
        body = ('--B\r\nContent-Disposition: form-data; name="f"; filename="s.php"\r\n\r\n'
                '<?php ?>\r\n--B--\r\n')
        empty = '--B\r\nContent-Disposition: form-data; name="f"; filename="x"\r\n\r\n\r\n--B--\r\n'
        headers = {"Content-Type": "multipart/form-data; boundary=B"}
        for directive, refused in (
                (Directive(id="d", kind="probe_http", method="POST", url="https://t.test/",
                           body=body, headers=headers, effect="read"), True),
                (Directive(id="d", kind="probe_http", method="POST", url="https://t.test/",
                           body=empty, headers=headers, effect="read"), False),
                (Directive(id="d", kind="probe_http", method="DELETE", url="https://t.test/x",
                           effect="read"), True)):
            self.assertEqual(_authorize_locally(directive, LocalExecutionPolicy(risk=1)) is not None,
                             refused, directive.method)
            self.assertIsNone(_authorize_locally(directive, LocalExecutionPolicy(risk=2)))


if __name__ == "__main__":
    unittest.main()
