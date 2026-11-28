# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""The concurrent path sends a plain primary-session HTTP request built from
the directive's URL, method, headers and body. A directive of another kind,
another identity, or with options that path does not implement was sent
anyway - a `navigate` with `method=DELETE` went out as a DELETE at risk 1.
It is refused instead. And a transport upload is held to the same risk
level as a browser upload.
"""

from __future__ import annotations

import unittest
from unittest.mock import Mock

from sekuscan.agent import execute
from sekuscan.agent.execute import LocalExecutionPolicy, _authorize_locally
from sekuscan.agent.scope import ScopeGuard
from sekuscan.protocol.models import CaptureRules, Directive, ScopeRules

URL = "https://target.test/x"


class TestABatchIsHeldToTheSameRules(unittest.TestCase):

    def _batch(self, **fields):
        worker = Mock()
        worker.dispatch_batch.return_value = []
        session = Mock()
        session.extra_headers = {}
        session.cookies.return_value = []
        outcomes = execute.execute_batch(
            session, [Directive(id="d", url=URL, **fields)],
            ScopeGuard(ScopeRules(origins=["https://target.test/"])), CaptureRules(),
            LocalExecutionPolicy(risk=1), worker, 5.0)
        return outcomes[0], worker

    def test_only_a_plain_primary_probe_is_batched(self):
        for fields in ({"kind": "navigate", "method": "DELETE", "effect": "write"},
                       {"kind": "probe_http", "auth_profile": "secondary"},
                       {"kind": "probe_http", "raw_query": True},
                       {"kind": "probe_http", "browser_context": True}):
            outcome, worker = self._batch(**fields)
            self.assertFalse(outcome.action_result.ok, fields)
            self.assertIn("refused", outcome.action_result.error, fields)
            worker.dispatch_batch.assert_not_called()

    def test_an_anonymous_probe_is_batched_in_a_context_of_its_own(self):
        """The engine batches anonymous reads and the worker gives each its own
        cookie-less context. Refusing them here failed every anonymous
        baseline a check compares against, silently."""
        outcome, worker = self._batch(kind="probe_http", anonymous=True)
        worker.dispatch_batch.assert_called_once()
        specs = worker.dispatch_batch.call_args[0][0]
        self.assertTrue(specs[0]["anonymous"])

    def test_a_transport_upload_needs_risk_2(self):
        directive = Directive(id="d", kind="probe_http", method="POST", url=URL, effect="read",
                              upload_fixture="text_plain", upload_marker="sksabcd")
        self.assertIsNotNone(_authorize_locally(directive, LocalExecutionPolicy(risk=1)))
        self.assertIsNone(_authorize_locally(directive, LocalExecutionPolicy(risk=2)))


if __name__ == "__main__":
    unittest.main()
