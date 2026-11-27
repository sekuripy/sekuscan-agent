# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""The agent's own copy of the risk model.

A External review found the agent trusted the engine to have already
applied `risk`/`allow_destructive`/`allow_upload_cleanup`/
`allow_authz_non_get` - `execute()` serialized whatever directive kind and
method the engine sent, with no local re-check. Scope gets a local,
engine-independent enforcement (`ScopeGuard`); risk had no equivalent. This
is that equivalent: `LocalExecutionPolicy` is built once in `agent/cli.py`
from the operator's own local CLI flags, never from anything the engine
sends back, and `_authorize_locally()` is consulted by `execute()` before
any directive is dispatched.
"""

from __future__ import annotations

import unittest

from sekuscan.agent.execute import (LocalExecutionPolicy, _authorize_locally,
                                    _urls_match)
from sekuscan.protocol.models import Directive, effective_risk


class TestAuthorizeLocally(unittest.TestCase):

    def test_upload_is_a_write_not_a_destruction(self):
        """This asserted risk 3, and the contract says otherwise.

        An upload the application ACCEPTS is a write - level 2. Only the
        cleanup that deletes it afterwards is destructive, and that has its
        own explicit flag (see the next test, which is unchanged). The real
        switch is still the `upload_probes` feature flag, off by default.
        """
        directive = Directive(id="d", kind="upload_file", url="http://t/upload")
        self.assertIsNotNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1)))
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=2)))
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=3)))

    def test_upload_cleanup_requires_the_flag_even_if_risk_is_high(self):
        directive = Directive(id="d", kind="upload_cleanup", url="http://t/cleanup",
                              method="DELETE")
        self.assertIsNotNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=3, allow_upload_cleanup=False)))
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(
                risk=3, allow_upload_cleanup=True,
                upload_cleanup_url="http://t/cleanup")))

    def test_upload_cleanup_refuses_a_url_other_than_the_one_authorized(self):
        """Regression: the agent verified the DELETE shape and that the url
        was in scope, but never that it was the EXACT url the operator
        authorized - any in-scope DELETE endpoint could be used."""
        directive = Directive(id="d", kind="upload_cleanup",
                              url="http://t/some-other-delete-endpoint",
                              method="DELETE")
        refusal = _authorize_locally(directive, LocalExecutionPolicy(
            risk=3, allow_upload_cleanup=True,
            upload_cleanup_url="http://t/cleanup"))
        self.assertIsNotNone(refusal)
        self.assertIn("explicitly authorized", refusal)

    def test_form_mutation_requires_risk_2_or_allow_destructive(self):
        directive = Directive(id="d", kind="fill_submit", url="http://t/form",
                              extra_values={"role": "admin"})
        self.assertIsNotNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1, allow_destructive=False)))
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=2)))
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1, allow_destructive=True)))

    def test_an_ordinary_form_fill_with_no_mutation_is_never_gated(self):
        directive = Directive(id="d", kind="fill_submit", url="http://t/form",
                              values={"q": "x"})
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1)))

    def test_a_non_read_only_probe_requires_risk_2(self):
        directive = Directive(id="d", kind="probe_http", url="http://t/x",
                              method="POST", effect="write")
        self.assertIsNotNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1)))
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=2)))

    def test_a_read_only_probe_is_never_gated(self):
        for method in ("GET", "HEAD", "OPTIONS"):
            directive = Directive(id="d", kind="probe_http", url="http://t/x",
                                  method=method)
            self.assertIsNone(_authorize_locally(
                directive, LocalExecutionPolicy(risk=1)))

    def test_a_declared_read_effect_over_post_is_never_gated(self):
        """A GraphQL query, a REST batch, a JSON search body - none of them
        change server state, whatever verb carries them. `queue()`'s own
        `_validate_effect` already enforces this at plan time; the agent's
        local gate honors the same declaration instead of refusing every
        non-GET method regardless of what the check actually said."""
        directive = Directive(id="d", kind="probe_http", url="http://t/x",
                              method="POST", effect="read")
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1)))

    def test_an_undeclared_effect_over_post_defaults_to_read_and_is_not_gated(self):
        """`Directive.effect` defaults to "read", the same default
        `ProbePlan.effect` already carries - a check that never touches the
        field (the common case) is a query, not a write, and this must not
        silently start requiring risk 2 for it."""
        directive = Directive(id="d", kind="probe_http", url="http://t/x",
                              method="POST")
        self.assertIsNone(_authorize_locally(
            directive, LocalExecutionPolicy(risk=1)))

    def test_a_declared_write_or_destructive_effect_over_post_still_requires_risk_2(self):
        for effect in ("write", "destructive"):
            directive = Directive(id="d", kind="probe_http", url="http://t/x",
                                  method="POST", effect=effect)
            self.assertIsNotNone(_authorize_locally(
                directive, LocalExecutionPolicy(risk=1)),
                "effect=%r must still be gated at risk 1" % effect)
            self.assertIsNone(_authorize_locally(
                directive, LocalExecutionPolicy(risk=2)))

    def test_navigation_and_other_kinds_are_never_gated_by_risk(self):
        for kind in ("navigate", "click", "set_cookie", "screenshot", "wait"):
            directive = Directive(id="d", kind=kind, url="http://t/x")
            self.assertIsNone(_authorize_locally(
                directive, LocalExecutionPolicy(risk=1)))


class TestUrlsMatch(unittest.TestCase):

    def test_identical_urls_match(self):
        self.assertTrue(_urls_match("http://t/a?x=1", "http://t/a?x=1"))

    def test_a_trailing_slash_does_not_defeat_the_match(self):
        self.assertTrue(_urls_match("http://t/a/", "http://t/a"))

    def test_a_different_path_does_not_match(self):
        self.assertFalse(_urls_match("http://t/a", "http://t/b"))

    def test_a_different_host_does_not_match(self):
        self.assertFalse(_urls_match("http://t/a", "http://evil.test/a"))


class TestEffectiveRisk(unittest.TestCase):
    """Shared by the engine and `agent/cli.py` - both must agree, or
    the agent's local gate refuses work the engine itself authorized (or
    worse, the reverse)."""

    def test_the_explicit_risk_dial_is_never_lowered(self):
        self.assertEqual(effective_risk(3, False, False, False), 3)

    def test_allow_destructive_alone_bumps_to_at_least_2(self):
        self.assertEqual(effective_risk(1, True, False, False), 2)

    def test_allow_authz_non_get_alone_bumps_to_at_least_2(self):
        self.assertEqual(effective_risk(1, False, False, True), 2)

    def test_allow_upload_cleanup_bumps_to_3(self):
        self.assertEqual(effective_risk(1, False, True, False), 3)

    def test_a_plain_profile_with_no_flags_stays_at_the_explicit_dial(self):
        self.assertEqual(effective_risk(1, False, False, False), 1)

    def test_a_profile_name_suffix_alone_no_longer_bumps_risk(self):
        """Regression: a External review found this used to ALSO bump
        risk from a `profile` string suffix (`*-upload`, `*-command-proof`)
        - `auth.features_for_profile()` already enables exactly the
        suffix-named capability directly and independently, so folding the
        same suffix into this scalar too only added collateral
        authorization (`default-command-proof` silently also authorized
        business_logic_probes/upload_probes/race_probes/smuggling_probes,
        none of which the operator asked for). `effective_risk` no longer
        takes a `profile` argument at all."""
        import inspect

        self.assertEqual(
            list(inspect.signature(effective_risk).parameters),
            ["risk", "allow_destructive", "allow_upload_cleanup",
             "allow_authz_non_get"])


class TestExecuteConsultsThePolicy(unittest.TestCase):
    """`execute()` must refuse BEFORE dispatching to a handler, not rely on
    every handler to remember to check risk itself."""

    def test_an_upload_directive_is_refused_at_risk_1_before_touching_the_browser(self):
        from unittest.mock import Mock

        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import ScopeRules

        session = Mock()
        guard = ScopeGuard(ScopeRules(origins=["http://t/"]))
        directive = Directive(id="d", kind="upload_file", url="http://t/upload")

        outcome = execute(session, directive, guard, capture=None, out_dir="/tmp",
                          seq=1, policy=LocalExecutionPolicy(risk=1))

        self.assertFalse(outcome.action_result.ok)
        self.assertIn("refused", outcome.action_result.error)
        session.page.locator.assert_not_called()

    def test_execute_defaults_to_the_safest_policy_when_none_is_passed(self):
        """A caller that forgets to pass a policy must fail closed (risk 1),
        not silently authorize everything."""
        from unittest.mock import Mock

        from sekuscan.agent.execute import execute
        from sekuscan.agent.scope import ScopeGuard
        from sekuscan.protocol.models import ScopeRules

        session = Mock()
        guard = ScopeGuard(ScopeRules(origins=["http://t/"]))
        directive = Directive(id="d", kind="upload_file", url="http://t/upload")

        outcome = execute(session, directive, guard, capture=None, out_dir="/tmp", seq=1)

        self.assertFalse(outcome.action_result.ok)


if __name__ == "__main__":
    unittest.main()
