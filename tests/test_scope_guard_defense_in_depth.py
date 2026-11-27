# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""the agent trusted the engine's ECHOED scope.

`ScopeGuard(run.scope)` used to be built straight from the engine's
RunCreateResponse, with no check that it matched what this process actually
asked for - unlike the risk model, which is deliberately kept from this
process's own local arguments alone. A compromised or buggy engine could
echo back an origins list wider than requested, or silently drop a
`--deny` entry, and every directive after that point would be authorized
against the wider thing. `_scope_not_widened` is the check that closes it -
scoped narrowly (lower priority than Tiers 1-3: this needs an
already-malicious engine deployment to matter), but a real, tested gap.
"""

from __future__ import annotations

import unittest

from sekuscan.agent.cli import _scope_not_widened
from sekuscan.protocol.models import ScopeRules


class TestScopeNotWidened(unittest.TestCase):

    def test_an_exact_echo_is_fine(self):
        echoed = ScopeRules(origins=["http://t.test/"], deny_substrings=["/logout"])
        self.assertIsNone(_scope_not_widened(["http://t.test/"], ["/logout"], echoed))

    def test_the_brain_adding_its_own_default_deny_entries_is_fine(self):
        """Only a MISSING requested entry is a problem - the engine adding
        its own DEFAULT_DENY hardening entries is expected and correct."""
        echoed = ScopeRules(origins=["http://t.test/"],
                            deny_substrings=["/logout", "/setup.php", "phpids=on"])
        self.assertIsNone(_scope_not_widened(["http://t.test/"], ["/logout"], echoed))

    def test_an_extra_origin_is_refused(self):
        echoed = ScopeRules(origins=["http://t.test/", "http://internal.test/"])
        problem = _scope_not_widened(["http://t.test/"], [], echoed)
        self.assertIsNotNone(problem)
        self.assertIn("internal.test", problem)

    def test_a_missing_deny_entry_is_refused(self):
        echoed = ScopeRules(origins=["http://t.test/"], deny_substrings=[])
        problem = _scope_not_widened(["http://t.test/"], ["/admin"], echoed)
        self.assertIsNotNone(problem)
        self.assertIn("/admin", problem)

    def test_no_scope_arg_falls_back_to_the_target_as_the_sole_origin(self):
        """Mirrors RunService.create()'s own `origins = req.scope or
        [req.target]` fallback - the caller passes `scope or [target]`."""
        echoed = ScopeRules(origins=["http://t.test/"])
        self.assertIsNone(_scope_not_widened(["http://t.test/"], [], echoed))

    def test_subdomains_the_operator_never_asked_for_are_refused(self):
        echoed = ScopeRules(origins=["http://t.test/"], allow_subdomains=True)
        self.assertIn("subdomains", _scope_not_widened(["http://t.test/"], [], echoed))

    def test_a_depth_beyond_max_depth_is_refused(self):
        for depth in (None, 5):
            echoed = ScopeRules(origins=["http://t.test/"], max_depth=depth)
            self.assertIsNotNone(_scope_not_widened(["http://t.test/"], [], echoed, 2), depth)
        self.assertIsNone(_scope_not_widened(
            ["http://t.test/"], [], ScopeRules(origins=["http://t.test/"], max_depth=2), 2))

    def test_a_subset_echo_is_also_fine(self):
        """The engine narrowing (never widening) is not a problem this
        check exists to catch."""
        echoed = ScopeRules(origins=["http://t.test/"])
        self.assertIsNone(
            _scope_not_widened(["http://t.test/", "http://also.test/"], [], echoed))

    def test_empty_echoed_origins_is_not_a_widening(self):
        echoed = ScopeRules(origins=[])
        self.assertIsNone(_scope_not_widened(["http://t.test/"], [], echoed))


if __name__ == "__main__":
    unittest.main()
