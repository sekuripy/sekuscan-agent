# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""`_cookie_applies` decides whether a browser-held cookie would actually be
sent to a given url - shared by the raw-query transport and the cookie
override probe, so a manually-replayed request carries exactly the cookies
the real browser would have, no more.

A External review found the domain check always allowed a subdomain
match, regardless of whether the cookie was host-only or domain-scoped, and
the raw-query transport's path check used a naive `startswith` with no
segment boundary (`/app` matching `/apple`).
"""

from __future__ import annotations

import unittest

from sekuscan.agent.execute import _cookie_applies


def cookie(**kw):
    base = {"name": "sid", "value": "x", "domain": "target.test", "path": "/"}
    base.update(kw)
    return base


class TestCookieApplies(unittest.TestCase):

    def test_a_host_only_cookie_matches_its_exact_host(self):
        self.assertTrue(_cookie_applies(
            cookie(domain="target.test"), "https://target.test/"))

    def test_a_host_only_cookie_does_not_match_a_subdomain(self):
        """Regression: a host-only cookie (no leading dot) used to match
        `host.endswith('.' + domain)` unconditionally - so a cookie scoped
        to `target.test` alone could be manually replayed to
        `api.target.test`, which the browser itself would never do."""
        self.assertFalse(_cookie_applies(
            cookie(domain="target.test"), "https://api.target.test/"))

    def test_a_domain_scoped_cookie_does_match_a_subdomain(self):
        self.assertTrue(_cookie_applies(
            cookie(domain=".target.test"), "https://api.target.test/"))

    def test_a_domain_scoped_cookie_still_matches_the_bare_host(self):
        self.assertTrue(_cookie_applies(
            cookie(domain=".target.test"), "https://target.test/"))

    def test_a_suffix_that_is_not_a_subdomain_never_matches(self):
        self.assertFalse(_cookie_applies(
            cookie(domain=".target.test"), "https://eviltarget.test/"))

    def test_a_sibling_path_that_shares_a_prefix_does_not_match(self):
        """Regression: the raw-query transport's own path check was a bare
        `startswith`, so a cookie scoped to `/app` matched a request to
        `/apple`."""
        self.assertFalse(_cookie_applies(
            cookie(path="/app"), "https://target.test/apple"))

    def test_a_child_path_matches(self):
        self.assertTrue(_cookie_applies(
            cookie(path="/app"), "https://target.test/app/settings"))

    def test_the_exact_path_matches(self):
        self.assertTrue(_cookie_applies(
            cookie(path="/app"), "https://target.test/app"))

    def test_a_secure_cookie_never_matches_a_plaintext_request(self):
        self.assertFalse(_cookie_applies(
            cookie(secure=True), "http://target.test/"))
        self.assertTrue(_cookie_applies(
            cookie(secure=True), "https://target.test/"))


if __name__ == "__main__":
    unittest.main()
