# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""An encoded separator can carry a `..` past the scope check.

`_decode_unreserved` deliberately leaves `%2F` encoded, reasoning that
decoding it "would change how many path segments the url has, which is
exactly the boundary this function exists to protect". It does change the
count - and that is the attack rather than the defence, because an encoded
separator keeps the dots INSIDE a segment where `_resolve_dot_segments`
cannot see them:

    /app/%2e%2e/admin      denied    the dots are their own segment
    /app/%2e%2e%2Fadmin    ALLOWED   the dots hide in one segment

Tomcat with `ALLOW_ENCODED_SLASH`, Apache with `AllowEncodedSlashes` and any
proxy that normalises before forwarding route the second one as
`/app/../admin` -> `/admin`. `%5C` is the same on IIS/.NET. So the scope
checker approved `/app` and the wire touched `/admin` - the same class of
disagreement this module's own docstring says it exists to close, arriving
through the one escape it left encoded.

The cases that must keep working matter as much: an encoded slash inside a
path VALUE is ordinary (`/repos/owner%2Fname` is how half the API web spells
a nested identifier), and refusing those would cost real coverage.
"""

from __future__ import annotations

import unittest

from sekuscan.protocol import scoping


SCOPE = ["https://host/app"]


class TestAnEncodedSlashCannotCarryADotSegment(unittest.TestCase):
    def test_the_escapes_are_refused(self) -> None:
        for url in (
            "https://host/app/%2e%2e/admin",       # already refused; the control
            "https://host/app/%2e%2e%2Fadmin",     # the reviewer's case
            "https://host/app/%2e%2e%2fadmin",     # lowercase hex
            "https://host/app/..%2Fadmin",         # plain dots, encoded slash
            "https://host/app/%2e%2e%5Cadmin",     # backslash, IIS/.NET
            "https://host/app/x/%2e%2e%2f%2e%2e%2fadmin",   # two levels up
        ):
            with self.subTest(url=url):
                self.assertFalse(scoping.decide(url, SCOPE).allowed)

    def test_an_encoded_slash_in_a_value_still_scans(self) -> None:
        # No `..` anywhere, so both readings agree and nothing is lost.
        for url in (
            "https://host/app",
            "https://host/app/x",
            "https://host/app/repos/owner%2Fname",
            "https://host/app/a%2Fb/c",
        ):
            with self.subTest(url=url):
                self.assertTrue(scoping.decide(url, SCOPE).allowed)

    def test_depth_counts_the_deeper_reading(self) -> None:
        # A backend that decodes `%2F` sees `/app/a/b/c` - three segments below
        # the scope, not two. A depth limit that trusts the shallower count is
        # not a limit on that backend.
        url = "https://host/app/a%2Fb/c"
        self.assertFalse(scoping.decide(url, SCOPE, max_depth=2).allowed)
        self.assertTrue(scoping.decide(url, SCOPE, max_depth=3).allowed)

    def test_the_normaliser_reports_both_readings(self) -> None:
        self.assertEqual(
            scoping._norm_paths("/app/%2e%2e%2Fadmin"),
            ("/app/..%2Fadmin", "/admin"),
        )
        # one form, and no second pass, when there is nothing encoded
        self.assertEqual(scoping._norm_paths("/app/x"), ("/app/x",))


if __name__ == "__main__":
    unittest.main()
