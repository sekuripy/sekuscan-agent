# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""A credentialed replay must not carry two values of the same cookie.

`_cookie_override_header` replaced the jar's copy only when the NAME AND THE
PATH both matched. A `Cookie` header carries no paths, so two entries of one
name are two values of that cookie and the server picks one - never reliably
the one the probe is trying to prove something about.

The path half fired on the ordinary case, because a `Set-Cookie` with no
`Path` attribute defaults to THE REQUEST'S DIRECTORY. the target application
answers `?fetch=true` with `Set-Cookie: JWT=<token>; httponly` under
`/the target application/JWTVulnerability`, the directive asks for `/`, and every
credentialed replay went out with two `JWT` cookies. Measured against the
live application:

    JWT=<its own token>                  {"content":null,"isValid":true}
    JWT=<other>; JWT=<its own token>     401
    JWT=<its own token>; JWT=<other>     401

So its `authentic` baseline failed on eleven of twelve routes and
its acceptance oracle correctly concluded nothing about any of them -
including the routes that do accept a forgery.
"""

from __future__ import annotations

import unittest

from sekuscan.agent import execute
from sekuscan.protocol.models import Directive


class _Session:
    def __init__(self, jar):
        self._jar = jar

    def cookies(self):
        return self._jar


def _directive(**kw):
    base = {"id": "d1", "kind": "probe_http", "url": "http://t.test/app/x",
            "cookie_name": "JWT", "cookie_value": "ours",
            "auth_profile": "primary"}
    base.update(kw)
    return Directive(**base)


def _jar(*cookies):
    return [{"name": n, "value": v, "path": p, "domain": "t.test",
             "secure": False} for n, v, p in cookies]


class TheJarsCopyIsReplacedNotJoined(unittest.TestCase):

    def test_a_directory_scoped_cookie_is_replaced(self):
        """THE case. No `Path` attribute means the request's directory, so
        the jar holds `/app` while the directive asks for `/`."""
        header = execute._cookie_override_header(
            _Session(_jar(("JWT", "theirs", "/app"))), _directive())
        self.assertEqual(header, "JWT=ours")

    def test_a_root_scoped_cookie_is_still_replaced(self):
        header = execute._cookie_override_header(
            _Session(_jar(("JWT", "theirs", "/"))), _directive())
        self.assertEqual(header, "JWT=ours")

    def test_two_copies_of_the_name_collapse_into_one(self):
        header = execute._cookie_override_header(
            _Session(_jar(("JWT", "a", "/"), ("JWT", "b", "/app"))),
            _directive())
        self.assertEqual(header, "JWT=ours")

    def test_other_cookies_are_untouched(self):
        """The session has to survive - replacing the credential must not
        log the probe out of everything else."""
        header = execute._cookie_override_header(
            _Session(_jar(("sid", "s1", "/"), ("JWT", "theirs", "/app"),
                          ("lang", "en", "/"))),
            _directive())
        self.assertEqual(header, "sid=s1; JWT=ours; lang=en")

    def test_a_name_the_jar_never_held_is_appended(self):
        header = execute._cookie_override_header(
            _Session(_jar(("sid", "s1", "/"))), _directive())
        self.assertEqual(header, "sid=s1; JWT=ours")


if __name__ == "__main__":
    unittest.main()
