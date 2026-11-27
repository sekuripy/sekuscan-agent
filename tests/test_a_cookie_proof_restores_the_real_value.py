# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""After a browser cookie proof the jar holds what the APPLICATION set, not
the engine's seed.

Restoring the seed (`alpha`) switched the target application's `security=low` to an invalid
level, which the target application answers by hardening itself - so every page tested after
the first cookie proof was a patched page, and which pages those were
depended on dispatch order. Driven through a real Playwright context: the
snapshot lives in the jar, and a mocked jar would only test the mock.
"""

import unittest

from sekuscan.agent.execute import _set_cookie
from sekuscan.protocol.models import Directive

try:
    from playwright.sync_api import sync_playwright
    HAVE_PLAYWRIGHT = True
except ImportError:                                       # pragma: no cover
    HAVE_PLAYWRIGHT = False

URL = "http://target.test/vulnerabilities/xss_r/"


class _Session:
    def __init__(self, context):
        self.context = context
        self.cookie_originals = {}


def _directive(value, restore=False):
    return Directive(id="c", kind="set_cookie", url=URL, cookie_name="security",
                     cookie_value=value, cookie_restore=restore)


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class TestACookieProofRestoresTheRealValue(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._pw = sync_playwright().start()
        cls._browser = cls._pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def setUp(self):
        self.context = self._browser.new_context()
        self.session = _Session(self.context)

    def tearDown(self):
        self.context.close()

    def _jar(self):
        return {c["name"]: c["value"] for c in self.context.cookies(URL)}

    def test_the_applications_own_value_comes_back(self):
        self.context.add_cookies([{"name": "security", "value": "low",
                                   "domain": "target.test", "path": "/"}])
        _set_cookie(self.session, _directive("<svg onload=alert(1)>"))
        _set_cookie(self.session, _directive("x<sks1>y"))
        self.assertEqual(self._jar()["security"], "x<sks1>y")
        _set_cookie(self.session, _directive("alpha", restore=True))
        self.assertEqual(self._jar()["security"], "low")

    def test_a_cookie_the_application_never_set_is_removed(self):
        _set_cookie(self.session, _directive("payload"))
        _set_cookie(self.session, _directive("alpha", restore=True))
        self.assertNotIn("security", self._jar())

    def test_without_a_snapshot_the_seed_is_the_fallback(self):
        self.context.add_cookies([{"name": "security", "value": "payload",
                                   "domain": "target.test", "path": "/"}])
        _set_cookie(self.session, _directive("alpha", restore=True))
        self.assertEqual(self._jar()["security"], "alpha")


if __name__ == "__main__":
    unittest.main()
