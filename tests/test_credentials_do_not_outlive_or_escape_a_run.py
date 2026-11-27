# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Review finding - four ways a run went wrong quietly.

  #65  `_SECRETS` is a module global and `load_secrets()` - the only thing
       that CLEARS it - was called `if auth.password:`. A passwordless run
       therefore inherited the previous run's password, and
       `SECRET_PASSWORD` resolved to it. In an embedding process, or any
       second `run_agent()`, one target's credential could be filled into a
       form on a DIFFERENT target.
  #67  the 429 backoff evaluated `2 ** (streak - 1)` BEFORE clamping, and
       the streak has no ceiling. Reproduced: streak 1025 raises
       `OverflowError`. A target crashes the scanner by doing nothing but
       rate-limiting it, which is the most ordinary behaviour a defended
       application has.
  #68  the primary login's return value was discarded and `json_login_error`
       was written in six places and read in none, so a failed login
       continued ANONYMOUSLY. Every authenticated surface goes untested and
       the report says "nothing found" about an application it never logged
       into - indistinguishable from a clean result.
  #69  the three login POSTs had no `max_redirects=0`. A 307/308 preserves
       METHOD AND BODY, so the credentials were re-sent to whatever
       `Location` named. This project already paid for this class once, when
       a bearer token reached GitHub through a target's own open redirect.
"""

from __future__ import annotations

import inspect
import unittest

from sekuscan.agent import browser as browser_mod
from sekuscan.agent import cli as cli_mod
from sekuscan.agent import execute as execute_mod
from sekuscan.agent.execute import (_SECRETS, _rate_limit_pause,
                                    _rate_limit_streak, load_secrets,
                                    resolve_secret)
from sekuscan.protocol.models import SECRET_PASSWORD


class TheVaultDoesNotSurviveARun(unittest.TestCase):

    def setUp(self):
        load_secrets({})

    def test_a_passwordless_run_clears_the_previous_password(self):
        # `resolve_secret` takes the HANDLE, not the bare name - a first
        # draft passed "password" and got "password" back unchanged, which
        # looks like a pass and proves nothing.
        load_secrets({"password": "run-one-secret"})
        self.assertEqual(resolve_secret(SECRET_PASSWORD), "run-one-secret")
        load_secrets({})
        self.assertEqual(_SECRETS, {},
                         "the previous run's password stayed registered")
        self.assertEqual(resolve_secret(SECRET_PASSWORD), "",
                         "the handle still resolved to the old password")

    def test_the_call_site_is_unconditional(self):
        """The bug was the `if`, not the function: `load_secrets` must run on
        every path so a passwordless run still CLEARS the previous one's vault.
        Building the secrets dict conditionally is fine; gating the CALL is not.
        The dict now also carries the static second-factor code (slice S0)."""
        source = inspect.getsource(cli_mod)
        self.assertNotIn('if auth.password:\n        load_secrets(', source)
        self.assertIn('load_secrets(local_secrets)', source)
        self.assertIn('local_secrets["mfa_code"] = auth.mfa_code', source)


class ARateLimitedTargetCannotCrashTheAgent(unittest.TestCase):

    def test_an_enormous_streak_does_not_overflow(self):
        _rate_limit_streak["h.test"] = 5000
        try:
            pause = _rate_limit_pause("h.test", 429, {})
        finally:
            _rate_limit_streak.pop("h.test", None)
        self.assertLessEqual(pause, execute_mod._RATE_LIMIT_MAX_SLEEP_S)

    def test_the_reviewers_exact_streak(self):
        _rate_limit_streak["h2.test"] = 1024
        try:
            _rate_limit_pause("h2.test", 429, {})   # used to raise
        finally:
            _rate_limit_streak.pop("h2.test", None)

    def test_a_short_streak_still_backs_off_progressively(self):
        """The clamp must not flatten the curve that makes this useful."""
        _rate_limit_streak.pop("h3.test", None)
        first = _rate_limit_pause("h3.test", 429, {})
        second = _rate_limit_pause("h3.test", 429, {})
        _rate_limit_streak.pop("h3.test", None)
        self.assertGreater(second, first)


class AFailedPrimaryLoginIsNotSilent(unittest.TestCase):

    def test_the_session_records_it(self):
        source = inspect.getsource(browser_mod)
        self.assertIn("self.login_failed", source)
        self.assertIn("if not self.login_json():", source,
                      "the primary login's return value was discarded")

    def test_the_agent_tells_the_operator(self):
        source = inspect.getsource(cli_mod)
        self.assertIn("PRIMARY LOGIN FAILED", source)
        self.assertIn("means 'not tested', not 'not vulnerable'", source,
                      "a silent fallback to anonymous is a false-negative "
                      "factory and has to say so")


class CredentialsStopAtTheFirstHop(unittest.TestCase):

    def test_every_login_post_refuses_to_follow_a_redirect(self):
        source = inspect.getsource(browser_mod)
        posts = [line for line in source.splitlines()
                 if ".post(" in line and "request" in line]
        self.assertGreaterEqual(len(posts), 3)
        # Each login POST's own call must carry it. Counting occurrences
        # would not do: `max_redirects=0` already appears on the navigation
        # pre-flight paths, so a global count passes while a login POST still
        # follows redirects.
        for marker in ("endpoint, data=body,", "endpoint, form=form_fields,",
                       "login_url, form=fields,"):
            start = source.index(marker)
            self.assertIn("max_redirects=0", source[start:start + 220], marker)

    def test_a_redirect_is_still_allowed_to_mean_success(self):
        """A login answering 302-to-dashboard is the ordinary case; the
        cookie check, not the status, is the authority."""
        source = inspect.getsource(browser_mod)
        self.assertIn("not 300 <= response.status < 400", source)


if __name__ == "__main__":
    unittest.main()
