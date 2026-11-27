# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Review finding - the proof described a request nobody made.

`_raw_request()` built its target from `directive.url` and took the method
and body from `kwargs`. The redirect loop MUTATES those: a 303, or a 301/302
on anything that was not already a GET, rewrites the method to GET and drops
the body.

So a real exchange of

    POST /a  ->  302 /b  ->  GET /b

was recorded as `GET /a` - not the request that was sent, not the one that
answered, and printed beside `/b`'s response.

That is the worst shape a proof defect can take. A missing exchange is
obviously missing; a plausible, well-formed, WRONG one is indistinguishable
from a true one, and a reader who tries to reproduce it gets a different
answer and concludes the scanner is lying about the finding rather than about
the transcript.

`url` is a parameter now, and both redirect-following call sites pass the hop
they actually ended on.
"""

from __future__ import annotations

import inspect
import unittest

from sekuscan.agent.execute import _raw_request
from sekuscan.protocol.models import Directive


def _directive(url):
    return Directive(id="d1", kind="probe_http", url=url)


class TheReconstructionDescribesTheHopThatAnswered(unittest.TestCase):

    def test_a_redirected_probe_names_the_final_target(self):
        raw = _raw_request(_directive("http://t.test/a"),
                           {"method": "GET", "headers": {}},
                           url="http://t.test/b")
        self.assertIn("GET /b HTTP/1.1", raw)
        self.assertNotIn("GET /a ", raw)

    def test_the_host_follows_the_final_hop_too(self):
        """A redirect can cross hosts; the `Host` header has to move with it
        or the transcript is not replayable at all."""
        raw = _raw_request(_directive("http://first.test/a"),
                           {"method": "GET", "headers": {}},
                           url="http://second.test/b")
        self.assertIn("Host: second.test", raw)
        self.assertNotIn("first.test", raw)

    def test_the_query_of_the_final_hop_is_kept(self):
        raw = _raw_request(_directive("http://t.test/a?one=1"),
                           {"method": "GET", "headers": {}},
                           url="http://t.test/b?two=2")
        self.assertIn("GET /b?two=2 HTTP/1.1", raw)

    def test_without_a_redirect_nothing_changes(self):
        """The common case must be untouched - most probes never redirect."""
        raw = _raw_request(_directive("http://t.test/a?q=1"),
                           {"method": "POST", "headers": {}, "data": "x=1"})
        self.assertIn("POST /a?q=1 HTTP/1.1", raw)
        self.assertIn("Host: t.test", raw)
        self.assertTrue(raw.rstrip().endswith("x=1"))


class BothRedirectFollowingSitesPassIt(unittest.TestCase):
    """Wired at the call sites, which is the half that was missing - the
    parameter existing changes nothing on its own."""

    def test_the_sync_probe_passes_the_response_url(self):
        from sekuscan.agent import execute
        source = inspect.getsource(execute)
        self.assertIn("_raw_request(directive, kwargs, url=response.url)",
                      source)

    def test_the_batch_probe_passes_its_final_url(self):
        from sekuscan.agent import execute
        source = inspect.getsource(execute)
        self.assertIn("_raw_request(directive, final_kwargs, url=url)", source)


if __name__ == "__main__":
    unittest.main()
