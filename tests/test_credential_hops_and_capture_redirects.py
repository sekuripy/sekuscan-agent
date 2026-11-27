"""Operator credentials must not follow a redirect onto an in-scope origin
that is outside `credential_origins`; capture fetches must be scope-checked
per hop."""
import asyncio
from types import SimpleNamespace as NS
from unittest.mock import Mock

from sekuscan.agent.execute import _perform_capture, _probe_http
from sekuscan.protocol.models import CaptureFrom, CaptureRules, Directive


class Resp:
    def __init__(self, status, location=None, url="http://a.test/"):
        self.status, self.url = status, url
        self.headers = {"location": location} if location else {}

    def body(self):
        return b""


def _session(fetch):
    s = Mock()
    s.extra_headers = {"Authorization": "Bearer SECRET"}
    s.secondary_headers = {}  # BrowserSession always carries a dict
    s.cookies.return_value = []
    s.credentials_allowed = lambda u: u.startswith("http://a.test")
    s.context.request.fetch = fetch
    return s


def _guard():
    g = Mock()
    g.check.return_value = NS(allowed=True, reason="")
    return g


def test_probe_http_strips_credentials_on_non_credential_hop():
    seen = []

    def fetch(url, **kw):
        seen.append((url, dict(kw.get("headers") or {})))
        return Resp(302, "http://b.test/x", url) if url.startswith("http://a.test") \
            else Resp(200, None, url)

    d = Directive(id="d1", kind="probe_http", url="http://a.test/start",
                  headers={"X-Probe": "1"}, cookie_name="sid", cookie_value="v")
    _probe_http(_session(fetch), d, CaptureRules(), _guard())
    assert seen[0][1]["Authorization"] == "Bearer SECRET"
    assert len(seen) == 2
    hop = {k.lower() for k in seen[1][1]}
    assert "authorization" not in hop and "cookie" not in hop
    assert "x-probe" in hop


def test_async_hop_strips_credentials():
    from sekuscan.agent.async_probe import AsyncProbeWorker
    seen = []

    class Ctx:
        async def fetch(self, url, **kw):
            seen.append(dict(kw.get("headers") or {}))
            return Resp(302, "http://b.test/x", url) if len(seen) == 1 \
                else Resp(200, None, url)

    w = AsyncProbeWorker.__new__(AsyncProbeWorker)
    spec = {"directive_id": "d", "url": "http://a.test/s", "method": "GET",
            "headers": {"Authorization": "Bearer SECRET", "Cookie": "a=b"},
            "credential_headers": ["Authorization"], "max_redirects": 5}
    try:
        asyncio.run(w._one(Ctx(), spec, lambda u: (True, ""),
                           lambda u: u.startswith("http://a.test")))
    except Exception:
        pass  # response post-processing on the stub is irrelevant here
    assert "Authorization" in seen[0] and len(seen) == 2
    assert not ({"authorization", "cookie"} & {k.lower() for k in seen[1]})


def test_capture_fetch_is_scope_checked_per_hop():
    calls = []
    ctx = Mock()

    def fetch(url, **kw):
        calls.append((url, kw.get("max_redirects")))
        return Resp(302, "http://evil.test/t", url)

    ctx.fetch = fetch
    g = Mock()
    g.check.side_effect = lambda u: NS(allowed=u.startswith("http://a.test"),
                                       reason="off")
    out = _perform_capture(ctx, CaptureFrom(url="http://a.test/p", pattern="x"), g)
    assert calls == [("http://a.test/p", 0)]
    assert "refused" in out.action_result.error


def test_browser_preflight_treats_non_credential_hop_as_offscope():
    from sekuscan.agent.browser import BrowserSession
    from sekuscan.protocol import scoping

    stub = NS(REDIRECT_STATUSES=(301, 302), MAX_NAV_REDIRECTS=10,
              scope_origins=["http://a.test", "http://b.test"],
              deny_substrings=[], allow_subdomains=False, max_depth=None,
              extra_headers={"Authorization": "x"},
              credentials_allowed=lambda u: u.startswith("http://a.test"),
              _credential_headers_for=lambda u: {},
              context=Mock())
    first = Resp(302, "http://b.test/x")
    assert scoping  # in scope for the scan, outside credential_origins
    assert BrowserSession._offscope_hop(stub, first, "http://a.test/") \
        == "http://b.test/x"


# pytest-style module-level functions are invisible to `unittest discover`;
# see tests/pytest_style.py.
from tests import pytest_style  # noqa: E402

TestCredentialHopsAndCaptureRedirects = pytest_style.collect(globals(), "TestCredentialHopsAndCaptureRedirects", __doc__)
