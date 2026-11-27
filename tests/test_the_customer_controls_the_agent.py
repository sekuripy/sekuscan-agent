# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Customer-side controls over an agent that obeys a possibly hostile engine:
--version, the risk wording, --browser-sandbox, --verify-target-tls,
--strict-egress, --max-capture-bytes and the local --max-seconds deadline."""

import contextlib
import io
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests import pytest_style

from sekuscan.agent import cli
from sekuscan.agent.browser import BrowserSession, launch_browser
from sekuscan.protocol.models import (
    AGENT_VERSION, PROTOCOL_VERSION, ActionResult, CaptureRules, Directive, ScopeRules)


# --- 1. --version -----------------------------------------------------------

def _version_output(typer_on):
    out = io.StringIO()
    with patch.object(cli, "typer", cli.typer if typer_on else None), \
            contextlib.redirect_stdout(out):
        try:
            code = cli.main(["--version"])
        except SystemExit as exc:
            code = exc.code
    assert code in (0, None)
    return out.getvalue().strip()


def test_version_prints_agent_and_protocol_and_exits_zero():
    want = "sekuscan-agent %s (protocol %s)" % (AGENT_VERSION, PROTOCOL_VERSION)
    assert _version_output(True) == want      # typer parser
    assert _version_output(False) == want     # argparse fallback


# --- 2. risk wording ---------------------------------------------------------

def test_level_one_is_not_called_read_only():
    assert "read-only" not in cli.RISK_HELP.split("2 observed")[0].replace(
        "engine-declared read-only test inputs", "")
    assert "1 read-only" not in cli.RISK_HELP
    assert "no uploads, no DELETE" in cli.RISK_HELP


# --- 3. --browser-sandbox ----------------------------------------------------

class _Launcher:
    def __init__(self, sandbox_works):
        self.sandbox_works, self.calls = sandbox_works, []

    def launch(self, **kw):
        self.calls.append(kw)
        if kw.get("chromium_sandbox") and not self.sandbox_works:
            raise RuntimeError("Chromium sandboxing failed!")
        return object()


def test_sandbox_auto_falls_back_with_one_loud_warning():
    lau, err = _Launcher(sandbox_works=False), io.StringIO()
    with contextlib.redirect_stderr(err):
        _, sandboxed = launch_browser(lau, "chromium", "auto", headless=True)
    assert sandboxed is False
    assert [c.get("chromium_sandbox") for c in lau.calls] == [True, None]
    assert err.getvalue().count("browser sandbox unavailable") == 1


def test_sandbox_auto_uses_it_when_it_works():
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        _, sandboxed = launch_browser(_Launcher(True), "chromium", "auto")
    assert sandboxed is True and err.getvalue() == ""


def test_sandbox_on_is_fatal_and_names_the_fix():
    lau = _Launcher(sandbox_works=False)
    with pytest.raises(RuntimeError) as exc:
        launch_browser(lau, "chromium", "on")
    assert "apparmor_restrict_unprivileged_userns" in str(exc.value)
    assert "--browser-sandbox off" in str(exc.value)
    assert len(lau.calls) == 1


def test_sandbox_off_never_asks_for_it():
    lau = _Launcher(sandbox_works=True)
    _, sandboxed = launch_browser(lau, "chromium", "off")
    assert sandboxed is False and "chromium_sandbox" not in lau.calls[0]


def test_an_unrelated_launch_failure_is_not_swallowed_by_auto():
    class Broken:
        def launch(self, **kw):
            raise RuntimeError("executable doesn't exist")
    with pytest.raises(RuntimeError, match="executable"):
        launch_browser(Broken(), "chromium", "auto")


# --- 4. --verify-target-tls --------------------------------------------------

def test_verify_target_tls_turns_browser_verification_on_only_when_asked():
    assert BrowserSession().ignore_https_errors is True
    on = BrowserSession(verify_target_tls=True)
    assert on.ignore_https_errors is False and on.api_ignore_https_errors is False


# --- 5. --strict-egress ------------------------------------------------------

class _Route:
    def __init__(self):
        self.verdict = None

    def abort(self):
        self.verdict = "abort"

    def continue_(self, **_kw):
        self.verdict = "continue"

    # strict mode fetches every in-scope request itself (redirect walk)
    def fetch(self, **_kw):
        return SimpleNamespace(status=200, headers={})

    def fulfill(self, **_kw):
        self.verdict = "fulfill"


class _Context:
    def __init__(self, websockets=True):
        self.handler = self.ws_handler = None
        if websockets:
            self.route_web_socket = lambda _p, h: setattr(self, "ws_handler", h)

    def route(self, _pattern, handler):
        self.handler = handler


def _guarded(strict):
    s = BrowserSession(scope_origins=["http://target.test/"],
                       strict_egress=strict)
    s.egress, s.safety_incidents = [], 0
    s.context = _Context()
    s._install_egress_guard()
    return s


def _fetch(session, url, kind="image"):
    req = SimpleNamespace(url=url, method="GET", headers={}, resource_type=kind,
                          post_data_buffer=None,
                          is_navigation_request=lambda: kind == "document")
    route = _Route()
    session.context.handler(route, req)
    return route.verdict


def test_strict_egress_aborts_offscope_and_continues_inscope():
    s = _guarded(strict=True)
    assert _fetch(s, "http://cdn.evil.test/p.png") == "abort"
    assert _fetch(s, "http://target.test/p.png") == "fulfill"  # walked, then served
    assert s.egress[0]["blocked"] is True and s.safety_incidents == 0


def test_without_strict_egress_offscope_subresources_still_load():
    assert _fetch(_guarded(strict=False), "http://cdn.evil.test/p.png") == "continue"


def test_strict_egress_blocks_service_workers_and_closes_offscope_websockets():
    s = _guarded(strict=True)
    assert s._network_context_kwargs()["service_workers"] == "block"
    assert "service_workers" not in _guarded(strict=False)._network_context_kwargs()
    closed = []

    def ws(url):
        return SimpleNamespace(url=url, close=lambda: closed.append(url),
                               connect_to_server=lambda: closed.append("ok"))
    s.context.ws_handler(ws("ws://evil.test/s"))
    s.context.ws_handler(ws("ws://target.test/s"))
    assert closed == ["ws://evil.test/s", "ok"]


# --- 6/7. the run loop: capture ceiling and wall-clock limit -----------------

def _drive(capture, max_seconds=None, max_capture_bytes=None, clock=None, **extra):
    """Run the real loop against a fake engine that never stops by itself."""
    seen = {}

    class Browser:
        safety_incidents = 0
        sandboxed = False
        ignore_https_errors = True

        def __init__(self, **kw):
            seen["browser_kw"] = kw

        def start(self):
            return self

        def stop(self):
            pass

        def drain_network(self):
            return []

        drain_console = drain_egress = drain_network

    class Engine:
        def __init__(self, *_a, **_k):
            pass

        def health(self):
            return {"engine_version": "t", "protocol_version": "t"}

        def create_run(self, _r):
            return SimpleNamespace(
                run_id="run-test", scope=ScopeRules(origins=["http://target.test/"]),
                capture=capture, safety_ceiling=50)

        def step(self, _obs):
            return SimpleNamespace(
                directive=Directive(id="d", kind="navigate", url="http://target.test/x"),
                progress=SimpleNamespace(auth_state=None, phase="explore"))

        def complete(self, reason, artifacts=None):
            seen["reason"] = reason
            return SimpleNamespace(run_id="run-test")

        def fetch_text(self, path):
            return (json.dumps({"summary": {}, "coverage": {}})
                    if path.endswith("report.json") else "<html></html>")

        def close(self):
            pass

    def execute_action(*_a, **_kw):
        return SimpleNamespace(
            capture_state=False, http_status=200, load_error=None,
            screenshots=[], probe=None,
            action_result=ActionResult(directive_id="d", kind="navigate", ok=True))

    out = tempfile.mkdtemp()
    with patch.object(cli, "BrowserSession", Browser), \
            patch.object(cli, "EngineClient", Engine), \
            patch.object(cli, "execute", execute_action), \
            patch.dict("os.environ", {"SEKUSCAN_BROWSER_ISOLATION": "0"}):
        if clock:
            patch_clock = patch.object(cli.time, "monotonic", clock)
        else:
            patch_clock = patch.object(cli, "MAX_SECONDS_GRACE_S", 30)
        with patch_clock:
            code = cli.run_agent(
                engine="http://127.0.0.1", api_key="k", target="http://target.test/",
                scope=["http://target.test/"], out=out, quiet=True,
                max_seconds=max_seconds, max_capture_bytes=max_capture_bytes, **extra)
    with open(out + "/agent-trace.json") as fh:
        seen["trace"] = json.load(fh)
    seen["code"] = code
    return seen


def test_the_engine_can_lower_capture_sizes_but_never_raise_them():
    big = CaptureRules(html_sample_bytes=10_000_000, text_sample_bytes=50,
                       body_sample_bytes=9_999_999)
    got = _drive(big, max_capture_bytes=4000, max_steps=2)["browser_kw"]["capture"]
    assert (got.html_sample_bytes, got.text_sample_bytes, got.body_sample_bytes) == (4000, 50, 4000)


def test_without_the_flag_the_engine_value_stands():
    big = CaptureRules(html_sample_bytes=10_000_000)
    got = _drive(big, max_steps=2)["browser_kw"]["capture"]
    assert got.html_sample_bytes == 10_000_000


def test_flags_reach_the_session_and_the_trace_records_the_sandbox():
    seen = _drive(CaptureRules(), max_steps=2, strict_egress=True,
                  verify_target_tls=True, browser_sandbox="off")
    kw = seen["browser_kw"]
    assert kw["strict_egress"] is True and kw["ignore_https_errors"] is False
    assert kw["browser_sandbox"] == "off"
    assert seen["trace"]["browser_sandbox"] is False


def test_max_seconds_ends_the_run_locally_with_a_report():
    ticks = iter(range(0, 10_000, 40))       # each look at the clock is 40s later
    seen = _drive(CaptureRules(), max_seconds=60, clock=lambda: next(ticks))
    assert seen["reason"].startswith("wall-time budget")
    assert seen["code"] == 0 and seen["trace"]["stop_reason"].startswith("wall-time budget")


def test_the_terminal_is_not_flooded_with_one_line_per_engine_request():
    import logging
    logging.getLogger("httpx").setLevel(logging.NOTSET)
    _drive(CaptureRules())
    assert logging.getLogger("httpx").level >= logging.WARNING


def test_strict_egress_fails_closed_without_websocket_interception():
    s = BrowserSession(scope_origins=["http://target.test/"], strict_egress=True)
    s.egress, s.safety_incidents = [], 0
    s.context = _Context(websockets=False)
    with pytest.raises(RuntimeError, match="route_web_socket"):
        s._install_egress_guard()


def test_browser_sandbox_on_refuses_a_non_chromium_browser():
    class Lau:
        def launch(self, **_kw):
            raise AssertionError("must not launch")
    with pytest.raises(RuntimeError, match="chromium"):
        launch_browser(Lau(), "firefox", "on")
    for mode in ("auto", "off"):
        class L2:
            def launch(self, **_kw):
                return object()
        assert launch_browser(L2(), "firefox", mode)[1] is False


TestTheCustomerControlsTheAgent = pytest_style.collect(
    globals(), "TestTheCustomerControlsTheAgent", __doc__)
