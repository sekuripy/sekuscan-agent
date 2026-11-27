# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Every customer policy reaches every execution path.

The agent runs the browser in-process or in an isolated child (restartable
after a hang), and sends probes sequentially or through `AsyncProbeWorker`.
The customer's flags must mean the same thing on all of them, so this drives
the REAL construction code (`run_agent`, `_browser_executor`, the respawn) and
compares what each path actually built."""

from __future__ import annotations

from tests import pytest_style
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from sekuscan.agent import async_probe, browser, browser_worker, cli, execute, pacing
from sekuscan.agent import scope as scope_mod
from sekuscan.agent.browser import BrowserSession
from sekuscan.protocol.models import CaptureRules, Directive, Observation, ScopeRules

ORIGIN = "http://target.test/"
FLAGS = dict(
    risk=2, allow_destructive=True, allow_upload_cleanup=True,
    upload_cleanup_url="http://target.test/u", allow_authz_non_get=True,
    browser_sandbox="on", verify_target_tls=True, strict_egress=True,
    max_capture_bytes=4000, max_rps=7.0, deny=["/logout"], max_depth=3,
    client_cert="/c/c.pem", client_key="/c/k.pem",
    client_cert_origin="https://target.test")
BIG = CaptureRules(html_sample_bytes=10_000_000, body_sample_bytes=9_999_999)


class _Session(BrowserSession):
    started = []

    def start(self):
        _Session.started.append(self)
        self.sandboxed, self.login_failed, self.pre_login_states = True, None, []

    def stop(self):
        pass

    def drain_egress(self):
        return []

    def drain_network(self):
        return []

    drain_console = drain_network


class _Engine:
    batch_first = False

    def __init__(self, *_a, **_k):
        self.calls = 0

    def health(self):
        return {"engine_version": "t", "protocol_version": "t"}

    def create_run(self, _r):
        return SimpleNamespace(
            run_id="r", capture=BIG, safety_ceiling=50,
            scope=ScopeRules(origins=[ORIGIN], deny_substrings=["/logout"],
                             max_depth=3, allow_subdomains=False))

    def step(self, _o):
        self.calls += 1
        progress = SimpleNamespace(auth_state=None, phase="explore")
        stop = Directive(id="s", kind="stop", reason="done")
        if _Engine.batch_first and self.calls == 1:
            ds = [Directive(id="p%d" % i, kind="probe_http", url=ORIGIN + "x",
                            method="GET") for i in range(2)]
            return SimpleNamespace(directive=ds[0], directives=ds, progress=progress)
        return SimpleNamespace(directive=stop, directives=[stop], progress=progress)

    def complete(self, reason, artifacts=None):
        return SimpleNamespace(run_id="r")

    def fetch_text(self, path):
        return json.dumps({"summary": {}, "coverage": {}}) if path.endswith("json") else "<html/>"

    def close(self):
        pass


def _run(isolated, batch=False):
    """run_agent with every collaborator recorded. Returns what was built."""
    rec = {"policy": None, "guard": None, "rps": [], "init": None, "worker": None}
    _Session.started = []
    _Engine.batch_first = batch
    real_policy, real_guard = cli.LocalExecutionPolicy, cli.ScopeGuard

    def policy(**kw):
        rec["policy"] = kw
        return real_policy(**kw)

    def guard(*a, **kw):
        rec["guard"] = (a, kw)
        return real_guard(*a, **kw)

    class Handle:
        def __init__(self, init, cap_s=0):
            rec["init"] = init

        def start(self):
            return {"ready": True, "browser_sandbox": True, "login_failed": None,
                    "pre_login_states": []}

        def close(self):
            pass

    class Worker:
        def __init__(self, **kw):
            rec["worker"] = kw

        def start(self):
            pass

        def stop(self):
            pass

    with patch.object(cli, "BrowserSession", _Session), \
            patch.object(cli, "EngineClient", _Engine), \
            patch.object(cli, "LocalExecutionPolicy", policy), \
            patch.object(cli, "ScopeGuard", guard), \
            patch.object(cli, "BrowserWorkerHandle", Handle), \
            patch.object(cli, "AsyncProbeWorker", Worker), \
            patch.object(cli, "_run_probe_batch",
                         lambda *a, **k: Observation(seq=1)), \
            patch.object(pacing, "configure", lambda r: rec["rps"].append(r)), \
            patch.dict("os.environ",
                       {"SEKUSCAN_BROWSER_ISOLATION": "1" if isolated else "0"}):
        code = cli.run_agent(engine="http://127.0.0.1", api_key="k", target=ORIGIN,
                             scope=[ORIGIN], out=tempfile.mkdtemp(), quiet=True,
                             **FLAGS)
    assert code == 0
    rec["session"] = _Session.started[0] if _Session.started else None
    return rec


def _session_kw(s):
    return dict(scope_origins=s.scope_origins, credential_origins=s.credential_origins,
                deny_substrings=s.deny_substrings, allow_subdomains=s.allow_subdomains,
                max_depth=s.max_depth, browser_sandbox=s.browser_sandbox,
                strict_egress=s.strict_egress, ignore_https_errors=s.ignore_https_errors,
                capture=(s.capture.html_sample_bytes, s.capture.body_sample_bytes),
                client_cert=(s.client_cert_path, s.client_key_path, s.client_cert_origin))


EXPECTED = dict(
    scope_origins=[ORIGIN], credential_origins=["http://target.test"],
    deny_substrings=["/logout"], allow_subdomains=False, max_depth=3,
    browser_sandbox="on", strict_egress=True, ignore_https_errors=False,
    capture=(4000, 4000),
    client_cert=("/c/c.pem", "/c/k.pem", "https://target.test"))
POLICY = dict(risk=3,  # effective_risk folds the allow flags in
               allow_destructive=True, allow_upload_cleanup=True,
              upload_cleanup_url="http://target.test/u", allow_authz_non_get=True)


def test_in_process_session_gets_every_policy():
    rec = _run(isolated=False)
    assert _session_kw(rec["session"]) == EXPECTED
    assert rec["policy"] == POLICY and rec["rps"] == [7.0]
    assert rec["guard"][1]["operator_deny"] == ["/logout"]


def _child(init, rec):
    """Build the isolated child's executor from `init` exactly as the child
    process does, recording what it constructs."""
    pol, guards, rps = [], [], []
    real_policy, real_guard = execute.LocalExecutionPolicy, scope_mod.ScopeGuard
    _Session.started = []
    with patch.object(browser, "BrowserSession", _Session), \
            patch.object(execute, "LocalExecutionPolicy",
                         lambda **kw: (pol.append(kw), real_policy(**kw))[1]), \
            patch.object(scope_mod, "ScopeGuard",
                         lambda *a, **kw: (guards.append((a, kw)), real_guard(*a, **kw))[1]), \
            patch.object(pacing, "configure", rps.append):
        fns, _ = browser_worker._browser_executor(init)
    return fns, _Session.started[0], pol[0], guards[0], rps


def test_isolated_child_gets_every_policy_and_so_does_a_restarted_child():
    rec = _run(isolated=True)
    init = rec["init"]
    assert init["policy"] == POLICY and init["max_rps"] == 7.0
    assert init["operator_deny"] == ["/logout"]
    assert init["scope"]["deny_substrings"] == ["/logout"] and init["scope"]["max_depth"] == 3

    # the restart: a respawn must start the child from the SAME init
    handle = browser_worker.BrowserWorkerHandle(init, cap_s=1)
    started = []
    handle.start = lambda: started.append(handle.init)
    handle._kill = lambda: None
    handle._respawn()
    assert started == [init]

    for it in (init, started[0]):
        _, session, pol, (gargs, gkw), rps = _child(it, rec)
        assert _session_kw(session) == EXPECTED
        assert pol == POLICY and rps == [7.0]
        assert gkw["operator_deny"] == ["/logout"]
        assert gargs[0].deny_substrings == ["/logout"] and gargs[0].max_depth == 3
        assert gargs[0].origins == [ORIGIN]


def test_async_probe_worker_inherits_the_session_transport_policy_in_process():
    rec = _run(isolated=False, batch=True)
    assert rec["worker"] == rec["session"].async_worker_kwargs()
    assert rec["worker"]["ignore_https_errors"] is False
    assert rec["worker"]["client_certificates"][0]["certPath"] == "/c/c.pem"


def test_async_probe_worker_inherits_the_session_transport_policy_in_the_child():
    rec = _run(isolated=True)
    fns, session, *_ = _child(rec["init"], rec)
    built = []

    class W:
        def __init__(self, **kw):
            built.append(kw)

        def start(self):
            pass

    with patch.object(async_probe, "AsyncProbeWorker", W), \
            patch.object(cli, "_run_probe_batch", lambda *a, **k: Observation(seq=1)):
        fns["batch"]([{"id": "p", "kind": "probe_http", "url": ORIGIN, "method": "GET"}])
    assert built == [session.async_worker_kwargs()]
    assert built[0]["ignore_https_errors"] is False
    assert built[0]["client_certificates"]


def test_a_supplied_ca_makes_the_batch_transport_verify_like_the_sequential_one():
    # regression: the worker used `ignore_https_errors` (True by default) and
    # skipped verification the operator asked for with --ca-cert
    s = BrowserSession(ca_cert_path="/ca.pem")
    assert s.ignore_https_errors is True
    assert s.async_worker_kwargs()["ignore_https_errors"] is False


TestThePolicySurvivesEveryExecutionPath = pytest_style.collect(globals(), "TestThePolicySurvivesEveryExecutionPath", __doc__)
