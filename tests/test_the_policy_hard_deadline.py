# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""--max-seconds is a real wall-clock limit: an engine step that blocks forever
still ends the process by N + margin, with the documented exit code and a
trace saying why."""

from __future__ import annotations

from tests import pytest_style
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time

from sekuscan.agent import ci
from sekuscan.agent.cli import MAX_SECONDS_HELP, MAX_SECONDS_HARD_MARGIN_S

SCRIPT = textwrap.dedent("""
    import sys, time
    from types import SimpleNamespace
    from unittest.mock import patch
    from sekuscan.agent import cli
    from sekuscan.protocol.models import CaptureRules, ScopeRules

    class Browser:
        def __init__(self, **kw): self.safety_incidents = 0
        def start(self): pass
        def stop(self): pass
        def drain_egress(self): return []

    class Engine:
        def __init__(self, *a, **k): pass
        def health(self): return {"engine_version": "t", "protocol_version": "t"}
        def create_run(self, _r):
            return SimpleNamespace(run_id="r", scope=ScopeRules(origins=["http://t.test/"]),
                                   capture=CaptureRules(), safety_ceiling=50)
        def step(self, _o):
            time.sleep(3600)          # a blocked engine request
        def close(self): pass

    with patch.object(cli, "BrowserSession", Browser), patch.object(cli, "EngineClient", Engine):
        cli.run_agent(engine="http://127.0.0.1", api_key="k", target="http://t.test/",
                      scope=["http://t.test/"], out=sys.argv[1], quiet=True, max_seconds=2)
""")


def test_a_blocked_engine_step_ends_by_n_plus_margin_with_the_documented_code():
    out = tempfile.mkdtemp()
    env = dict(os.environ, SEKUSCAN_BROWSER_ISOLATION="0",
               SEKUSCAN_MAX_SECONDS_HARD_MARGIN_S="2")
    t0 = time.monotonic()
    proc = subprocess.run([sys.executable, "-c", SCRIPT, out], env=env,
                          capture_output=True, text=True, timeout=60)
    took = time.monotonic() - t0
    assert proc.returncode == ci.EXIT_WALL_CLOCK == 5, proc.stderr[-800:]
    assert took < 25          # N=2 + margin=2 + interpreter start, not 3600
    with open(os.path.join(out, "agent-trace.json")) as fh:
        assert "hard deadline" in json.load(fh)["stop_reason"]


def test_the_help_states_soft_and_hard():
    assert "N+%d" % MAX_SECONDS_HARD_MARGIN_S in MAX_SECONDS_HELP
    assert "code %d" % ci.EXIT_WALL_CLOCK in MAX_SECONDS_HELP


TestThePolicyHardDeadline = pytest_style.collect(globals(), "TestThePolicyHardDeadline", __doc__)
