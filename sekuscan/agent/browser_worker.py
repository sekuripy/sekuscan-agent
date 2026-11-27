# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Run the browser in a killable child process so a wedged Playwright call can
never hang the whole agent.

A greenlet blocked on an infinite epoll inside sync Playwright is unreachable
by any in-process timeout (SIGALRM, a read timeout) and is not reliably freed
by killing the browser subprocess either. The design that survives a target
that black-holes the connection (no RST/FIN, everything waits forever) is to
run the browser in a child process that the PARENT can kill on a wall-clock
timeout, while the parent itself never touches Playwright and so can never
wedge.

This module is the transport and the kill/respawn primitive, plus the real
"browser" executor that drives a `BrowserSession` inside the child. Both are
plugged in by name (`init["executor"]`); a dummy executor exercises the
kill/respawn behaviour with no Playwright involved.
Every Playwright/BrowserSession/execute/observe import lives INSIDE
`_browser_executor` (and the parent-side `rebuild_*` helpers), never at
module scope, so `import sekuscan.agent.browser_worker` alone never imports
Playwright - the parent must never be able to wedge on it.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import signal
import time
from typing import Any, Callable, Optional

# `spawn`, never `fork`: a forked child would inherit the parent's greenlet /
# asyncio state, which is exactly the corrupted-sync-Playwright situation this
# design exists to avoid. A spawned child is a clean interpreter.
_CTX = mp.get_context("spawn")

#: What `run_directive` returns instead of an observation when the child wedged
#: past the cap and was killed. The caller synthesises a load-error observation
#: from it, the same way the in-process SIGALRM path already does.
WEDGED = "__wedged__"


# --------------------------------------------------------------------------
# executors: init_config -> (handlers: {cmd: callable}, handshake_dict)
#
# `handlers` maps a wire `cmd` to the callable that serves it - "directive"
# (run(directive_dict, seq) -> observation_dict) always exists; "batch"
# (run_batch(directives_list, seq, phase) -> payload_dict) exists only for
# the real browser executor, since only it has a probe transport that
# benefits from concurrent dispatch.
#
# `handshake_dict` is merged into the `{"ready": True, ...}` message the
# worker sends the parent once, at startup - the few things the real
# executor's `session` knows before the first directive that the parent's
# run loop reads immediately (`login_failed`, `pre_login_states`, the proxy
# dict). The dummy executor has none, so it hands back `{}`.
# --------------------------------------------------------------------------
def _dummy_executor(init: dict[str, Any]) -> tuple[dict[str, Callable], dict]:
    """A Playwright-free executor for proving the primitive. A directive with
    kind `__hang__` blocks forever (the wedge); anything else echoes."""
    def run(directive: dict[str, Any], seq: int = 0) -> dict[str, Any]:
        if directive.get("kind") == "__hang__":
            while True:                       # the wedge the parent must survive
                time.sleep(3600)
        return {"echo": directive, "worker_pid": os.getpid()}
    return {"directive": run}, {}


def _browser_executor(init: dict[str, Any]) -> tuple[dict[str, Callable], dict]:
    """The real executor: a `BrowserSession` that lives and dies with
    this child, driven exactly the way `agent/cli.py`'s run loop drives an
    in-process one (see that module's per-directive block - this replicates
    it verbatim so behaviour is identical, not just similar).

    Every heavy import is lazy, here, inside the child - the parent-side
    `BrowserWorkerHandle`/`rebuild_*` helpers never need Playwright, and this
    is the one place in the whole module allowed to.
    """
    from ..protocol.models import CaptureRules, Directive, ScopeRules
    from .browser import BrowserSession
    from .execute import LocalExecutionPolicy, execute, load_secrets
    from .observe import observe_state
    from .scope import ScopeGuard

    # `execute._SECRETS` is a module global the parent filled with
    # `load_secrets()`; a spawned child starts with an empty one. Repopulate
    # it here so a `fill_submit` carrying `SECRET_PASSWORD` resolves to the
    # real value at fill time instead of "". Agent-local only: these came
    # over the parent->child pipe, never from the engine.
    load_secrets(init.get("secrets") or {})

    # `pacing` is module state too: the parent's `pacing.configure(max_rps)`
    # does not reach a spawned child, so it is configured again here and
    # `--max-rps` applies to browser navigation and in-child HTTP probes.
    from . import pacing
    pacing.configure(init.get("max_rps") or 0.0)

    session_kwargs = dict(init.get("session_kwargs") or {})
    session_kwargs["capture"] = CaptureRules(**(session_kwargs.get("capture") or {}))
    session = BrowserSession(**session_kwargs)
    session.start()

    guard = ScopeGuard(ScopeRules(**(init.get("scope") or {})),
                       operator_deny=init.get("operator_deny") or ())
    policy = LocalExecutionPolicy(**(init.get("policy") or {}))
    out_dir = init.get("out_dir") or "."

    handshake = {
        "login_failed": session.login_failed,
        "pre_login_states": [s.model_dump() for s in (session.pre_login_states or [])],
        "proxy_dict": session._proxy_dict(),
    }

    def run(directive_dict: dict[str, Any], seq: int = 0) -> dict[str, Any]:
        directive = Directive.model_validate(directive_dict)
        outcome = execute(session, directive, guard, session.capture, out_dir,
                          seq, policy)
        state = None
        if outcome.capture_state and directive.kind != "probe_http":
            state = observe_state(session, session.capture,
                                  http_status=outcome.http_status,
                                  requested_url=directive.url,
                                  load_error=outcome.load_error)
        network = session.drain_network()
        console = session.drain_console()
        return {
            "outcome": {
                "action_result": outcome.action_result.model_dump(),
                "probe": outcome.probe.model_dump() if outcome.probe else None,
                "http_status": outcome.http_status,
                "load_error": outcome.load_error,
                "capture_state": outcome.capture_state,
                "screenshots": list(outcome.screenshots),
            },
            "state": state.model_dump() if state is not None else None,
            "network": [e.model_dump() for e in network],
            "console": [c.model_dump() for c in console],
            "egress": session.drain_egress(),
            "safety_incidents": session.safety_incidents,
        }

    # Lazily built, reused across every batch this child ever serves - the
    # same lifetime rule `cli.py`'s own `async_worker` follows in-process
    # (started on the first batch, never per-batch).
    _async_worker_box: list[Any] = []

    class _Progress:
        """The two `progress` attributes `_run_probe_batch` reads - a real
        `StepResponse.progress` has more, but the batch path never touches
        them."""
        def __init__(self, phase: str) -> None:
            self.phase = phase
            self.auth_state = None

    def run_batch(directives_list: list[dict[str, Any]], seq: int = 0,
                  phase: str = "") -> dict[str, Any]:
        # Imported lazily, here: `cli.py` imports this module (for
        # `BrowserWorkerHandle`), so importing it back at module scope would
        # be circular - and it drags in the same Playwright-free-until-used
        # rule as everything else in this function. `Directive` is already
        # bound in the enclosing `_browser_executor` scope (see the top of
        # this function) - no need to import it twice.
        from .async_probe import AsyncProbeWorker
        from .cli import _run_probe_batch

        if not _async_worker_box:
            worker = AsyncProbeWorker(proxy=session._proxy_dict(),
                                      user_agent=session.user_agent)
            worker.start()
            _async_worker_box.append(worker)
        worker = _async_worker_box[0]

        directives = [Directive.model_validate(d) for d in directives_list]
        progress = _Progress(phase)
        artifacts: list[str] = []
        trace: list[dict] = []
        obs = _run_probe_batch(session, directives, guard, session.capture,
                               policy, worker, progress, seq, True,
                               artifacts, trace)
        return {
            "observation": obs.model_dump(),
            "trace": trace,
            "artifacts": artifacts,
            "egress": session.drain_egress(),
            "safety_incidents": session.safety_incidents,
        }

    return {"directive": run, "batch": run_batch}, handshake


_EXECUTORS: dict[str, Callable[[dict], tuple[dict[str, Callable], dict]]] = {
    "dummy": _dummy_executor,
    "browser": _browser_executor,
}


def _worker_main(conn: Any, init: dict[str, Any]) -> None:
    """Child entry point. Build the executor once, then serve directives until
    the parent says stop or closes the pipe."""
    # Do not let a stray SIGINT to the process group tear the worker down out
    # from under the parent's own lifecycle management.
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass
    try:
        handlers, handshake = _EXECUTORS[init["executor"]](init)
    except Exception as exc:                              # pragma: no cover
        try:
            conn.send({"fatal": "executor init failed: %r" % exc})
        except Exception:
            pass
        return
    # Handshake: tell the parent the worker is ready, plus whatever the
    # executor learned at start (the real executor reports login_failed /
    # pre_login_states / proxy_dict here; the dummy has nothing to add).
    try:
        ready = {"ready": True, "worker_pid": os.getpid()}
        if isinstance(handshake, dict):
            ready.update(handshake)
        conn.send(ready)
    except Exception:
        return
    while True:
        try:
            msg = conn.recv()
        except EOFError:
            return                              # parent gone
        except Exception:                       # pragma: no cover
            return
        if not isinstance(msg, dict) or msg.get("cmd") == "stop":
            return
        cmd = msg.get("cmd")
        handler = handlers.get(cmd)
        if handler is None:
            continue
        try:
            if cmd == "batch":
                result = handler(msg["directives"], msg.get("seq", 0),
                                 msg.get("phase", ""))
            else:
                result = handler(msg["directive"], msg.get("seq", 0))
            conn.send({"ok": result})
        except Exception as exc:
            try:
                conn.send({"error": "%s: %s" % (type(exc).__name__, exc)})
            except Exception:
                return


class BrowserWorkerHandle:
    """Parent-side handle to the browser child. `run_directive` is bounded: the
    child cannot make it wait longer than `cap_s`, because the wait is a plain
    `Connection.poll(timeout)` and the parent holds no browser fds."""

    def __init__(self, init: dict[str, Any], cap_s: float = 120.0):
        self.init = dict(init)
        self.cap_s = float(cap_s)
        self._proc: Optional[Any] = None
        self._conn: Optional[Any] = None
        #: How many times a wedge forced a respawn - surfaced so a run can stop
        #: pathological churn rather than respawn forever.
        self.respawns = 0
        self.ready_info: dict[str, Any] = {}

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> dict[str, Any]:
        parent_conn, child_conn = _CTX.Pipe(duplex=True)
        proc = _CTX.Process(target=_worker_main, args=(child_conn, self.init),
                            daemon=True, name="sekuscan-browser-worker")
        proc.start()
        child_conn.close()                      # the child owns its end now
        self._proc, self._conn = proc, parent_conn
        # Bound the handshake too: a child that cannot even start (a browser
        # that never launches) must not hang the parent here either.
        if not parent_conn.poll(self.cap_s):
            self._kill()
            raise RuntimeError("browser worker did not become ready in %ss"
                               % self.cap_s)
        info = parent_conn.recv()
        if not isinstance(info, dict) or not info.get("ready"):
            self._kill()
            raise RuntimeError("browser worker start failed: %r" % (info,))
        self.ready_info = info
        return info

    def _kill(self) -> None:
        proc, conn = self._proc, self._conn
        self._proc, self._conn = None, None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        if proc is not None and proc.is_alive():
            try:
                proc.kill()                     # SIGKILL - unconditional
            except Exception:
                pass
            proc.join(timeout=5.0)

    def _respawn(self) -> None:
        self._kill()
        self.respawns += 1
        self.start()

    def close(self) -> None:
        if self._proc is not None and self._proc.is_alive() and self._conn:
            try:
                self._conn.send({"cmd": "stop"})
            except Exception:
                pass
        self._kill()

    # -- the bounded round trip -------------------------------------------
    def _round_trip(self, msg: dict[str, Any]) -> Any:
        """Send `msg`; return the child's reply payload, or `WEDGED` if the
        child did not answer within `cap_s` (in which case it has been
        SIGKILLed and a fresh child spawned, ready for the next request).
        Shared by `run_directive` and `run_batch` - both are one send, one
        bounded `poll`, one recv; only the message shape differs."""
        if self._conn is None or self._proc is None or not self._proc.is_alive():
            self._respawn()
        try:
            self._conn.send(msg)
        except Exception:
            self._respawn()
            return WEDGED
        if not self._conn.poll(self.cap_s):
            # The child is wedged - it has not answered in the whole cap. Kill
            # it and stand a fresh one up; the caller treats this request as
            # abandoned and moves on.
            self._respawn()
            return WEDGED
        try:
            reply = self._conn.recv()
        except Exception:
            self._respawn()
            return WEDGED
        if isinstance(reply, dict) and "ok" in reply:
            return reply["ok"]
        # An executor error is a normal failed directive, not a wedge - report
        # it without killing the (healthy) child.
        return {"__error__": (reply or {}).get("error", "unknown worker error")}

    def run_directive(self, directive: dict[str, Any], seq: int = 0) -> Any:
        """Return the child's observation dict, or `WEDGED`. `seq` is the
        action sequence number the real executor needs for screenshot
        naming, same as `execute()`'s own `seq` argument."""
        return self._round_trip(
            {"cmd": "directive", "directive": directive, "seq": seq})

    def run_batch(self, directives: list[dict[str, Any]], seq: int = 0,
                  phase: str = "") -> Any:
        """Batch counterpart of `run_directive` - one child round trip that
        dispatches every `directives` entry concurrently (see
        `cli.py::_run_probe_batch`, which the child's `"browser"` executor
        calls directly). Returns `WEDGED` on the same terms."""
        return self._round_trip(
            {"cmd": "batch", "directives": directives, "seq": seq, "phase": phase})


# --------------------------------------------------------------------------
# parent-side reconstruction: the "browser" executor's observation payload
# (plain dicts, see `_browser_executor.run` above) back into the pydantic/
# dataclass shapes `agent/cli.py`'s run loop works with. Imports are
# lazy here too, for the same reason as `_browser_executor` itself - nothing
# about calling these should be able to import Playwright.
# --------------------------------------------------------------------------
def rebuild_outcome(payload: dict[str, Any]) -> Any:
    from ..protocol.models import ActionResult, ProbeResponse
    from .execute import Outcome

    probe = payload.get("probe")
    return Outcome(
        action_result=ActionResult.model_validate(payload["action_result"]),
        probe=ProbeResponse.model_validate(probe) if probe else None,
        http_status=payload.get("http_status"),
        load_error=payload.get("load_error"),
        capture_state=payload.get("capture_state", True),
        screenshots=list(payload.get("screenshots") or []),
    )


def rebuild_state(payload: Optional[dict[str, Any]]) -> Any:
    if payload is None:
        return None
    from ..protocol.models import StateSnapshot
    return StateSnapshot.model_validate(payload)


def rebuild_network(payload: list[dict[str, Any]]) -> list[Any]:
    from ..protocol.models import NetworkEvent
    return [NetworkEvent.model_validate(e) for e in (payload or [])]


def rebuild_console(payload: list[dict[str, Any]]) -> list[Any]:
    from ..protocol.models import ConsoleEvent
    return [ConsoleEvent.model_validate(e) for e in (payload or [])]


def rebuild_batch_observation(payload: dict[str, Any]) -> Any:
    """The `"batch"` handler's payload carries one already-shaped
    `Observation` (built by `_run_probe_batch` inside the child) rather than
    the outcome/state/network/console quartet `run_directive` returns -
    round-trip it back into the pydantic model `cli.py`'s run loop works
    with."""
    from ..protocol.models import Observation
    return Observation.model_validate(payload["observation"])
