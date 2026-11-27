# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""sekuscan-agent - thin local executor/observer.

    export SEKUSCAN_API_KEY=...
    sekuscan-agent run --engine https://api.sekuscan.com \
        --target https://app.example.com/ --out ./report

The run budget is unlimited by default: it ends when there is nothing left
worth testing. `--max-actions N` is an explicit operator limit. The observer's
per-page control enumeration is also unlimited by default; use
`--max-discovered-actions N` only when you deliberately want that bound.

The agent does not decide what to test. It loops:
send observation -> receive directive -> execute -> observe.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import pathlib
import re
import signal
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Optional

from pydantic import ValidationError

try:
    import typer
except ImportError:  # pragma: no cover
    typer = None

from ..protocol.models import (
    AGENT_VERSION,
    PIPE_HOLD,
    PROTOCOL_VERSION,
    SECRET_MFA_CODE,
    SECRET_PASSWORD,
    ActionResult,
    AgentCapabilities,
    BatchedResult,
    Credentials,
    Observation,
    OperatorDatum,
    RunCreateRequest,
    ScopeRules,
    StateSnapshot,
    StepResponse,
    effective_risk,
)
from . import ci
from . import relay as relaymod
from .api import (READ_CEILING_S, EngineClient, EngineError, trust_context,
                   EngineUnreachable)
from .async_probe import AsyncProbeWorker
from .browser import DEFAULT_USER_AGENT, BrowserSession, launch_browser
# `browser_worker` (isolated mode) never imports Playwright at its own module
# scope either, so importing its names here is as safe as the `BrowserSession`
# import above.
from .browser_worker import (
    WEDGED,
    BrowserWorkerHandle,
    rebuild_batch_observation,
    rebuild_console,
    rebuild_network,
    rebuild_outcome,
    rebuild_state,
)
from .execute import (LocalExecutionPolicy, Outcome, execute, execute_batch,
                      load_secrets, probe_from_network)
from .observe import observe_state
from . import pacing
from . import redaction
from . import settle
from .scope import ScopeGuard

log = logging.getLogger("sekuscan.agent")

# A dropped connection or an engine that is momentarily slow to answer must
# not discard hours of scan progress on the first blip. Only EngineUnreachable
# (no answer at all) is retried; a 4xx/5xx application rejection (bad token,
# unknown run, malformed body) will never succeed on retry and fails on the
# first attempt.
#
# The schedule is long enough to ride out a lost network link, not only a
# blip: it backs off to a minute and totals about eight minutes, inside the
# no-progress watchdog (`READ_CEILING_S` + 210 s), so a run that truly lost
# its engine still ends on its own.
_ENGINE_RETRY_DELAYS_S = (2.0, 5.0, 10.0, 20.0, 30.0, 45.0,
                         60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0)


def _restrict(path: str, mode: int) -> None:
    """Best-effort chmod - permission hardening must never crash the agent."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _engine_url_is_safe(engine: str) -> bool:
    """https, or plaintext http only to loopback."""
    from urllib.parse import urlparse

    parsed = urlparse(engine)
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http":
        return False
    import ipaddress

    host = (parsed.hostname or "").lower()
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _origin_only(url: str) -> str:
    """scheme://host[:port], no path - the whole origin a credential belongs to."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _pipe_split(resp: StepResponse) -> list[StepResponse]:
    """One engine answer as the batches to run, in order: its own, then the
    one it sent `ahead`. A pipeline hold carries nothing to run."""
    if resp.directive.kind == "wait" \
            and getattr(resp.directive, "reason", None) == PIPE_HOLD:
        return []
    ahead = getattr(resp, "ahead", None)
    if not ahead:
        return [resp]
    return [resp.model_copy(update={"ahead": []}),
            resp.model_copy(update={"directive": ahead[0], "directives": ahead,
                                    "ahead": []})]


def _call_with_retry(fn: Any, *args: Any, **kwargs: Any) -> Any:
    for attempt in range(len(_ENGINE_RETRY_DELAYS_S) + 1):
        try:
            return fn(*args, **kwargs)
        except EngineUnreachable:
            if attempt == len(_ENGINE_RETRY_DELAYS_S):
                raise
            delay = _ENGINE_RETRY_DELAYS_S[attempt]
            log.warning("engine unreachable (attempt %d/%d), retrying in %.0fs",
                       attempt + 1, len(_ENGINE_RETRY_DELAYS_S) + 1, delay)
            time.sleep(delay)


def _template_values(template: Any) -> list[str]:
    """Every string in an operator's login template (JSON text or object):
    a tenant code or static token written there is a credential too."""
    if isinstance(template, str):
        try:
            template = json.loads(template)
        except ValueError:
            template = template.strip() or None
    if isinstance(template, dict):
        return [v for value in template.values() for v in _template_values(value)]
    if isinstance(template, list):
        return [v for value in template for v in _template_values(value)]
    if template is None or isinstance(template, bool) \
            or re.fullmatch(r"\{\w+\}", str(template)):  # a placeholder
        return []
    return [str(template)]


class _CleanStream:
    """A text stream that shows terminal control characters escaped."""

    def __init__(self, stream: Any):
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(text.translate(_CONTROL))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _clean_terminal_output(function: Any) -> Any:
    """Run `function` with stdout and stderr escaping control characters:
    much of what a run prints (and logs) comes from the engine or the target."""
    import functools

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        saved = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = _CleanStream(saved[0]), _CleanStream(saved[1])
        try:
            return function(*args, **kwargs)
        finally:
            sys.stdout, sys.stderr = saved
    return wrapper


@_clean_terminal_output
def stop_run_cli(engine: str, api_key: str, run_id: str, reason: str = "",
                 engine_timeout: Optional[float] = None) -> int:
    """Ask a run to stop gracefully, by id - no process access required."""
    if not _engine_url_is_safe(engine):
        print("error: --engine must be https:// (plain http only to loopback)", file=sys.stderr)
        return ci.EXIT_USAGE
    with EngineClient(engine, api_key, **_engine_timeout_kw(engine_timeout)) as client:
        try:
            resp = _call_with_retry(client.stop_run, run_id, reason)
        except EngineError as exc:
            print(f"error: stop failed: {exc}", file=sys.stderr)
            return ci.EXIT_ERROR
    print(f"run {run_id}: {resp.status}")
    return ci.EXIT_OK


# How long one directive may take before the agent gives up on it. Generous
# against the deadlines inside `execute()` (a click allows 3s, a load-state
# wait 3s), so this only fires when something has escaped all of them. For
# example, `page.evaluate` takes no timeout in Playwright's API and never
# returns if a navigation destroys the execution context. Without this bound
# one such page would stall a scan forever, with no error and no report.
ACTION_DEADLINE_S = 90

# A concurrent probe batch runs on `async_probe.AsyncProbeWorker`'s own
# dedicated thread, never the main one. `_action_deadline`'s SIGALRM below is
# armed only on the main thread (Python delivers signals to the main thread
# only), so it does not cover batch dispatch. This is the batch's own deadline
# instead; `_ProgressWatchdog` remains the coarser last-resort net. Sized
# generously above the ordinary per-probe timeout (12s default,
# `directive.timeout_ms`), since concurrent dispatch should cost about one
# probe's worth of wall time regardless of batch size.
BATCH_TIMEOUT_S = 60.0

# A last-resort wall clock, in a thread, that kills the process if no step has
# completed in this long.
#
# `_action_deadline` above is the first line of defence and is not sufficient.
# It raises from a SIGALRM handler, and Python delivers signals on the main
# thread at a bytecode boundary, which a Playwright sync call driven by
# greenlets may not reach while it is blocked. A daemon thread is not waiting
# on anything, so it always gets to run. It cannot safely unwind the
# unreachable main thread, so it reports why and exits hard: the run is
# already lost at that point, and the only question is how quickly the process
# ends.
# Derived, not chosen. A watchdog whose deadline is shorter than the longest
# legitimate step would kill healthy runs: a single step can properly take a
# full engine read timeout plus the action deadline. The margin is slack for
# process scheduling. Keeping this expressed as a sum means a later change to
# either bound moves it too.
NO_PROGRESS_DEADLINE_S = int(READ_CEILING_S) + ACTION_DEADLINE_S + 120

#: Run-level safety breaker: how many refused out-of-scope events end the run
#: outright. Scope enforcement is per-request; this additionally notices that
#: it has been firing repeatedly. An application that keeps trying to send the
#: browser somewhere it was told not to go is either misconfigured or hostile,
#: and the right response is to stop the engagement rather than keep refusing
#: quietly. The value sits well above what ordinary scans produce, so the
#: breaker does not trip on normal traffic.
DEFAULT_MAX_SAFETY_INCIDENTS = 50


def _isolation_enabled() -> bool:
    """`SEKUSCAN_BROWSER_ISOLATION` -> route the browser through a killable child
    process (`browser_worker.py`) instead of driving it in this one.

    Default ON: a single wedged sync-Playwright call (for example a form
    submit to an endpoint that black-holes the connection) would otherwise
    hang the whole in-process agent, and cannot be recovered in-process
    (SIGALRM cannot reach a blocked greenlet). A killable child can be
    recovered. Set the var to 0/false/no to force the in-process path, e.g.
    when debugging."""
    return os.environ.get("SEKUSCAN_BROWSER_ISOLATION", "1").strip().lower() \
        not in ("", "0", "false", "no")


# The isolated per-directive wall-clock cap: how long the parent waits on one
# `BrowserWorkerHandle.run_directive`/`run_batch` round trip before deciding
# the child is wedged, killing it and respawning. It is a backstop for the
# case the child's own `ACTION_DEADLINE_S` SIGALRM cannot catch, so it must
# sit above the slowest legitimate round trip, or it kills healthy-but-slow
# work. A round trip covers one of a single action (bounded by
# `ACTION_DEADLINE_S`) or a probe batch (bounded by `BATCH_TIMEOUT_S`), plus
# post-action observation, settling and IPC overhead.
PER_DIRECTIVE_CAP_S = int(os.environ.get("SEKUSCAN_DIRECTIVE_CAP_S", "130"))


class _ProgressWatchdog:
    """Kill the process when the step loop stops advancing.

    See `NO_PROGRESS_DEADLINE_S`. `beat()` is called once per completed step;
    if the gap between beats exceeds the deadline the watchdog writes a reason
    and exits the process, because by then the main thread cannot be recovered.
    """

    #: `time.monotonic`, never `time.time`: a wall clock can jump (NTP
    #: correction, manual change), which would make a healthy scan look
    #: stalled - and the response to a stall is `os._exit()` - or hide a real
    #: stall.
    _clock = staticmethod(time.monotonic)

    def __init__(self, seconds: float = NO_PROGRESS_DEADLINE_S,
                 on_stall: Optional[Any] = None,
                 hard_deadline: Optional[float] = None,
                 on_hard: Optional[Any] = None):
        # `hard_deadline` is an absolute `_clock()` time (the `--max-seconds`
        # backstop): same thread, same os._exit, a different exit code.
        self.hard_deadline = hard_deadline
        self._on_hard = on_hard
        self.seconds = float(seconds)
        self._last = self._clock()
        self._stop = threading.Event()
        self._on_stall = on_stall
        self._thread: Optional[threading.Thread] = None

    def beat(self) -> None:
        self._last = self._clock()

    def start(self) -> "_ProgressWatchdog":
        if self.seconds <= 0 and self.hard_deadline is None:
            return self
        self._thread = threading.Thread(target=self._watch, daemon=True,
                                        name="sekuscan-progress-watchdog")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def stalled_for(self) -> float:
        return self._clock() - self._last

    def _tick(self) -> float:
        tick = 5.0
        if self.seconds > 0:
            tick = min(tick, self.seconds / 4.0)
        if self.hard_deadline is not None:
            tick = min(tick, max(0.05, (self.hard_deadline - self._clock()) / 4.0))
        return max(0.05, tick)

    def _hard_exit(self) -> None:
        message = ("--max-seconds hard deadline reached - the run did not "
                   "wind down in time; abandoning it")
        log.error(message)
        try:
            if self._on_hard is not None:
                self._on_hard(message)
        except Exception:
            pass
        sys.stderr.write("\n!! %s\n" % message)
        sys.stderr.flush()
        os._exit(ci.EXIT_WALL_CLOCK)

    def _watch(self) -> None:
        while not self._stop.wait(self._tick()):
            if (self.hard_deadline is not None
                    and self._clock() >= self.hard_deadline):
                self._hard_exit()
            if self.seconds <= 0:
                continue
            sample = self.stalled_for()
            try:
                stalled = float(sample)
            except (TypeError, ValueError):
                # An unmeasurable interval is not evidence of a stall.
                continue
            if stalled < self.seconds:
                continue
            message = ("agent made no progress for %.0fs - abandoning the run. "
                       "The step loop is wedged somewhere neither the "
                       "%ds action deadline nor the engine read timeout can "
                       "reach (see NO_PROGRESS_DEADLINE_S)."
                       % (stalled, ACTION_DEADLINE_S))
            log.error(message)
            try:
                if self._on_stall is not None:
                    self._on_stall(message)
            except Exception:
                pass
            sys.stderr.write("\n!! %s\n" % message)
            sys.stderr.flush()
            os._exit(ci.EXIT_ERROR if hasattr(ci, "EXIT_ERROR") else 1)


def _bypassed(host: str, bypass: Optional[str]) -> bool:
    for rule in (bypass or "").split(","):
        rule = rule.strip().lower().lstrip("*").lstrip(".")
        if rule and (host == rule or host.endswith("." + rule)):
            return True
    return False


def _engine_link(engine: str, proxy_server: Optional[str],
                 proxy_username: Optional[str], proxy_password: Optional[str],
                 proxy_auth_scheme: str, proxy_bypass: Optional[str],
                 ca_cert: Optional[str]) -> dict:
    """How the agent reaches the ENGINE from inside a corporate network.

    The engine is one HTTPS origin answering short POSTs. It follows the
    scan's proxy (unless `--proxy-bypass` names the engine host),
    authenticates through the same local relay the browser uses - contained to
    the engine's origin alone - and verifies against the OS trust store plus
    `--ca-cert`.
    """
    from urllib.parse import urlsplit, urlunsplit

    link: dict = {"verify": trust_context(ca_cert)}
    parts = urlsplit(engine)
    host = (parts.hostname or "").lower()
    if not proxy_server or _bypassed(host, proxy_bypass):
        return link            # direct, or whatever HTTPS_PROXY says
    spec = relaymod.parse_upstream(
        _encode_proxy_auth_scheme(proxy_server, proxy_auth_scheme),
        proxy_username, proxy_password)
    if relaymod.needs_relay(spec):
        relay = relaymod.Relay(spec, ScopeRules(origins=[urlunsplit(
            (parts.scheme, parts.netloc, "", "", ""))]))
        relay_host, relay_port = relay.start()
        link["proxy"] = "http://%s:%d" % (relay_host, relay_port)
        return link
    proxy = urlsplit(proxy_server)
    auth = ""
    if proxy_username:
        from urllib.parse import quote
        auth = "%s:%s@" % (quote(proxy_username, safe=""),
                           quote(proxy_password or "", safe=""))
    link["proxy"] = urlunsplit((proxy.scheme, auth + proxy.netloc,
                                proxy.path, "", ""))
    return link


def _engine_timeout_kw(value: Optional[float]) -> dict:
    """Pass the flag through only when the operator actually gave one.

    `EngineClient` distinguishes "said nothing" - which selects a bounded
    default - from an explicit `None`, which means genuinely unlimited.
    Forwarding our own `None` unconditionally would turn the first into the
    second.
    """
    return {} if value is None else {"timeout": value}


class _ActionTimeout(BaseException):
    """One directive outstayed its welcome.

    `BaseException`, not `Exception`, for the same reason `KeyboardInterrupt`
    is: this is raised from a SIGALRM handler into whatever code happens to be
    running, and that code contains broad `except Exception:` handlers that
    tolerate an un-fillable field or an un-clickable control. Deriving from
    `Exception` would let the deadline be caught there and treated as "this
    field did not work", so the limit could never abandon a long loop inside a
    browser action.

    Every Playwright call already carries its own short timeout; what needs
    bounding is the loop over them, and this is that bound.
    """


@contextlib.contextmanager
def _action_deadline(directive: Any):
    """Abandon a directive that has escaped every timeout inside it.

    SIGALRM rather than a worker thread, because Playwright's sync API is bound
    to the thread that created the browser and cannot be driven from another
    one. The signal interrupts the blocking wait, which is exactly what another
    thread could not do.

    Armed only on the main thread of a POSIX host; elsewhere it is a no-op and
    directives are not bounded by this mechanism.
    """
    armed = False
    previous = None
    if (hasattr(signal, "SIGALRM")
            and threading.current_thread() is threading.main_thread()):
        def _fire(_signum: int, _frame: Any) -> None:
            raise _ActionTimeout(getattr(directive, "id", "?"))

        previous = signal.signal(signal.SIGALRM, _fire)
        signal.alarm(ACTION_DEADLINE_S)
        armed = True
    try:
        yield
    finally:
        if armed:
            signal.alarm(0)
            if previous is not None:
                signal.signal(signal.SIGALRM, previous)


def _scope_not_widened(requested_origins: list[str], requested_deny: list[str],
                       echoed: ScopeRules, requested_max_depth: Optional[int] = None
                       ) -> Optional[str]:
    """None if the engine's echoed scope is a subset of what was actually
    requested; otherwise a message naming exactly what widened.

    The engine echoes `scope`/`target`/`deny` back verbatim, so an exact set
    comparison against this process's own CLI arguments is precise. A `deny`
    list that grows (the engine adding its own default entries) is expected;
    only a requested entry going missing is checked.
    """
    echoed_origins = {o for o in (echoed.origins or []) if o}
    widened = echoed_origins - set(requested_origins)
    if widened:
        return ("engine echoed scope wider than requested - it added "
                f"{sorted(widened)}")
    dropped_deny = set(requested_deny) - set(echoed.deny_substrings or [])
    if dropped_deny:
        return f"engine echoed scope with --deny entries missing - {sorted(dropped_deny)}"
    # No operator option asks for subdomains, so the engine may not add them.
    if echoed.allow_subdomains:
        return "engine echoed scope with subdomains allowed, which was not requested"
    if requested_max_depth is not None and (
            echoed.max_depth is None or echoed.max_depth > requested_max_depth):
        return (f"engine echoed scope deeper than --max-depth {requested_max_depth} "
                f"({echoed.max_depth})")
    return None


def _encode_proxy_auth_scheme(proxy_server: Optional[str],
                              proxy_auth_scheme: str) -> Optional[str]:
    """Stash `--proxy-auth-scheme` in `--proxy-server`'s own URL scheme
    (`http://host` -> `http+digest://host`) rather than adding a new
    constructor parameter to the browser layer.

    `agent/browser.py` forwards `proxy_server` to `relay.parse_upstream()` as
    an opaque string; `+` is an ordinary RFC 3986 scheme character, so
    `urlparse` on the far side splits it back apart (see
    `relay.parse_upstream`). Basic (the default) is left unchanged.
    """
    if not proxy_server or proxy_auth_scheme == "basic":
        return proxy_server
    scheme, sep, rest = proxy_server.partition("://")
    if not sep:
        return proxy_server
    return f"{scheme}+{proxy_auth_scheme}://{rest}"


def with_ports(target: str, scope: list[str], ports: list[int]) -> list[str]:
    """Every in-scope host, also on these operator-authorized ports.

    Scope is fixed when the run is created and enforced on both sides, so an
    extra port is an explicit origin from the start, never a widening the
    engine decides on later. A bare `host:port` accepts http and https.
    """
    from urllib.parse import urlparse

    if not ports:
        return scope
    base = list(scope) or [target]
    hosts = dict.fromkeys(urlparse(o if "://" in o else "//" + o).hostname for o in base)
    return base + ["%s:%d" % (h, p) for h in hosts if h for p in ports]


#: How long past `--max-seconds` the agent waits for the engine to stop first.
MAX_SECONDS_GRACE_S = 30

#: Hard wall-clock backstop: the process exits (code `ci.EXIT_WALL_CLOCK`) at
#: `--max-seconds` + this, whatever the main thread is doing. Derived: the
#: engine gets its grace (30s) and a step already in flight may legitimately
#: run to the action deadline (90s) - this is their sum, so a healthy wind-down
#: is never cut short. It is far below the 600s engine read timeout, which is
#: exactly the case the backstop exists for (a blocked engine request).
MAX_SECONDS_HARD_MARGIN_S = MAX_SECONDS_GRACE_S + ACTION_DEADLINE_S

MAX_SECONDS_HELP = (
    "wall-clock limit for the run, counted from agent start. Soft at N: the "
    "engine is asked to stop and the report says why; the agent ends the run "
    "itself at the next step boundary after N+%ds. Hard: the agent process "
    "exits with code %d by N+%ds even if a step is blocked (partial trace "
    "written, browser killed)"
    % (MAX_SECONDS_GRACE_S, ci.EXIT_WALL_CLOCK, MAX_SECONDS_HARD_MARGIN_S))


def clamp_capture(capture: Any, ceiling: int) -> Any:
    """The operator's `--max-capture-bytes`: the engine may lower every
    `*_bytes` evidence size, never raise it."""
    return capture.model_copy(update={
        name: min(getattr(capture, name), ceiling)
        for name in type(capture).model_fields if name.endswith("_bytes")})


@_clean_terminal_output
def _hard_margin_s() -> float:
    # The env var exists for tests and can only shorten the documented margin.
    try:
        return min(float(os.environ.get("SEKUSCAN_MAX_SECONDS_HARD_MARGIN_S",
                                        MAX_SECONDS_HARD_MARGIN_S)),
                   float(MAX_SECONDS_HARD_MARGIN_S))
    except ValueError:
        return float(MAX_SECONDS_HARD_MARGIN_S)


def run_agent(*args: Any, **kwargs: Any) -> int:
    """`_run_agent` with the `--max-seconds` hard deadline enforced from the
    first moment, run creation and setup included. The step-loop watchdog
    takes over once it starts."""
    import inspect
    bound = inspect.signature(_run_agent).bind(*args, **kwargs)
    max_seconds = bound.arguments.get("max_seconds")
    early = (_ProgressWatchdog(0, hard_deadline=_ProgressWatchdog._clock()
                               + max_seconds + _hard_margin_s()).start()
             if max_seconds else None)
    try:
        return _run_agent(*args, _early_watchdog=early, **kwargs)
    finally:
        if early is not None:
            early.stop()


def _run_agent(engine: str, api_key: str, target: str, scope: list[str],
              profile: str = "default", out: str = "./runs/latest",
              risk: int = 1,
              max_depth: Optional[int] = None,
              headful: bool = False,
              allow_destructive: bool = False, timeout_ms: int = 15000,
              engine_timeout: Optional[float] = None,
              allow_upload_cleanup: bool = False,
              upload_cleanup_url: Optional[str] = None,
              allow_safe_get_replay: bool = False,
              allow_authz_non_get: bool = False,
              safe_get_urls: Optional[list[str]] = None,
              capture_max_actions: Optional[int] = None,
              max_steps: Optional[int] = None, quiet: bool = False,
              max_seconds: Optional[int] = None,
              browser_sandbox: str = "auto", verify_target_tls: bool = False,
              strict_egress: bool = False,
              max_capture_bytes: Optional[int] = None,
              max_safety_incidents: int = DEFAULT_MAX_SAFETY_INCIDENTS,
              max_rps: float = 0.0,
              ca_cert: Optional[str] = None,
              browser: str = "chromium", username: Optional[str] = None,
              password: Optional[str] = None, login_url: Optional[str] = None,
              mfa_code: Optional[str] = None,
              login_body: Optional[str] = None,
              login_fields: Optional[str] = None,
              additional_login_urls: Optional[list[str]] = None,
              additional_logins: Optional[str] = None,
              auth_file: Optional[str] = None,
              cookie: Optional[list[str]] = None,
              header: Optional[list[str]] = None,
              bearer: Optional[str] = None, fail_on: str = "none",
              secondary_cookie: Optional[list[str]] = None,
              secondary_header: Optional[list[str]] = None,
              secondary_bearer: Optional[str] = None,
              secondary_username: Optional[str] = None,
              secondary_password: Optional[str] = None,
              secondary_login_url: Optional[str] = None,
              secondary_login_fields: Optional[str] = None,
              secondary_additional_login_urls: Optional[list[str]] = None,
              baseline: Optional[str] = None,
              fail_on_candidates: bool = False,
              require_complete: bool = False,
              deny: Optional[list[str]] = None,
              allow_internal_targets: bool = False,
              test_data: Optional[list[str]] = None,
              proxy_server: Optional[str] = None,
              proxy_username: Optional[str] = None,
              proxy_password: Optional[str] = None,
              proxy_bypass: Optional[str] = None,
              proxy_auth_scheme: str = "basic",
              client_cert: Optional[str] = None,
              client_key: Optional[str] = None,
              client_cert_origin: Optional[str] = None,
              target_auth: Optional[str] = None,
              target_auth_username: Optional[str] = None,
              target_auth_password: Optional[str] = None,
              webhook_url: Optional[str] = None,
              webhook_format: str = "generic",
              pdf: bool = False,
              user_agent: Optional[str] = None,
              _early_watchdog: Optional[_ProgressWatchdog] = None) -> int:
    if browser_sandbox not in ("auto", "on", "off"):
        print("error: --browser-sandbox must be auto, on or off", file=sys.stderr)
        return 2
    if max_capture_bytes is not None and max_capture_bytes < 1:
        print("error: --max-capture-bytes must be at least 1", file=sys.stderr)
        return 2
    run_started = time.monotonic()      # --max-seconds counts from here
    hard_s = _hard_margin_s()
    os.makedirs(out, exist_ok=True)
    # The report/trace directory holds sensitive material (session values,
    # evidence), so it is chmod-ed explicitly: `mode=` on makedirs is umask-
    # filtered and a no-op for a directory that already exists.
    try:
        os.chmod(out, 0o700)
    except OSError:
        pass
    logging.basicConfig(
        level=logging.WARNING if quiet else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    # The API key and the run token both travel to this url on every request,
    # so a plaintext `http://` engine address that is not loopback would hand
    # both to anyone who could observe the network path, and is refused.
    # Loopback stays allowed unencrypted (engine and agent normally run on the
    # same host).
    if not _engine_url_is_safe(engine):
        print(f"error: refusing a non-loopback http:// engine url ({engine}); "
             "use https:// for a remote engine", file=sys.stderr)
        return 2

    # NTLM to the target. Only "ntlm" is supported; Negotiate falls back to
    # it, and full Kerberos/SPNEGO is not implemented. Validated here, once,
    # rather than let a typo reach `BrowserSession` as a silently-ignored
    # value.
    if target_auth and target_auth not in ("ntlm",):
        print(f"error: --target-auth {target_auth!r} is not supported "
             "(only 'ntlm')", file=sys.stderr)
        return 2
    if target_auth and not (target_auth_username and target_auth_password):
        print("error: --target-auth requires --target-auth-username and "
             "--target-auth-password", file=sys.stderr)
        return 2
    if not target_auth and (target_auth_username or target_auth_password):
        print("error: --target-auth-username/--target-auth-password need "
             "--target-auth ntlm - otherwise they are silently ignored",
             file=sys.stderr)
        return 2

    # Non-Basic parent-proxy auth. Validated here, once, for the same reason
    # as --target-auth above: a typo or nonsensical combination should fail
    # loudly now rather than silently fall back to Basic later.
    if proxy_auth_scheme not in relaymod.PROXY_AUTH_SCHEMES:
        print(f"error: --proxy-auth-scheme {proxy_auth_scheme!r} is not "
             "supported (one of basic/digest/ntlm/negotiate)",
             file=sys.stderr)
        return 2
    if proxy_auth_scheme != "basic":
        if not proxy_server:
            print("error: --proxy-auth-scheme needs --proxy-server",
                 file=sys.stderr)
            return 2
        if not proxy_username:
            print("error: --proxy-auth-scheme digest/ntlm/negotiate needs "
                 "--proxy-username/--proxy-password", file=sys.stderr)
            return 2
        if proxy_server.split("://", 1)[0].lower() in ("socks5", "socks5h"):
            print("error: --proxy-auth-scheme only applies to an http(s) "
                 "--proxy-server; SOCKS5 has its own username/password "
                 "sub-negotiation (RFC 1929), unrelated to Digest/NTLM/"
                 "Negotiate", file=sys.stderr)
            return 2

    auth = ci.resolve_auth(username, password, login_url, auth_file,
                           cookie, header, bearer, mfa_code, login_body,
                           login_fields,
                           additional_login_urls=additional_login_urls,
                           additional_logins=additional_logins)
    secondary = ci.resolve_secondary_auth(secondary_username,
                                          secondary_password,
                                          secondary_login_url,
                                          secondary_login_fields,
                                          secondary_additional_login_urls)
    _say(quiet, f"session: {auth.describe()}")

    client = EngineClient(engine, api_key, **_engine_timeout_kw(engine_timeout),
                          **_engine_link(engine, proxy_server, proxy_username,
                                         proxy_password, proxy_auth_scheme,
                                         proxy_bypass, ca_cert))
    try:
        health = client.health()
        _say(quiet, f"engine ok: {health.get('engine_version')} "
                    f"(protocol {health.get('protocol_version')})")
    except Exception as exc:
        print(f"error: cannot reach engine at {engine}: {exc}", file=sys.stderr)
        return 2

    credentials = None
    # The password stays in this process. The engine gets a handle it cannot
    # read, and substitutes nothing - the agent resolves it at fill time. It
    # is registered whenever there is a password, including for `--login-
    # body`/`--login-fields` runs, so a later engine-built probe carrying the
    # `SECRET_PASSWORD` handle still resolves to the real value:
    # `resolve_secret` answers "" for an unregistered name, which would send a
    # login with an empty password.
    #
    # `load_secrets` is the only thing that clears the vault and `_SECRETS` is
    # a module global, so it is called unconditionally: with no password it
    # clears and registers nothing, and a previous run's password in the same
    # process can never be sent to a different target.
    #
    # The static second factor is registered here too: the code stays in this
    # process and the engine only receives `SECRET_MFA_CODE`, resolved back to
    # the value by the agent at fill time
    # (`agent/execute.py::resolve_secret`).
    local_secrets: dict[str, str] = {}
    if auth.password:
        local_secrets["password"] = auth.password
    if auth.mfa_code:
        local_secrets["mfa_code"] = auth.mfa_code
    load_secrets(local_secrets)
    # `settle` keeps module-global calibration state, so it is reset at the
    # start of every run: one run's calibration must not decide whether the
    # next run trusts fast settling on the same origin.
    settle.reset()
    if auth.has_form_login:
        credentials = Credentials(username=auth.username,
                                  password=SECRET_PASSWORD,
                                  login_url=auth.login_url,
                                  # the handle, never the code - resolved only
                                  # in this process when the challenge is filled
                                  mfa_code=(SECRET_MFA_CODE if auth.mfa_code
                                            else None))

    try:
        run = client.create_run(RunCreateRequest(
            target=target, scope=scope or [target], profile=profile,
            risk=risk,
            max_depth=max_depth,
            max_actions=max_steps, max_seconds=max_seconds,
            allow_destructive=allow_destructive,
            capture_max_actions=capture_max_actions,
            allow_upload_cleanup=allow_upload_cleanup,
            upload_cleanup_url=upload_cleanup_url,
            allow_safe_get_replay=allow_safe_get_replay,
            safe_get_urls=list(safe_get_urls or []),
            allow_authz_non_get=allow_authz_non_get,
            deny=list(deny or []), credentials=credentials,
            allow_internal_targets=allow_internal_targets,
            test_data=[OperatorDatum(**json.loads(item))
                       for item in (test_data or [])],
            secondary_session=bool(secondary_cookie or secondary_header
                                   or secondary_bearer or secondary.has_form_login
                                   or secondary.has_form_fields_login),
            # A cookie, bearer or header the operator supplied is the session
            # - there is nothing to confirm. A JSON login still has to
            # succeed, so it is only `pending` until it is confirmed.
            preset_session=auth.has_session,
            pending_session=bool(auth.has_json_login
                                 or auth.has_form_fields_login),
            labels={key: value for key, value in {
                "primary_identity": auth.username,
                "secondary_identity": secondary.username,
            }.items() if value},
            agent_version=AGENT_VERSION,
            capabilities=AgentCapabilities(
                headless=not headful, browser=browser,
                secondary_session=bool(secondary_cookie or secondary_header
                                       or secondary_bearer or secondary.has_form_login
                                       or secondary.has_form_fields_login)),
        ))
    except (EngineError, ValidationError) as exc:
        print(f"error: run creation failed: {exc}", file=sys.stderr)
        return 2

    _say(quiet, f"run {run.run_id} :: target={target} "
         f"risk={getattr(run, 'risk', risk)}")
    # The run token rides in the fragment, which the browser never sends -
    # and only to a terminal: it also authorizes /step, so not into CI logs.
    if sys.stdout.isatty():
        _say(quiet, f"live view : {engine.rstrip('/')}/v1/runs/{run.run_id}/watch"
             f"#token={run.run_token}")
    # `run.scope` is the engine's response, not a second local copy of what
    # was requested, so it is verified against this process's own arguments: a
    # compromised or buggy engine could echo back an origins list wider than
    # what was asked for (or silently drop a `--deny` entry), and every
    # directive after this point is authorized against whatever `guard` holds.
    if max_capture_bytes:
        run.capture = clamp_capture(run.capture, max_capture_bytes)
    scope_problem = _scope_not_widened(scope or [target], deny or [], run.scope, max_depth)
    if scope_problem:
        print(f"error: {scope_problem}; refusing rather than trusting it",
              file=sys.stderr)
        return 2
    guard = ScopeGuard(run.scope, operator_deny=deny or [])
    if not guard.allowed(target):
        print(f"error: target {target} is not inside the agreed scope "
              f"{run.scope.origins}", file=sys.stderr)
        return 2
    # Built from this process's own local arguments, never from anything `run`
    # (the engine's response) says: the agent keeps its own copy of the risk
    # model rather than trusting the engine to have applied it.
    # `effective_risk` folds in the legacy-flag-bumps-risk convention
    # (`--allow-destructive` and `--allow-authz-non-get` imply a risk level),
    # matching the engine's.
    policy = LocalExecutionPolicy(
        risk=effective_risk(risk, allow_destructive, allow_upload_cleanup,
                            allow_authz_non_get),
        allow_destructive=allow_destructive,
        allow_upload_cleanup=allow_upload_cleanup,
        upload_cleanup_url=upload_cleanup_url,
        allow_authz_non_get=allow_authz_non_get)

    # The operator's agreed per-host request ceiling, honoured by both probe
    # transports. Set before any traffic leaves; 0 disables it entirely.
    pacing.configure(max_rps)
    if max_rps and max_rps > 0:
        _say(quiet, f"pacing    : at most {max_rps} request(s)/second per host")

    steps = 0
    last_auth_state: Optional[str] = None
    artifacts: list[str] = []
    stop_reason = "agent-finished"
    extra_headers = ci.parse_pairs(auth.headers, separator=":")
    if auth.bearer:
        extra_headers["Authorization"] = f"Bearer {auth.bearer}"
    secondary_headers = ci.parse_pairs(secondary_header or [], separator=":")
    if secondary_bearer:
        secondary_headers["Authorization"] = f"Bearer {secondary_bearer}"
    secondary_cookies = ci.parse_pairs(secondary_cookie or [])
    # Every credential value the operator supplied is scrubbed from all that
    # is sent to the engine (`redaction.scrub_secrets` in `api.py`).
    redaction.register_secret_values([
        auth.password, auth.mfa_code, auth.bearer, secondary.password, secondary_bearer,
        proxy_password, target_auth_password,
        *extra_headers.values(), *ci.parse_pairs(auth.cookies).values(),
        *secondary_headers.values(), *secondary_cookies.values(),
        *(login.get("password") for login in auth.additional_logins or []),
        *_template_values(auth.login_body), *_template_values(auth.login_fields),
        *_template_values(secondary.login_fields),
        *(v for login in auth.additional_logins or []
          for key in ("body", "fields") for v in _template_values(login.get(key)))])
    # Built as a dict so the isolated path can hand the identical kwargs to
    # the child process; the in-process path constructs
    # `BrowserSession(**session_kwargs)` from the same values.
    session_kwargs = dict(
        headless=not headful, timeout_ms=timeout_ms,
        allow_destructive=allow_destructive,
        user_agent=(user_agent or DEFAULT_USER_AGENT),
        capture=run.capture, browser_name=browser,
        browser_sandbox=browser_sandbox, strict_egress=strict_egress,
        ignore_https_errors=not verify_target_tls,
        extra_headers=extra_headers,
        cookies=ci.parse_pairs(auth.cookies),
        cookie_url=target,
        secondary_headers=secondary_headers,
        secondary_cookies=secondary_cookies,
        secondary_cookie_url=target,
        secondary_username=secondary.username,
        secondary_password=secondary.password,
        secondary_login_url=secondary.login_url or target,
        secondary_login_fields=secondary.login_fields,
        secondary_additional_login_urls=(
            secondary.additional_login_urls),
        login_fields=auth.login_fields,
        additional_login_urls=auth.additional_login_urls,
        additional_logins=auth.additional_logins,
        json_login_url=auth.login_url,
        json_login_body=getattr(auth, "login_body", None),
        json_login_username=auth.username,
        json_login_password=auth.password,
        # the agreed scope, exactly as the engine returned it - widening this
        # with `target` would let a path-scoped engagement escape back to the
        # bare origin
        scope_origins=list(run.scope.origins),
        # Scan scope and "may receive the operator's credentials" are
        # different questions - a scope covering several origins (e.g. `www.`
        # and `api.`) does not mean a bearer that belongs to one of them
        # belongs on the other. Defaults to exactly the target's own origin.
        credential_origins=[_origin_only(target)],
        deny_substrings=list(run.scope.deny_substrings),
        allow_subdomains=run.scope.allow_subdomains,
        max_depth=run.scope.max_depth,
        proxy_server=_encode_proxy_auth_scheme(
            proxy_server, proxy_auth_scheme),
        proxy_username=proxy_username,
        proxy_password=proxy_password,
        proxy_bypass=proxy_bypass,
        client_cert_path=client_cert,
        client_key_path=client_key,
        client_cert_origin=client_cert_origin,
        ca_cert_path=ca_cert,
        target_auth_username=(
            target_auth_username if target_auth else None),
        target_auth_password=(
            target_auth_password if target_auth else None),
    )
    session: Optional[BrowserSession] = None
    browser_sandboxed: Optional[bool] = None
    trace: list[dict] = []
    # Started lazily on the first batch response (`len(resp.directives) > 1`):
    # a run that never receives a batch never creates this - no extra thread,
    # no extra Playwright driver.
    async_worker: Optional[AsyncProbeWorker] = None

    old_interrupt_handlers: dict[int, Any] = {}
    interrupted = False

    def interrupt(_signum: int, _frame: Any) -> None:
        # Turn external termination (a timeout kill, or Ctrl-C) into the same
        # recoverable path. The report must say partial rather than
        # disappearing because the browser was in a directive.
        raise KeyboardInterrupt

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            old_interrupt_handlers[signum] = signal.signal(signum, interrupt)
        except (AttributeError, ValueError):
            # A caller embedding the agent in a worker thread cannot own
            # process signal handlers; ordinary exception handling still
            # protects that caller.
            pass

    isolated = _isolation_enabled()
    handle: Optional[Any] = None
    #: Started only once the browser is up; a failure before that (a child
    #: that never starts) must still reach the partial report below.
    watchdog: Optional[_ProgressWatchdog] = None
    # Pipelining: the engine absorbs one observation while we run the batch
    # it already sent ahead (`StepResponse.ahead`). One step in flight, ever.
    pipeline = os.environ.get("SEKUSCAN_PIPELINE", "1") != "0"
    pipe_pool: Optional[ThreadPoolExecutor] = None
    inflight: Optional[Future] = None
    held: list[StepResponse] = []
    _iso_incidents = 0
    _iso_egress: list[dict[str, Any]] = []   # child's egress ledger, drained
    #                                           per directive across the pipe

    def _incidents() -> int:
        # Reads whichever counter is live for this run. When isolated,
        # `session` stays `None` for the whole run (this process never touches
        # Playwright), so this must not fall through to
        # `session.safety_incidents`.
        return _iso_incidents if isolated else session.safety_incidents

    # Last-resort deadlines, started BEFORE the browser/session init so a hang
    # there is covered too. A malformed `SEKUSCAN_NO_PROGRESS_S` must not stop
    # the agent starting, and must not be silent: the default is announced.
    raw_no_progress = os.environ.get("SEKUSCAN_NO_PROGRESS_S")
    no_progress_s = NO_PROGRESS_DEADLINE_S
    if raw_no_progress:
        try:
            no_progress_s = float(raw_no_progress)
        except (TypeError, ValueError):
            log.warning("SEKUSCAN_NO_PROGRESS_S=%r is not a number - "
                        "using the default %s", raw_no_progress,
                        NO_PROGRESS_DEADLINE_S)

    def _hard_stop(message: str) -> None:
        # Runs on the watchdog thread; the main thread is wedged. Best effort,
        # each part guarded: kill the browser (isolated child), then leave the
        # trace and the reason on disk. The in-process browser dies with this
        # process (its driver's pipe closes).
        try:
            if handle is not None:
                handle._kill()
        except Exception:
            pass
        try:
            path = os.path.join(out, "agent-trace.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"target": target, "profile": profile,
                           "stop_reason": message, "steps": steps,
                           "trace": list(trace), "browser_sandbox": None,
                           "egress": []}, fh, indent=2, default=str)
            _restrict(path, 0o600)
        except Exception:
            pass

    if _early_watchdog is not None:
        _early_watchdog.stop()   # this one also kills the browser on expiry
    watchdog = _ProgressWatchdog(
        no_progress_s,
        # in the watchdog's own clock, minus what init has already used
        hard_deadline=(_ProgressWatchdog._clock() + max_seconds + hard_s
                       - (time.monotonic() - run_started)
                       if max_seconds else None),
        on_hard=_hard_stop).start()

    try:
        if isolated:
            # The browser lives in a killable child; this process never calls
            # `BrowserSession(...)`/`.start()`. See `browser_worker.py`.
            init = {
                "executor": "browser",
                "session_kwargs": {**session_kwargs,
                                   "capture": run.capture.model_dump()},
                # The agent's secret vault (`execute._SECRETS`) is a module
                # global populated by `load_secrets()` above, and a module
                # global does not cross the spawn boundary into the child.
                # Without this, the `SECRET_PASSWORD` handle used by an
                # engine-directed login would resolve to "" in the child. The
                # real password already reaches the child via
                # `session_kwargs["json_login_password"]`, so carrying it here
                # is the same agent-to-child IPC trust level and is never
                # visible to the engine.
                "secrets": dict(local_secrets),
                "scope": run.scope.model_dump(),
                "operator_deny": list(deny or []),
                "policy": {
                    "risk": policy.risk,
                    "allow_destructive": policy.allow_destructive,
                    "allow_upload_cleanup": policy.allow_upload_cleanup,
                    "upload_cleanup_url": policy.upload_cleanup_url,
                    "allow_authz_non_get": policy.allow_authz_non_get,
                },
                "out_dir": out,
                "max_rps": max_rps,
            }
            handle = BrowserWorkerHandle(init, cap_s=PER_DIRECTIVE_CAP_S)
            info = handle.start()
            login_failed = info.get("login_failed")
            browser_sandboxed = info.get("browser_sandbox")
            pre_login_states = [StateSnapshot.model_validate(s)
                               for s in info.get("pre_login_states") or []]
        else:
            session = BrowserSession(**session_kwargs)
            session.start()
            browser_sandboxed = getattr(session, "sandboxed", None)
            login_failed = getattr(session, "login_failed", None)
            pre_login_states = getattr(session, "pre_login_states", None) or []
        # `_observe_pre_login` (agent/browser.py) captured an anonymous
        # StateSnapshot of the primary login endpoint before `start()`'s
        # credentialed login ran - the only point in the run where such an
        # observation exists. Deliver it now, flagged `pre_auth=True`.
        #
        # `Observation.state` carries exactly one state, so only the primary
        # login (`--login-url`) has a delivery path for its pre-login
        # baseline; additional login endpoints do not.
        #
        # `getattr` with a default, so a session without the attribute is
        # treated as having no pre-login states.
        # A primary login that did not establish a session must not be silent:
        # the scan would continue anonymously and the report would describe an
        # application it never logged into. Said once, at the top, where an
        # operator will see it before the run's output scrolls past.
        if login_failed:
            _say(quiet, "")
            _say(quiet, "  !! PRIMARY LOGIN FAILED: %s" % login_failed)
            _say(quiet, "  !! this scan is running ANONYMOUSLY - authenticated "
                        "surfaces will not be reached, and 'no findings' here "
                        "means 'not tested', not 'not vulnerable'")
            _say(quiet, "")
        pre_login_state = pre_login_states[0] if pre_login_states else None
        obs = Observation(seq=0, phase_hint="bootstrap",
                          state=pre_login_state,
                          pre_auth=pre_login_state is not None)
        # The engine owns action accounting. A local ceiling is only an
        # overrun guard: after executing action N the agent must still POST
        # action N's observation so the engine can absorb its results and
        # decide to stop. Checking the guard in the loop condition would exit
        # before that final POST and discard the evidence the last allowed
        # action produced, so the guard is checked only after a directive is
        # received.
        limit = max_steps if max_steps and max_steps > 0 else run.safety_ceiling
        # Last-resort deadlines live in the watchdog started before init; the
        # init time is not "no progress" in the step loop.
        watchdog.beat()
        # `--max-seconds` is also enforced HERE, not only by the engine that
        # was asked to stop: the grace lets an honest engine end the run
        # itself first, with its own final report. Counted from agent start.
        run_deadline = (run_started + max_seconds + MAX_SECONDS_GRACE_S
                        if max_seconds else None)
        while True:
            if run_deadline is not None and time.monotonic() >= run_deadline:
                # worded like the engine's own, which its coverage
                # classifier already reads as a spent budget
                stop_reason = ("wall-time budget reached after %ds (enforced "
                               "by the agent; coverage incomplete)"
                               % max_seconds)
                log.error("%s - ending the engagement", stop_reason)
                _say(quiet, "stop: %s" % stop_reason)
                break
            # The run-level safety breaker. Checked at the top of the loop,
            # the one point both branches below return through, so one check
            # covers both transports. It lives here rather than in
            # `ScopeGuard`, whose job is to decide one URL and stays a pure
            # function of it; counting is a property of the run.
            if (max_safety_incidents > 0
                    and _incidents() >= max_safety_incidents):
                stop_reason = ("safety-kill-switch: %d refused out-of-scope "
                               "events (limit %d)"
                               % (_incidents(), max_safety_incidents))
                log.error("%s - ending the engagement", stop_reason)
                _say(quiet, "stop: %s" % stop_reason)
                break
            try:
                if inflight is not None and (obs is not None or not held):
                    held.extend(_pipe_split(inflight.result()))
                    inflight = None
                if held:
                    resp = held.pop(0)
                    if obs is not None:
                        # report the last batch while this one runs
                        obs.pipeline = True
                        if pipe_pool is None:
                            pipe_pool = ThreadPoolExecutor(1, "sekuscan-pipe")
                        inflight = pipe_pool.submit(_call_with_retry,
                                                    client.step, obs)
                        obs = None
                else:
                    if obs is None:
                        stop_reason = "engine held with nothing outstanding"
                        log.error(stop_reason)
                        break
                    obs.pipeline = pipeline
                    got = _pipe_split(_call_with_retry(client.step, obs))
                    obs = None
                    if not got:
                        stop_reason = "engine held with nothing outstanding"
                        log.error(stop_reason)
                        break
                    resp = got.pop(0)
                    held.extend(got)
            except EngineError as exc:
                print(f"error: step failed: {exc}", file=sys.stderr)
                stop_reason = f"step-failed: {exc}"[:200]
                break

            directive = resp.directive
            progress = resp.progress
            if directive.kind == "stop":
                stop_reason = directive.reason or "engine-stop"
                _say(quiet, f"stop: {stop_reason}")
                break

            # `getattr` rather than `resp.directives` directly: the field is
            # additive (see `StepResponse`), so an older engine or a caller
            # that only knew the singular `directive` still works and never
            # takes the batch branch.
            directives = getattr(resp, "directives", None) or [directive]
            if len(directives) > 1:
                # Trim the batch to the remaining budget. Comparing `steps >=
                # limit` and then adding the whole batch would overshoot a
                # `--max-actions` bound by up to the batch size. Trimmed
                # rather than refused: dropping the whole batch would throw
                # away directives the budget can still afford. Refusal stays
                # for the case where there is no room at all.
                if limit is not None:
                    room = limit - steps
                    if room <= 0:
                        stop_reason = "engine issued work past agent action limit"
                        log.error("refusing a %d-directive batch after %d/%d "
                                  "actions", len(directives), steps, limit)
                        break
                    if len(directives) > room:
                        log.warning("trimming a %d-directive batch to %d to "
                                    "stay inside the %d-action limit",
                                    len(directives), room, limit)
                        directives = directives[:room]
                steps += len(directives)
                watchdog.beat()
                if isolated:
                    # The child dispatches the whole batch itself (it calls
                    # the same `_run_probe_batch` this process would have) -
                    # one bounded round trip either way.
                    bp = handle.run_batch(
                        [d.model_dump(mode="json") for d in directives],
                        seq=steps, phase=progress.phase)
                    if bp is WEDGED:
                        log.warning(
                            "batch of %d directives wedged the isolated "
                            "browser after %ds; child killed and respawned",
                            len(directives), PER_DIRECTIVE_CAP_S)
                        obs = Observation(
                            seq=steps, phase_hint=progress.phase,
                            action_result=ActionResult(
                                directive_id=directives[0].id,
                                ok=False, kind="probe_http",
                                error=("browser-wedged: batch killed after "
                                      "%ds; child respawned"
                                      % PER_DIRECTIVE_CAP_S),
                                detail={"timeout_s": PER_DIRECTIVE_CAP_S}))
                    else:
                        obs = rebuild_batch_observation(bp)
                        artifacts.extend(bp.get("artifacts") or [])
                        trace.extend(bp.get("trace") or [])
                        _iso_incidents = bp.get("safety_incidents", _iso_incidents)
                        _iso_egress.extend(bp.get("egress") or [])
                else:
                    if async_worker is None:
                        # Route batched probes through the same proxy/relay
                        # every other transport uses - the worker's own
                        # request context inherits nothing, so without this
                        # concurrent probes would bypass the relay (and,
                        # against an NTLM target, get 401).
                        async_worker = AsyncProbeWorker(
                            **session.async_worker_kwargs())
                        async_worker.start()
                    obs = _run_probe_batch(
                        session, directives, guard, run.capture, policy,
                        async_worker, progress, steps, quiet, artifacts, trace)
                if progress.auth_state and progress.auth_state != last_auth_state:
                    last_auth_state = progress.auth_state
                    _say(quiet, f"       session: {last_auth_state}")
                continue

            if limit is not None and steps >= limit:
                stop_reason = "engine issued work past agent action limit"
                log.error("refusing directive %s after %d/%d actions",
                         directive.id, steps, limit)
                break

            steps += 1
            watchdog.beat()
            _say(quiet, f"[{steps:03d}] {directive.kind:12s} "
                        f"{(directive.url or directive.selector or '')[:78]}"
                        f"  <- {directive.reason[:60]}")
            if progress.auth_state and progress.auth_state != last_auth_state:
                last_auth_state = progress.auth_state
                _say(quiet, f"       session: {last_auth_state}")

            if isolated:
                payload = handle.run_directive(
                    directive.model_dump(mode="json"), seq=steps)
                if payload is WEDGED:
                    log.warning(
                        "directive %s (%s) wedged the isolated browser after "
                        "%ds; child killed and respawned",
                        directive.id, directive.kind, PER_DIRECTIVE_CAP_S)
                    outcome = Outcome(
                        action_result=ActionResult(
                            # see the in-process `_ActionTimeout` handler
                            # below for why `directive_id` is required.
                            directive_id=getattr(directive, "id", None),
                            ok=False, kind=directive.kind,
                            error=("browser-wedged: %s killed after %ds; "
                                  "child respawned"
                                  % (directive.kind, PER_DIRECTIVE_CAP_S)),
                            detail={"timeout_s": PER_DIRECTIVE_CAP_S,
                                    "url": getattr(directive, "url", None)}),
                        load_error=("browser-wedged: %s abandoned after %ds"
                                   % (directive.kind, PER_DIRECTIVE_CAP_S)),
                        capture_state=False)
                    state = None
                    network: list[Any] = []
                    console: list[Any] = []
                    _say(quiet, "       wedged: browser killed + respawned "
                                "after %ds" % PER_DIRECTIVE_CAP_S)
                else:
                    outcome = rebuild_outcome(payload["outcome"])
                    state = rebuild_state(payload["state"])
                    network = rebuild_network(payload["network"])
                    console = rebuild_console(payload["console"])
                    _iso_incidents = payload["safety_incidents"]
                    _iso_egress.extend(payload.get("egress") or [])
            else:
                try:
                    with _action_deadline(directive):
                        outcome = execute(session, directive, guard, run.capture,
                                          out, steps, policy)
                        state = None
                        if outcome.capture_state and directive.kind != "probe_http":
                            state = observe_state(session, run.capture,
                                                  http_status=outcome.http_status,
                                                  requested_url=directive.url,
                                                  load_error=outcome.load_error)
                except _ActionTimeout:
                    # The action is abandoned, not the run. Reported as a load
                    # error so the engine sees a completed step with a reason
                    # instead of silence, and the crawl moves on.
                    log.warning("action %s (%s) exceeded %ds and was abandoned",
                                directive.id, directive.kind, ACTION_DEADLINE_S)
                    outcome = Outcome(
                        action_result=ActionResult(
                            # `directive_id` is required: the engine refuses
                            # (409) an observation that carries no result for
                            # the directive still outstanding.
                            directive_id=getattr(directive, "id", None),
                            ok=False, kind=directive.kind,
                            error="action-timeout after %ds" % ACTION_DEADLINE_S,
                            detail={"timeout_s": ACTION_DEADLINE_S}),
                        load_error="action-timeout: %s abandoned after %ds"
                                   % (directive.kind, ACTION_DEADLINE_S),
                        capture_state=False)
                    state = None
                    _say(quiet, "       abandoned: no response after %ds"
                                % ACTION_DEADLINE_S)
                network = session.drain_network()
                console = session.drain_console()
            artifacts.extend(outcome.screenshots)
            preferred_url = (outcome.action_result.detail.get("form_action")
                             if outcome.action_result else None)
            probe = outcome.probe or probe_from_network(
                directive, network, preferred_url=preferred_url)
            obs = Observation(
                seq=steps, phase_hint=progress.phase, state=state,
                probe=probe, action_result=outcome.action_result,
                network=network, console=console,
                screenshots=[os.path.relpath(p, out) for p in outcome.screenshots],
            )
            trace.append({
                "step": steps, "directive": _safe_directive(directive),
                "ok": outcome.action_result.ok,
                "error": outcome.action_result.error,
                "status": outcome.http_status or (probe.status
                                                  if probe else None),
                "url": (state.url if state else
                        (probe.url if probe else None)),
            })
            if not outcome.action_result.ok:
                log.info("directive %s failed: %s", directive.kind,
                         outcome.action_result.error)
    except KeyboardInterrupt:
        interrupted = True
        stop_reason = "agent-interrupted"
        log.warning("agent interrupted; finalizing a partial report")
    except Exception as exc:
        stop_reason = f"agent-error: {type(exc).__name__}: {exc}"[:200]
        log.exception("agent loop failed; finalizing a partial report")
    finally:
        # Stop the no-progress watchdog first, before the slow teardown. It is
        # a daemon thread that would otherwise keep measuring "no progress"
        # through completion, report build, PDF render and webhook delivery -
        # none of which call `beat()` - and its action on a stall is
        # `os._exit()`, which would kill a finished scan and lose the report.
        # In an embedding process a stale watchdog could also outlive the run
        # and exit the host process.
        if watchdog is not None:
            watchdog.stop()
        # never `complete` beside a step still in flight
        if inflight is not None:
            try:
                inflight.result()
            except Exception:                          # noqa: BLE001
                log.warning("pipelined step failed at shutdown", exc_info=True)
        if pipe_pool is not None:
            pipe_pool.shutdown(wait=False)
        # Attempted unconditionally, including after Ctrl-C: in an embedding
        # process (`run_agent()` is a function) the browser would otherwise
        # survive the run that started it. A teardown that raises must not
        # replace the interrupt or lose the partial report this `finally`
        # exists to produce.
        try:
            if isolated:
                # `handle.close()` is itself bounded (SIGKILL + a 5s join) -
                # there is no Playwright client here that can hang the way
                # `session.stop()` below can.
                if handle is not None:
                    handle.close()
            else:
                session.stop()
        except Exception:                              # noqa: BLE001
            log.warning("browser teardown failed after %s",
                        "interrupt" if interrupted else "completion",
                        exc_info=True)
        if async_worker is not None:
            async_worker.stop()
        for signum, handler in old_interrupt_handlers.items():
            try:
                signal.signal(signum, handler)
            except (AttributeError, ValueError):
                pass

    try:
        done = _call_with_retry(client.complete, reason=stop_reason,
                                artifacts=[os.path.relpath(a, out) for a in artifacts])
    except EngineError as exc:
        print(f"error: completion failed: {exc}", file=sys.stderr)
        return 3

    try:
        report_json = _call_with_retry(
            client.fetch_text, f"/v1/runs/{done.run_id}/report.json")
        report_html = _call_with_retry(
            client.fetch_text, f"/v1/runs/{done.run_id}/report.html")
    except EngineError as exc:
        print(f"error: report download failed: {exc}", file=sys.stderr)
        return 3
    paths = {
        "report.json": os.path.join(out, "report.json"),
        "report.html": os.path.join(out, "report.html"),
        "agent-trace.json": os.path.join(out, "agent-trace.json"),
    }
    with open(paths["report.json"], "w", encoding="utf-8") as fh:
        fh.write(report_json)
    _restrict(paths["report.json"], 0o600)
    with open(paths["report.html"], "w", encoding="utf-8") as fh:
        fh.write(report_html)
    _restrict(paths["report.html"], 0o600)
    if pdf:
        paths["report.pdf"] = os.path.join(out, "report.pdf")
        pdf_error = render_report_pdf(paths["report.html"], paths["report.pdf"],
                                      browser_sandbox)
        if pdf_error is not None:
            print(f"pdf       : export failed - {pdf_error}", file=sys.stderr)
            del paths["report.pdf"]
        else:
            _restrict(paths["report.pdf"], 0o600)
    # Isolated: the egress ledger lives on the child's `session`, which this
    # process never holds - so the child drains it per directive and hands
    # each batch back over the pipe, and this process accumulates it in
    # `_iso_egress`. The safety-incident count travels the same way, via
    # `_incidents()`.
    egress = session.drain_egress() if not isolated else _iso_egress
    with open(paths["agent-trace.json"], "w", encoding="utf-8") as fh:
        json.dump({"run_id": done.run_id, "target": target, "profile": profile,
                   "stop_reason": stop_reason, "steps": steps, "trace": trace,
                   "browser_sandbox": browser_sandboxed, "egress": egress},
                  fh, indent=2, default=str)
    _restrict(paths["agent-trace.json"], 0o600)

    report = json.loads(report_json)
    # SARIF as its own file, because that is the form consumers want:
    # `--sarif-file` for the GitHub upload action, a GitLab report artefact,
    # an IDE problems panel. It is inside report.json too, but nothing takes a
    # SARIF log nested under a key.
    if report.get("sarif"):
        paths["report.sarif"] = os.path.join(out, "report.sarif")
        with open(paths["report.sarif"], "w", encoding="utf-8") as fh:
            json.dump(report["sarif"], fh, indent=2, default=str)
        _restrict(paths["report.sarif"], 0o600)
    if interrupted and not isolated:
        # A browser action can leave the synchronous Playwright client blocked
        # in the same call that received SIGTERM. The report is already safe to
        # hand off; cleanup must not be allowed to erase that handoff. A daemon
        # worker gets the ordinary close attempt without holding the process
        # open if Playwright cannot unwind.
        #
        # Isolated mode needs no second attempt here: `handle.close()` in the
        # `finally` above already tore the child down with a bounded SIGKILL +
        # join.
        cleaner = threading.Thread(target=session.stop, daemon=True)
        cleaner.start()
        cleaner.join(timeout=2.0)
    summary = report.get("summary", {})
    counts = summary.get("signals") or summary.get("findings") or {}
    explored = summary.get("explored", {})
    print()
    print(f"run       : {done.run_id}")
    print(f"steps     : {steps} (stop: {stop_reason})")
    if egress:
        # `session.safety_incidents`, not a count over `egress` - the ledger
        # is capped at 200 entries and the counter is not, so on a runaway
        # these two genuinely differ and the uncapped one is the true figure.
        print(f"egress    : {len(egress)} out-of-scope request(s) "
              f"({_incidents()} blocked) - see agent-trace.json")
    print(f"explored  : {explored.get('states', 0)} states, "
          f"{explored.get('surfaces', 0)} surfaces "
          f"({explored.get('surfaces_exercised', 0)} exercised), "
          f"{explored.get('probes_sent', 0)} probes")
    print(f"signals   : {counts.get('findings', 0)} confirmed, "
          f"{counts.get('candidates', 0)} unconfirmed")
    cov = report.get("coverage") or {}
    if cov:
        # printed for every run, not only the bad ones: "complete" is a claim
        # the reader should see being made, not infer from silence
        print(f"coverage  : {cov.get('status', '?')} "
              f"({cov.get('termination', '?')})")
        for reason in (cov.get("reasons") or [])[:4]:
            print(f"            ! {reason}")
    ex = report.get("executive") or {}
    ec = ex.get("counts") or {}
    if ec:
        print(f"weaknesses: {ec.get('weaknesses', 0)} distinct, "
              f"{ec.get('locations', 0)} affected location(s)")
        print(f"follow-up : {ec.get('validate', 0)} need validation, "
              f"{ec.get('observations', 0)} observation(s), "
              f"{ec.get('clean', 0)} clean")
    by_sev = (summary.get("issues") or {}).get("by_severity") or \
        counts.get("by_severity", {})
    if by_sev:
        print("severity  : " + ", ".join(f"{k}={v}" for k, v in by_sev.items()))
    print(f"reports   : {paths['report.html']}")
    print(f"            {paths['report.json']}")
    if "report.pdf" in paths:
        print(f"            {paths['report.pdf']}")
    if webhook_url:
        post_completion_webhook(webhook_url, {
            "run_id": done.run_id, "target": target, "profile": profile,
            "stop_reason": stop_reason,
            "findings": counts.get("findings", 0),
            "candidates": counts.get("candidates", 0),
            "by_severity": by_sev,
            "coverage_status": cov.get("status"),
        }, quiet=quiet, fmt=webhook_format)
    client.close()

    diff = ci.diff_against(report, baseline)
    if diff is not None:
        paths["report.diff.json"] = os.path.join(out, "report.diff.json")
        with open(paths["report.diff.json"], "w", encoding="utf-8") as fh:
            json.dump(diff, fh, indent=2, default=str)
        _restrict(paths["report.diff.json"], 0o600)
        print(ci.render_diff(diff))

    known = ci.load_baseline(baseline)
    code, offenders, note = ci.gate(report, fail_on, known, fail_on_candidates)
    # An incomplete run reporting "no findings" is the failure mode a pipeline
    # cannot see. `--require-complete` turns it into one it cannot miss, and
    # it never downgrades a real finding: the gate result wins if it is worse.
    if require_complete and not (report.get("coverage") or {}).get(
            "coverage_complete", True):
        print("gate      : coverage incomplete and --require-complete was set")
        code = max(code, 4)
    if fail_on not in ("", "none"):
        print(f"gate      : {note}")
        for finding in offenders[:10]:
            print(f"            {finding.get('severity'):<8} "
                  f"{finding.get('check_id')} :: {finding.get('title')}")
        if len(offenders) > 10:
            print(f"            ... and {len(offenders) - 10} more")
    return code


# --------------------------------------------------------------------------
# cli plumbing (typer when available, argparse otherwise)
# --------------------------------------------------------------------------


def _safe_directive(directive: Any) -> dict:
    """Never let credentials reach the on-disk trace."""
    payload = directive.model_dump()
    if payload.get("sensitive"):
        payload["values"] = {k: "<redacted>" for k in (payload.get("values") or {})}
    return payload


#: Terminal control characters (ESC sequences included), shown escaped:
#: much of what is printed comes from the engine or the target.
_CONTROL = {c: "\\x%02x" % c for c in [*range(0x20), *range(0x7f, 0xa0)] if c not in (0x09, 0x0a)}


def _say(quiet: bool, message: str) -> None:
    if not quiet:
        print(message.translate(_CONTROL), flush=True)


REPORT_PDF_HEADER = (
    '<div style="width:100%;padding:0 15mm;color:#68717c;'
    'font:8px Arial,sans-serif;letter-spacing:.14em;'
    'text-transform:uppercase">'
    'SekuScan &middot; security assessment</div>'
)
REPORT_PDF_FOOTER = (
    '<div style="width:100%;padding:4px 15mm 0;'
    'border-top:1px solid #d9dde3;color:#68717c;'
    'font:8px Arial,sans-serif;display:flex;'
    'justify-content:space-between">'
    '<span>SekuScan &middot; authorised assessment</span>'
    '<span>Page <span class="pageNumber"></span> '
    'of <span class="totalPages"></span></span></div>'
)


def render_report_pdf(html_path: str, pdf_path: str,
                      browser_sandbox: str = "auto") -> Optional[str]:
    """A dedicated PDF export, so an operator need not print-to-PDF from their
    own browser by hand. Returns an error string on failure, None on success -
    never raises, so a scan that finished correctly is not failed by a missing
    or broken Playwright install.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "playwright is not installed"
    try:
        with sync_playwright() as p:
            browser, _ = launch_browser(p.chromium, "chromium", browser_sandbox)
            try:
                # The report comes from the engine: render it with scripts
                # off and nothing fetched except the file itself.
                page = browser.new_page(java_script_enabled=False)
                report_url = pathlib.Path(os.path.abspath(html_path)).as_uri()
                page.route("**/*", lambda route: route.continue_()
                           if route.request.url == report_url else route.abort())
                page.goto(report_url,
                          wait_until="load")
                # Chromium will not lay out a closed <details> body even when
                # print CSS asks for display:block. Open only confirmed finding
                # disclosures in this transient print document; the saved HTML
                # remains compact and interactive, and the large inventories
                # stay collapsed instead of turning a client PDF into a dump.
                page.evaluate(
                    "document.querySelectorAll('details.inst.confirmed')"
                    ".forEach(function (d) { d.open = true; });"
                )
                page.emulate_media(media="print")
                page.pdf(
                    path=pdf_path,
                    print_background=True,
                    prefer_css_page_size=True,
                    display_header_footer=True,
                    header_template=REPORT_PDF_HEADER,
                    footer_template=REPORT_PDF_FOOTER,
                )
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - a PDF export is a bonus artefact
        return f"{type(exc).__name__}: {exc}"
    return None


#: Webhook payload shapes. `generic` is the agent's own flat JSON, suited to
#: an automation rule, a SIEM HTTP source or any custom intake. `slack` and
#: `msteams` reject a bare object and require their own message schema, and
#: need no deployment-specific configuration to render.
WEBHOOK_FORMATS = ("generic", "slack", "msteams")


def _webhook_headline(payload: dict[str, Any]) -> tuple[str, str]:
    """`(title, detail)` shared by every vendor shape."""
    sev = payload.get("by_severity") or {}
    counted = ", ".join("%s=%s" % (k, v) for k, v in sev.items()) or "none"
    incomplete = (payload.get("coverage_status") or "") != "completed"
    title = "SekuScan: %d finding(s) on %s" % (
        payload.get("findings", 0), payload.get("target", "?"))
    detail = (
        "*Target:* %s\n*Findings:* %s (%s candidates)\n*Severity:* %s\n"
        "*Coverage:* %s%s\n*Stopped:* %s\n*Run:* %s"
        % (payload.get("target", "?"), payload.get("findings", 0),
           payload.get("candidates", 0), counted,
           payload.get("coverage_status", "?"),
           "  :warning: incomplete - absence of findings proves nothing here"
           if incomplete else "",
           payload.get("stop_reason", "?"), payload.get("run_id", "?")))
    return title, detail


def format_webhook(payload: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Wrap the completion summary in one vendor's envelope.

    The summary itself never changes shape - only its wrapper - so a reader
    comparing two deliveries is comparing the same numbers.
    """
    if fmt not in WEBHOOK_FORMATS:
        raise ValueError("unknown webhook format %r (expected one of %s)"
                         % (fmt, ", ".join(WEBHOOK_FORMATS)))
    if fmt == "generic":
        return payload
    title, detail = _webhook_headline(payload)
    if fmt == "slack":
        return {
            # `text` is not redundant: Slack uses it for the notification
            # preview and for any client that cannot render blocks.
            "text": title,
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text", "text": title[:150]}},
                {"type": "section",
                 "text": {"type": "mrkdwn", "text": detail}},
            ],
        }
    # msteams: a MessageCard, which is what an Incoming Webhook connector
    # accepts. Markdown bold is `**`, not Slack's single `*`.
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "D93F0B" if payload.get("findings") else "2EB886",
        "title": title,
        "text": detail.replace("*", "**").replace("\n", "\n\n"),
    }


def post_completion_webhook(url: str, payload: dict[str, Any],
                            quiet: bool = False,
                            fmt: str = "generic") -> None:
    """Best-effort, generic completion notification - the shape a Slack incoming
    webhook, an automation rule, or a SIEM's HTTP source can all consume.
    Never raises: a scan that finished correctly must not fail its own exit
    code because a webhook endpoint was briefly down.
    """
    import httpx

    try:
        body = format_webhook(payload, fmt)
    except ValueError as exc:
        # A bad --webhook-format is an operator mistake worth saying out
        # loud, but still must not fail a scan that finished correctly.
        _say(quiet, f"webhook   : {exc}")
        return
    try:
        resp = httpx.post(url, json=body, timeout=10.0)
        if resp.status_code >= 400:
            _say(quiet, f"webhook   : {url} answered {resp.status_code}")
    except httpx.HTTPError as exc:
        _say(quiet, f"webhook   : delivery failed - {exc}")


def _run_probe_batch(session: BrowserSession, directives: list[Any],
                     guard: ScopeGuard, capture: Any,
                     policy: LocalExecutionPolicy,
                     async_worker: AsyncProbeWorker, progress: Any,
                     seq: int, quiet: bool, artifacts: list[str],
                     trace: list[dict]) -> Observation:
    """The batch counterpart of the main loop's single-directive body -
    dispatches `directives` concurrently via `execute_batch`, appends one
    trace entry per item, and returns one `Observation` carrying every item's
    result in `.batch` (`probe`/`action_result` also carry the first item, for
    readers of the singular fields).

    A batch holds only ordinary primary-auth `probe_http` directives, never
    `navigate`/`click`/anything state-capturing, so this never calls
    `observe_state()` and always posts `state=None`.
    """
    _say(quiet, f"[{seq:03d}] batch of {len(directives)} probe_http "
                f"directives dispatched concurrently")
    outcomes = execute_batch(session, directives, guard, capture, policy,
                             async_worker, BATCH_TIMEOUT_S)
    network = session.drain_network()
    console = session.drain_console()
    batch_items: list[BatchedResult] = []
    for directive, outcome in zip(directives, outcomes):
        artifacts.extend(outcome.screenshots)
        batch_items.append(
            BatchedResult(action_result=outcome.action_result, probe=outcome.probe))
        trace.append({
            "step": seq, "directive": _safe_directive(directive),
            "ok": outcome.action_result.ok,
            "error": outcome.action_result.error,
            "status": outcome.probe.status if outcome.probe else None,
            "url": outcome.probe.url if outcome.probe else directive.url,
        })
        if not outcome.action_result.ok:
            log.info("directive %s failed: %s", directive.kind,
                     outcome.action_result.error)
    first = batch_items[0]
    return Observation(
        seq=seq, phase_hint=progress.phase, state=None,
        probe=first.probe, action_result=first.action_result,
        batch=batch_items, network=network, console=console,
    )


RISK_HELP = ("operator risk level: 1 conservative - browses and submits the "
             "forms it finds as a user would and sends engine-declared "
             "read-only test inputs; no uploads, no DELETE, no undeclared "
             "writes, no form method overrides; 2 observed workflows; "
             "3 bounded upload and command proof")
BROWSER_SANDBOX_HELP = (
    "Chromium sandbox: auto (default) uses it and, if the host cannot start "
    "it, warns loudly and runs without; on refuses to run without it; off "
    "never uses it")
VERIFY_TLS_HELP = (
    "verify the TARGET's TLS certificate in the browser and in the agent's "
    "own requests (default: certificate errors are ignored, test systems "
    "often lack valid ones). Chromium does not read --ca-cert: a private CA "
    "must be in the system trust store for the browser to accept it")
STRICT_EGRESS_HELP = (
    "abort every off-scope request the page makes and block service workers "
    "(default: off-scope subresources load, without credentials). Page "
    "WebSockets are closed when off-scope if Playwright supports it; a "
    "firewall is the real containment")
MAX_CAPTURE_HELP = (
    "ceiling in bytes on every evidence sample size (HTML, text, body) the "
    "engine asks the agent to capture; the engine may lower it, never raise it")


VERSION_LINE = "sekuscan-agent %s (protocol %s)" % (AGENT_VERSION,
                                                     PROTOCOL_VERSION)


def _argparse_main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sekuscan-agent",
                                     description="SekuScan thin agent")
    parser.add_argument("--version", action="version", version=VERSION_LINE)
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="explore a target under engine control")
    # `--engine` is the name used throughout (the agent talks to the engine);
    # argparse stores it under `args.engine`.
    r.add_argument("--engine", dest="engine", required=True,
                   help="base URL of the SekuScan engine")
    r.add_argument("--api-key", default=None,
                   help="engine API key; falls back to SEKUSCAN_API_KEY "
                        "(preferred - argv is visible to anyone on the "
                        "same host via `ps`)")
    r.add_argument("--target", required=True)
    r.add_argument("--scope", action="append", default=[])
    r.add_argument("--ports", type=lambda v: [int(p) for p in v.split(",") if p],
                   default=[], help="also scan these ports on every in-scope host "
                                    "(comma-separated; explicit authorization)")
    r.add_argument("--profile", default="default", help=argparse.SUPPRESS)
    r.add_argument("--risk", type=int, choices=(1, 2, 3), default=1,
                   help=RISK_HELP)
    r.add_argument("--max-depth", type=int, default=None,
                   help="optional relative URL path-depth limit; omitted means unlimited")
    r.add_argument("--out", default="./runs/latest")
    r.add_argument("--headful", action="store_true")
    r.add_argument("--allow-destructive", action="store_true")
    r.add_argument("--allow-upload-cleanup", action="store_true",
                   help="allow the explicitly supplied in-scope DELETE cleanup URL")
    r.add_argument("--upload-cleanup-url", default=None,
                   help="exact in-scope DELETE URL that removes the agent's test upload")
    r.add_argument("--allow-safe-get-replay", action="store_true",
                   help="allow replay of exact observed URLs supplied with --safe-get-url")
    r.add_argument("--allow-authz-non-get", action="store_true",
                   help="allow exact observed non-GET authorization comparisons")
    r.add_argument("--safe-get-url", action="append", default=[], dest="safe_get_urls",
                   help="exact observed in-scope GET URL allowed once for replay (repeatable)")
    r.add_argument("--timeout-ms", type=int, default=15000)
    r.add_argument("--engine-timeout", type=float, default=None,
                   help="engine HTTP timeout in seconds; omitted means a bounded default (10s connect, %ds read)" % int(READ_CEILING_S))
    r.add_argument("--max-actions", type=int, default=None, dest="max_steps")
    r.add_argument("--max-seconds", type=int, default=None, dest="max_seconds",
                   help=MAX_SECONDS_HELP)
    r.add_argument("--browser-sandbox", choices=("auto", "on", "off"),
                   default="auto", help=BROWSER_SANDBOX_HELP)
    r.add_argument("--verify-target-tls", action="store_true",
                   help=VERIFY_TLS_HELP)
    r.add_argument("--strict-egress", action="store_true", help=STRICT_EGRESS_HELP)
    r.add_argument("--max-capture-bytes", type=int, default=None,
                   help=MAX_CAPTURE_HELP)
    r.add_argument("--ca-cert", default=None,
                   help="PEM bundle for a private CA; makes the probe/API "
                        "transport VERIFY against it instead of trusting "
                        "only public roots. Chromium runs its own verifier "
                        "and is unaffected")
    r.add_argument("--max-rps", type=float, default=0.0,
                   help="per-host ceiling on the scan's own request rate; "
                        "0 (default) is unlimited")
    r.add_argument("--max-safety-incidents", type=int,
                   default=DEFAULT_MAX_SAFETY_INCIDENTS,
                   help="abort the run after this many REFUSED out-of-scope "
                        "events (off-scope navigation, --deny match, "
                        "off-scope redirect); 0 disables the breaker "
                        "(default: %d)" % DEFAULT_MAX_SAFETY_INCIDENTS)
    r.add_argument("--max-discovered-actions", type=int, default=None,
                   dest="capture_max_actions",
                   help="optional per-page observer bound; omitted means unlimited")
    r.add_argument("--browser", default="chromium",
                   choices=["chromium", "firefox", "webkit"])
    r.add_argument("--username", default=None, help="log in with this user")
    r.add_argument("--password", default=None, help="password for --username")
    r.add_argument("--login-url", default=None,
                   help="login page (found automatically when omitted)")
    r.add_argument("--login-body", default=None,
                   help="JSON document to POST to --login-url instead of "
                        "filling a form, with {username} and {password} "
                        "substituted (single-page applications log in this "
                        "way and often render no form at all)")
    r.add_argument("--login-fields", default=None,
                   help="JSON object of URL-encoded form fields to POST to "
                        "--login-url, with {username} and {password} "
                        "substituted")
    r.add_argument("--additional-login-url", action="append", default=[],
                   dest="additional_login_urls",
                   help="additional API login endpoint using the same explicit "
                        "credentials and form fields (repeatable)")
    r.add_argument("--additional-login", default=None,
                   dest="additional_logins",
                   help="JSON array of additional primary login profiles; each "
                        "has url, username, password, and body or fields")
    r.add_argument("--mfa-code", default=None,
                   help="static second-factor code to submit if challenged "
                        "after login (a backup code, or one copied from an "
                        "authenticator app for this run)")
    r.add_argument("--auth-file", default=None,
                   help="JSON file with username/password/cookies/headers")
    r.add_argument("--cookie", action="append", default=[],
                   help="name=value session cookie (repeatable)")
    r.add_argument("--header", action="append", default=[],
                   help="'Name: value' sent with every request (repeatable)")
    r.add_argument("--bearer", default=None, help="bearer token")
    r.add_argument("--secondary-cookie", action="append", default=[],
                   help="secondary identity session cookie (repeatable)")
    r.add_argument("--secondary-header", action="append", default=[],
                   help="secondary identity header (repeatable)")
    r.add_argument("--secondary-bearer", default=None,
                   help="secondary identity bearer token")
    r.add_argument("--secondary-username", default=None,
                   help="log in as the optional secondary identity")
    r.add_argument("--secondary-password", default=None,
                   help="password for --secondary-username")
    r.add_argument("--secondary-login-url", default=None,
                   help="login page for the optional secondary identity")
    r.add_argument("--secondary-login-fields", default=None,
                   help="JSON object of URL-encoded form fields for the "
                        "optional secondary identity")
    r.add_argument("--secondary-additional-login-url", action="append",
                   default=[],
                   dest="secondary_additional_login_urls",
                   help="additional secondary login endpoint using the same "
                        "form fields (repeatable)")
    r.add_argument("--deny", action="append", default=[],
                   help="never request urls containing this substring (repeatable)")
    r.add_argument("--test-data", action="append", default=[], dest="test_data",
                   metavar="JSON",
                   help='a value the operator authorises, named exactly: '
                        '\'{"path":"/cart/coupon","field":"code","value":"SAVE10",'
                        '"replays":2}\' (repeatable; shown in the report)')
    r.add_argument("--allow-internal-targets", action="store_true",
                   help="acknowledge and permit a target/scope naming a "
                        "loopback, link-local, private, or reserved address "
                        "(e.g. an internal staging app) - refused by "
                        "default")
    r.add_argument("--proxy-server", default=None,
                   help="enterprise proxy the browser sends all traffic "
                        "through, e.g. http://proxy.corp.example:8080")
    r.add_argument("--proxy-username", default=None,
                   help="basic-auth username for --proxy-server")
    r.add_argument("--proxy-password", default=None,
                   help="basic-auth password for --proxy-server")
    r.add_argument("--proxy-bypass", default=None,
                   help="comma-separated hosts the proxy should NOT be used "
                        "for, e.g. localhost,*.internal.example")
    r.add_argument("--proxy-auth-scheme", default="basic",
                   choices=["basic", "digest", "ntlm", "negotiate"],
                   help="how to authenticate to --proxy-server ITSELF (not "
                        "the target) when it challenges the CONNECT with a "
                        "407; Chromium only ever attempts Basic on its own, "
                        "so digest/ntlm/negotiate route through the local "
                        "relay")
    r.add_argument("--client-cert", default=None,
                   help="PEM client certificate for mutual TLS, with "
                        "--client-key and --client-cert-origin")
    r.add_argument("--client-key", default=None,
                   help="PEM private key for --client-cert")
    r.add_argument("--client-cert-origin", default=None,
                   help="origin (scheme://host[:port]) the client "
                        "certificate is presented to; required alongside "
                        "--client-cert/--client-key")
    r.add_argument("--target-auth", default=None, choices=["ntlm"],
                   help="authenticate TO THE TARGET (not a proxy) before "
                        "scanning; requires --target-auth-username and "
                        "--target-auth-password. NTLM is supported: "
                        "the local relay TLS-intercepts the target "
                        "connection and completes the NTLMv2 handshake on "
                        "the agent's behalf")
    r.add_argument("--target-auth-username", default=None,
                   help="'DOMAIN\\\\user' for --target-auth (case sent "
                        "verbatim)")
    r.add_argument("--target-auth-password", default=None,
                   help="password for --target-auth-username")
    r.add_argument("--webhook-url", default=None,
                   help="POST a JSON completion summary here when the run "
                        "finishes (run id, target, finding/candidate "
                        "counts, severity breakdown, coverage status) - a "
                        "Slack incoming webhook, a Jira automation rule, "
                        "or any HTTP-based SIEM/ticketing intake can all "
                        "consume this without a dedicated integration")
    r.add_argument("--pdf", action="store_true",
                   help="also render report.pdf, using the report's own "
                        "print stylesheet through a headless browser - the "
                        "same thing printing report.html from a browser "
                        "already produces, done for the operator")
    r.add_argument("--fail-on", default="none",
                   choices=["none", "info", "low", "medium", "high", "critical"],
                   help="exit non-zero when a finding at or above this severity is new")
    r.add_argument("--require-complete", action="store_true",
                   help="exit 4 if the run did not achieve complete coverage")
    r.add_argument("--fail-on-candidates", action="store_true",
                   help="count candidates too, not just confirmed findings")
    r.add_argument("--baseline", default=None,
                   help="previous report.json; only new findings fail the build")
    r.add_argument("--quiet", action="store_true")

    s = sub.add_parser("stop", help="ask a running scan to stop gracefully, by id")
    s.add_argument("--engine", dest="engine", required=True,
                   help="base URL of the SekuScan engine")
    s.add_argument("--api-key", default=None,
                   help="engine API key; falls back to SEKUSCAN_API_KEY")
    s.add_argument("run_id")
    s.add_argument("--reason", default="", help="recorded on the run as why it stopped")
    s.add_argument("--engine-timeout", type=float, default=None,
                   help="engine HTTP timeout in seconds; omitted means a bounded default (10s connect, %ds read)" % int(READ_CEILING_S))

    args = parser.parse_args(argv)
    api_key = args.api_key or os.environ.get(ci.ENV_API_KEY)
    if not api_key:
        print(f"error: --api-key is required (or set {ci.ENV_API_KEY})",
             file=sys.stderr)
        return ci.EXIT_USAGE
    if args.command == "stop":
        return stop_run_cli(engine=args.engine, api_key=api_key, run_id=args.run_id,
                            reason=args.reason, engine_timeout=args.engine_timeout)
    return run_agent(engine=args.engine, api_key=api_key, target=args.target,
                     user_agent=getattr(args, "user_agent", None),
                     scope=with_ports(args.target, args.scope, args.ports),
                     profile=args.profile, risk=args.risk,
                     max_depth=args.max_depth, out=args.out,
                     username=args.username, password=args.password,
                     login_url=args.login_url, mfa_code=args.mfa_code,
                     login_body=args.login_body,
                     login_fields=args.login_fields,
                     additional_login_urls=args.additional_login_urls,
                     additional_logins=args.additional_logins,
                     auth_file=args.auth_file,
                     cookie=args.cookie, header=args.header, bearer=args.bearer,
                     secondary_cookie=args.secondary_cookie,
                     secondary_header=args.secondary_header,
                     secondary_bearer=args.secondary_bearer,
                     secondary_username=args.secondary_username,
                     secondary_password=args.secondary_password,
                     secondary_login_url=args.secondary_login_url,
                     secondary_login_fields=args.secondary_login_fields,
                     secondary_additional_login_urls=(
                         args.secondary_additional_login_urls),
                     fail_on=args.fail_on, baseline=args.baseline,
                     fail_on_candidates=args.fail_on_candidates,
                     require_complete=args.require_complete, deny=args.deny,
                     allow_internal_targets=args.allow_internal_targets,
                     test_data=args.test_data,
                     headful=args.headful, allow_destructive=args.allow_destructive,
                     engine_timeout=args.engine_timeout,
                     allow_upload_cleanup=args.allow_upload_cleanup,
                     upload_cleanup_url=args.upload_cleanup_url,
                     allow_safe_get_replay=args.allow_safe_get_replay,
                     allow_authz_non_get=args.allow_authz_non_get,
                     safe_get_urls=args.safe_get_urls,
                     timeout_ms=args.timeout_ms, max_steps=args.max_steps,
                     max_seconds=args.max_seconds,
                     max_safety_incidents=args.max_safety_incidents,
                     max_rps=args.max_rps,
                     ca_cert=args.ca_cert,
                     browser_sandbox=args.browser_sandbox,
                     verify_target_tls=args.verify_target_tls,
                     strict_egress=args.strict_egress,
                     max_capture_bytes=args.max_capture_bytes,
                     capture_max_actions=args.capture_max_actions,
                     quiet=args.quiet, browser=args.browser,
                     proxy_server=args.proxy_server,
                     proxy_username=args.proxy_username,
                     proxy_password=args.proxy_password,
                     proxy_bypass=args.proxy_bypass,
                     proxy_auth_scheme=args.proxy_auth_scheme,
                     client_cert=args.client_cert, client_key=args.client_key,
                     client_cert_origin=args.client_cert_origin,
                     target_auth=args.target_auth,
                     target_auth_username=args.target_auth_username,
                     target_auth_password=args.target_auth_password,
                     webhook_url=args.webhook_url, pdf=args.pdf)


def main(argv: Optional[list[str]] = None) -> int:
    if typer is None:
        return _argparse_main(argv)

    app = typer.Typer(add_completion=False, help="SekuScan thin agent")

    def _print_version(value: bool) -> None:
        if value:
            print(VERSION_LINE)
            raise typer.Exit()

    @app.callback()
    def _root(version: bool = typer.Option(
            False, "--version", is_eager=True, callback=_print_version,
            help="print the agent and protocol versions")) -> None:
        """SekuScan thin agent: executes engine directives, observes, reports back."""

    @app.command()
    def run(
        engine: str = typer.Option(..., "--engine",
                                  help="SekuScan engine base URL"),
        api_key: Optional[str] = typer.Option(
            None, "--api-key",
            help="engine API key; falls back to SEKUSCAN_API_KEY (preferred - "
                 "argv is visible to anyone on the same host via `ps`)"),
        target: str = typer.Option(..., help="start URL"),
        scope: list[str] = typer.Option([], "--scope",
                                        help="allowed origin (repeatable)"),
        ports: str = typer.Option("", "--ports",
                                  help="also scan these ports on every in-scope host "
                                       "(comma-separated; explicit authorization)"),
        profile: str = typer.Option("default", hidden=True),
        risk: int = typer.Option(1, "--risk",
                                 help=RISK_HELP),
        max_depth: Optional[int] = typer.Option(
            None, "--max-depth",
            help="optional relative URL path-depth limit; omitted means unlimited"),
        out: str = typer.Option("./runs/latest", help="output directory"),
        headful: bool = typer.Option(False, "--headful", help="show the browser"),
        user_agent: Optional[str] = typer.Option(
            None, "--user-agent",
            help="override the User-Agent sent to the TARGET; the default "
                 "identifies SekuScan and its version"),
        allow_destructive: bool = typer.Option(False, "--allow-destructive"),
        allow_upload_cleanup: bool = typer.Option(
            False, "--allow-upload-cleanup",
            help="allow the explicitly supplied in-scope DELETE cleanup URL"),
        upload_cleanup_url: Optional[str] = typer.Option(
            None, "--upload-cleanup-url",
            help="exact in-scope DELETE URL that removes the agent's test upload"),
        allow_safe_get_replay: bool = typer.Option(
            False, "--allow-safe-get-replay",
            help="allow replay of exact URLs supplied with --safe-get-url"),
        allow_authz_non_get: bool = typer.Option(
            False, "--allow-authz-non-get",
            help="allow exact observed non-GET authorization comparisons"),
        safe_get_urls: list[str] = typer.Option(
            [], "--safe-get-url",
            help="exact observed in-scope GET URL allowed for one replay"),
        timeout_ms: int = typer.Option(15000, "--timeout-ms"),
        engine_timeout: Optional[float] = typer.Option(
            None, "--engine-timeout",
            help="engine HTTP timeout in seconds; omitted means a bounded default (10s connect, %ds read)" % int(READ_CEILING_S)),
        max_seconds: Optional[int] = typer.Option(
            None, "--max-seconds",
            help=MAX_SECONDS_HELP),
        max_steps: Optional[int] = typer.Option(
            None, "--max-actions",
            help="operator escape hatch; by default the run ends when there is "
                 "nothing left to test"),
        browser_sandbox: str = typer.Option(
            "auto", "--browser-sandbox", help=BROWSER_SANDBOX_HELP),
        verify_target_tls: bool = typer.Option(
            False, "--verify-target-tls", help=VERIFY_TLS_HELP),
        strict_egress: bool = typer.Option(
            False, "--strict-egress", help=STRICT_EGRESS_HELP),
        max_capture_bytes: Optional[int] = typer.Option(
            None, "--max-capture-bytes", help=MAX_CAPTURE_HELP),
        ca_cert: Optional[str] = typer.Option(
            None, "--ca-cert",
            help="PEM bundle for a private CA; makes the probe/API transport "
                 "VERIFY against it instead of trusting only public roots. "
                 "Chromium runs its own verifier and is unaffected"),
        max_rps: float = typer.Option(
            0.0, "--max-rps",
            help="per-host ceiling on the scan's own request rate; 0 "
                 "(default) is unlimited. Honoured by both probe transports"),
        max_safety_incidents: int = typer.Option(
            DEFAULT_MAX_SAFETY_INCIDENTS, "--max-safety-incidents",
            help="abort the run after this many REFUSED out-of-scope events "
                 "(off-scope navigation, --deny match, off-scope redirect); "
                 "0 disables the breaker"),
        capture_max_actions: Optional[int] = typer.Option(
            None, "--max-discovered-actions",
            help="optional per-page observer bound; omitted means unlimited"),
        browser: str = typer.Option("chromium", "--browser"),
        username: Optional[str] = typer.Option(None, "--username",
                                               help="log in with this user"),
        password: Optional[str] = typer.Option(None, "--password",
                                               help="password for --username"),
        login_url: Optional[str] = typer.Option(
            None, "--login-url", help="login page (found automatically when omitted)"),
        login_body: Optional[str] = typer.Option(
            None, "--login-body",
            help="JSON document to POST to --login-url instead of filling a "
                 "form; {username} and {password} are substituted"),
        login_fields: Optional[str] = typer.Option(
            None, "--login-fields",
            help="JSON object of URL-encoded form fields to POST to "
                 "--login-url; {username} and {password} are substituted"),
        additional_login_urls: list[str] = typer.Option(
            [], "--additional-login-url",
            help="additional API login endpoint using the same explicit "
                 "credentials and form fields (repeatable)"),
        additional_logins: Optional[str] = typer.Option(
            None, "--additional-login",
            help="JSON array of additional primary login profiles; each has "
                 "url, username, password, and body or fields"),
        mfa_code: Optional[str] = typer.Option(
            None, "--mfa-code",
            help="static second-factor code to submit if challenged after "
                 "login (a backup code, or one copied from an authenticator "
                 "app for this run)"),
        auth_file: Optional[str] = typer.Option(
            None, "--auth-file",
            help="JSON file with username/password/cookies/headers"),
        cookie: list[str] = typer.Option([], "--cookie",
                                         help="name=value session cookie"),
        header: list[str] = typer.Option([], "--header",
                                         help="'Name: value' for every request"),
        bearer: Optional[str] = typer.Option(None, "--bearer", help="bearer token"),
        secondary_cookie: list[str] = typer.Option(
            [], "--secondary-cookie",
            help="session cookie for the optional secondary identity"),
        secondary_header: list[str] = typer.Option(
            [], "--secondary-header",
            help="header for the optional secondary identity"),
        secondary_bearer: Optional[str] = typer.Option(
            None, "--secondary-bearer",
            help="bearer token for the optional secondary identity"),
        secondary_username: Optional[str] = typer.Option(
            None, "--secondary-username",
            help="log in as the optional secondary identity"),
        secondary_password: Optional[str] = typer.Option(
            None, "--secondary-password",
            help="password for --secondary-username"),
        secondary_login_url: Optional[str] = typer.Option(
            None, "--secondary-login-url",
            help="login page for the optional secondary identity"),
        secondary_login_fields: Optional[str] = typer.Option(
            None, "--secondary-login-fields",
            help="JSON object of URL-encoded form fields for the optional "
                 "secondary identity"),
        secondary_additional_login_urls: list[str] = typer.Option(
            [], "--secondary-additional-login-url",
            help="additional secondary login endpoint using the same form "
                 "fields (repeatable)"),
        deny: list[str] = typer.Option(
            [], "--deny",
            help="never request urls containing this substring (repeatable)"),
        test_data: list[str] = typer.Option(
            [], "--test-data",
            help='a value the operator authorises, named exactly: \'{"path":'
                 '"/cart/coupon","field":"code","value":"SAVE10","replays":2}\' '
                 "(repeatable; shown in the report)"),
        allow_internal_targets: bool = typer.Option(
            False, "--allow-internal-targets",
            help="acknowledge and permit a target/scope naming a loopback, "
                 "link-local, private, or reserved address - refused by "
                 "default"),
        proxy_server: Optional[str] = typer.Option(
            None, "--proxy-server",
            help="enterprise proxy the browser sends all traffic through, "
                 "e.g. http://proxy.corp.example:8080"),
        proxy_username: Optional[str] = typer.Option(
            None, "--proxy-username", help="basic-auth username for --proxy-server"),
        proxy_password: Optional[str] = typer.Option(
            None, "--proxy-password", help="basic-auth password for --proxy-server"),
        proxy_bypass: Optional[str] = typer.Option(
            None, "--proxy-bypass",
            help="comma-separated hosts the proxy should NOT be used for, "
                 "e.g. localhost,*.internal.example"),
        proxy_auth_scheme: str = typer.Option(
            "basic", "--proxy-auth-scheme",
            help="how to authenticate to --proxy-server ITSELF (not the "
                 "target) when it challenges the CONNECT with a 407: "
                 "basic/digest/ntlm/negotiate. Chromium only ever attempts "
                 "Basic on its own, so digest/ntlm/negotiate route through "
                 "the local relay"),
        client_cert: Optional[str] = typer.Option(
            None, "--client-cert",
            help="PEM client certificate for mutual TLS, with --client-key "
                 "and --client-cert-origin"),
        client_key: Optional[str] = typer.Option(
            None, "--client-key", help="PEM private key for --client-cert"),
        client_cert_origin: Optional[str] = typer.Option(
            None, "--client-cert-origin",
            help="origin (scheme://host[:port]) the client certificate is "
                 "presented to; required alongside --client-cert/--client-key"),
        target_auth: Optional[str] = typer.Option(
            None, "--target-auth",
            help="authenticate TO THE TARGET (not a proxy) before "
                 "scanning; requires --target-auth-username and "
                 "--target-auth-password. NTLM is supported"),
        target_auth_username: Optional[str] = typer.Option(
            None, "--target-auth-username",
            help="'DOMAIN\\user' for --target-auth (case sent verbatim)"),
        target_auth_password: Optional[str] = typer.Option(
            None, "--target-auth-password",
            help="password for --target-auth-username"),
        webhook_url: Optional[str] = typer.Option(
            None, "--webhook-url",
            help="POST a JSON completion summary here when the run "
                 "finishes - a Slack incoming webhook, a Jira automation "
                 "rule, or any HTTP-based SIEM/ticketing intake"),
        webhook_format: str = typer.Option(
            "generic", "--webhook-format",
            help="webhook payload shape: generic (flat JSON - what a Jira "
                 "automation rule or SIEM HTTP source wants), slack (Block "
                 "Kit), or msteams (MessageCard)"),
        pdf: bool = typer.Option(
            False, "--pdf",
            help="also render report.pdf, using the report's own print "
                 "stylesheet through a headless browser"),
        fail_on: str = typer.Option(
            "none", "--fail-on",
            help="exit non-zero on a new finding at or above this severity"),
        fail_on_candidates: bool = typer.Option(False, "--fail-on-candidates"),
        require_complete: bool = typer.Option(
            False, "--require-complete",
            help="exit 4 if the run did not achieve complete coverage"),
        baseline: Optional[str] = typer.Option(
            None, "--baseline",
            help="previous report.json; only new findings fail the build"),
        quiet: bool = typer.Option(False, "--quiet"),
    ) -> None:
        resolved_api_key = api_key or os.environ.get(ci.ENV_API_KEY)
        if not resolved_api_key:
            print(f"error: --api-key is required (or set {ci.ENV_API_KEY})",
                 file=sys.stderr)
            raise typer.Exit(ci.EXIT_USAGE)
        code = run_agent(engine=engine, api_key=resolved_api_key, target=target,
                         user_agent=user_agent,
                         scope=with_ports(target, list(scope),
                                          [int(p) for p in ports.split(",") if p]),
                         profile=profile, risk=risk,
                         max_depth=max_depth, out=out,
                         headful=headful,
                         allow_destructive=allow_destructive, timeout_ms=timeout_ms,
                         engine_timeout=engine_timeout,
                         allow_upload_cleanup=allow_upload_cleanup,
                         upload_cleanup_url=upload_cleanup_url,
                         allow_safe_get_replay=allow_safe_get_replay,
                         allow_authz_non_get=allow_authz_non_get,
                         safe_get_urls=list(safe_get_urls),
                         max_steps=max_steps, max_seconds=max_seconds,
                         max_safety_incidents=max_safety_incidents,
                         max_rps=max_rps,
                         ca_cert=ca_cert,
                         browser_sandbox=browser_sandbox,
                         verify_target_tls=verify_target_tls,
                         strict_egress=strict_egress,
                         max_capture_bytes=max_capture_bytes,
                         capture_max_actions=capture_max_actions,
                         quiet=quiet, browser=browser,
                         username=username, password=password,
                         login_url=login_url, mfa_code=mfa_code,
                         login_body=login_body,
                         login_fields=login_fields,
                         additional_login_urls=list(additional_login_urls),
                         additional_logins=additional_logins,
                         auth_file=auth_file,
                         cookie=list(cookie), header=list(header), bearer=bearer,
                         secondary_cookie=list(secondary_cookie),
                         secondary_header=list(secondary_header),
                         secondary_bearer=secondary_bearer,
                         secondary_username=secondary_username,
                         secondary_password=secondary_password,
                         secondary_login_url=secondary_login_url,
                         secondary_login_fields=secondary_login_fields,
                         secondary_additional_login_urls=(
                             list(secondary_additional_login_urls)),
                         fail_on=fail_on, baseline=baseline,
                         fail_on_candidates=fail_on_candidates,
                         require_complete=require_complete, deny=list(deny),
                         allow_internal_targets=allow_internal_targets,
                         test_data=list(test_data),
                         proxy_server=proxy_server,
                         proxy_username=proxy_username,
                         proxy_password=proxy_password,
                         proxy_bypass=proxy_bypass,
                         proxy_auth_scheme=proxy_auth_scheme,
                         client_cert=client_cert, client_key=client_key,
                         client_cert_origin=client_cert_origin,
                         target_auth=target_auth,
                         target_auth_username=target_auth_username,
                         target_auth_password=target_auth_password,
                         webhook_url=webhook_url,
                         webhook_format=webhook_format, pdf=pdf)
        raise typer.Exit(code)

    @app.command()
    def stop(
        engine: str = typer.Option(..., "--engine",
                                  help="SekuScan engine base URL"),
        run_id: str = typer.Argument(..., help="id of the run to stop"),
        api_key: Optional[str] = typer.Option(
            None, "--api-key",
            help="engine API key; falls back to SEKUSCAN_API_KEY"),
        reason: str = typer.Option(
            "", "--reason", help="recorded on the run as why it stopped"),
        engine_timeout: Optional[float] = typer.Option(
            None, "--engine-timeout",
            help="engine HTTP timeout in seconds; omitted means a bounded default (10s connect, %ds read)" % int(READ_CEILING_S)),
    ) -> None:
        """Ask a running scan to stop gracefully, by id - no process access required."""
        resolved_api_key = api_key or os.environ.get(ci.ENV_API_KEY)
        if not resolved_api_key:
            print(f"error: --api-key is required (or set {ci.ENV_API_KEY})",
                 file=sys.stderr)
            raise typer.Exit(ci.EXIT_USAGE)
        code = stop_run_cli(engine=engine, api_key=resolved_api_key, run_id=run_id,
                            reason=reason, engine_timeout=engine_timeout)
        raise typer.Exit(code)

    try:
        # with standalone_mode=False click *returns* the exit code from
        # typer.Exit instead of raising, so the return value is the verdict
        result = app(args=argv, standalone_mode=False)
        if isinstance(result, int):
            return result
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:
        code = getattr(exc, "exit_code", None)
        if code is None:
            raise
        # click raises Exit for a clean, non-zero finish (our --fail-on gate);
        # only a UsageError carries a message worth printing
        message = getattr(exc, "format_message", None)
        if message is not None:
            print(f"error: {message()}", file=sys.stderr)
        return int(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
