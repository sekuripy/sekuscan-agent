# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Playwright session + passive recorders.

Mechanical only: launch a browser, remember what flew past, hand it to the
engine.  The agent does not decide what to test.
"""

from __future__ import annotations

import base64
import contextlib
import html
import json
import logging
import os
import re
import signal
import sys
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

from ..protocol.models import (AGENT_VERSION, CaptureRules, ConsoleEvent,
                               NetworkEvent, ScopeRules, StateSnapshot)
from ..protocol import grpcweb
from . import relay as relaymod
from .bodies import decode_body, is_streaming_body
from .interaction import registry_script
from .settle import INFLIGHT_SCRIPT
from .taint import taint_script
from . import redaction
from .redaction import REDACTED, redact_headers, redact_text

log = logging.getLogger("sekuscan.agent.browser")

TEXTY = ("text/", "json", "xml", "javascript", "html", "urlencoded", "graphql")
# `stylesheet` is here because a stylesheet names resources - `@font-face
# src:`, `background: url(...)` - that no markup rule can see, so its body has
# to be kept for the engine to read. `_texty` already admits `text/css`.
BODY_TYPES = {"document", "xhr", "fetch", "other", "script", "stylesheet"}
_MAX_BUFFERED_BODY_BYTES = 25 * 1024 * 1024  # ceiling for a response
                                             # Playwright's buffered API is
                                             # asked to hold in memory at once


# Injected into every page before its own scripts run.
#
# A modal dialog is the enemy of an automated browser: it blocks the page that
# raised it, and handling it from the driver costs a round trip per dialog.  So
# the dialog functions are replaced with console writes: a call to `alert()`
# is recorded as a console line the engine reads, instead of raising a dialog.
#
# `confirm()` returning false would make a real branch unreachable:
# `if (confirm("Delete this?")) fetch(DELETE ...)` is a very common shape.
# Returning TRUE is what a user clicking OK does, so it is a side effect and
# follows the operator's `allow_destructive` setting instead of being
# unconditional.
#
# `prompt()` stays null (Cancel): inventing a value to type into an unknown
# field would be guessing.
DIALOG_HOOK = """
(() => {
  const say = (kind, value) => {
    try { console.log('[sekuscan:' + kind + '] ' + String(value)); } catch (e) {}
  };
  try {
    window.alert = (m) => { say('alert', m); };
    window.confirm = (m) => { say('confirm', m); return %(confirm)s; };
    window.prompt = (m) => { say('prompt', m); return null; };
    window.print = () => { say('print', ''); };
  } catch (e) {}
})();
"""


def dialog_hook(allow_destructive: bool = False) -> str:
    """`DIALOG_HOOK` with `confirm()` answered for this run's risk."""
    return DIALOG_HOOK % {"confirm": "true" if allow_destructive else "false"}


# Image, font and media subresources are deliberately NOT blocked at the route
# hook. Aborted requests surface as network failures that the page's own
# scripts and the engine would read as application errors we caused, and the
# time saved is small. Stylesheets are not blocked either: CSS decides what is
# visible, `_click` refuses a control that is not `is_visible()`, and
# `_fill_field` asks `getComputedStyle` whether a field can be filled.


def _is_unreachable_destination(url: Optional[str]) -> bool:
    """Could this refused destination ever have been reached at all?

    The run-level breaker counts how many times the application tried to take
    the browser somewhere the guard refused. A destination that cannot be
    dialled is not somewhere: refusing it prevented nothing, so counting it
    would trip the breaker on harmless traffic.

    Three shapes qualify:

        http://example.test:99999/        port out of range
        foo:bar                           not a web scheme
        anything.invalid                  `.invalid` is reserved by RFC 2606
                                          so that it never resolves

    A redirect an application issues to a malformed URL built from request
    input is the typical source. What this does NOT excuse is the case the
    breaker exists for: a real redirect to a real host, possibly carrying
    credentials. Those resolve, so they still count.

    The refusal is still RECORDED in the egress ledger either way.
    """
    try:
        parsed = urlparse(url or "")
    except ValueError:
        return True
    if parsed.scheme not in ("http", "https"):
        return True
    host = (parsed.hostname or "").lower()
    if not host or host == "invalid" or host.endswith(".invalid"):
        return True
    try:
        parsed.port          # raises for a port that is not a valid number
    except ValueError:
        return True
    return False


#: What the target sees. Three deliberate parts.
#:
#: A real Chrome prefix, because applications routinely serve degraded or
#: different markup to a user agent they do not recognise.
#:
#: NOT "HeadlessChrome", which Playwright sends by default and which many WAFs
#: and bot filters block.
#:
#: And a `SekuScan/<version> (+url)` suffix, the convention crawlers have used
#: since Googlebot, so an operator who finds the scanner in their logs can tell
#: who it is: this product does not hide from the owner of the estate it tests.
#: Override per run with `--user-agent` when a target demands something else.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36 "
    "SekuScan/%s (+https://www.sekuscan.com/)" % AGENT_VERSION
)


#: How long ONE handle's close()/dispose() may run before teardown gives up
#: on it and moves to the next.
#:
#: A handle's close()/dispose() can block the main thread indefinitely inside
#: Playwright's own dispatch loop. The thread is still executing bytecode, which
#: is the condition `_action_deadline` in `agent/cli.py` relies on to interrupt
#: a stuck Playwright sync call with SIGALRM. `close()`/`dispose()` take no
#: timeout in Playwright's API and this runs after the progress watchdog has
#: been stopped, so nothing else bounds it.
RELEASE_TIMEOUT_S = 20.0


class _ReleaseTimeout(BaseException):
    """One handle's close()/dispose() outstayed its welcome.

    `BaseException`, like `_ActionTimeout` in `agent/cli.py`: it is raised from
    a SIGALRM handler into whatever happens to be running, here Playwright's
    own driver code. Caught inside `_release` itself, so one stuck handle does
    not abort the loop in `stop()` and skip every closer queued after it.
    """


@contextlib.contextmanager
def _release_deadline():
    """Same mechanism as `agent/cli.py`'s `_action_deadline`: SIGALRM on the
    main thread, because Playwright's sync API is bound to the thread that
    created it - a worker thread cannot make this call at all, so a
    thread-and-join timeout is not an option here, only an interrupt.

    A no-op off the main thread or without SIGALRM (non-POSIX).
    """
    armed = False
    previous = None
    if (hasattr(signal, "SIGALRM")
            and threading.current_thread() is threading.main_thread()):
        def _fire(_signum: int, _frame: Any) -> None:
            raise _ReleaseTimeout()

        previous = signal.signal(signal.SIGALRM, _fire)
        # `signal.alarm` takes whole seconds and 0 means "cancel" - so a
        # sub-second override (a test wanting this to fire quickly) must
        # never truncate down to that.
        signal.alarm(int(RELEASE_TIMEOUT_S) or 1)
        armed = True
    try:
        yield
    finally:
        if armed:
            signal.alarm(0)
            if previous is not None:
                signal.signal(signal.SIGALRM, previous)


def _release(handle: Any) -> None:
    """Release a Playwright handle, whichever verb IT uses.

    An `APIRequestContext` has `dispose()` and no `close()`, while a
    `BrowserContext` and a `Browser` have `close()`. Asking the object which
    verb it supports lets all of them go through the same teardown loop.
    """
    if handle is None:
        return
    for verb in ("close", "dispose"):
        method = getattr(handle, verb, None)
        if callable(method):
            try:
                with _release_deadline():
                    method()
            except _ReleaseTimeout:
                log.warning("%s.%s() did not return within %ss - abandoning "
                            "teardown for it and moving on",
                            type(handle).__name__, verb, RELEASE_TIMEOUT_S)
            return
    log.debug("no close/dispose on %r", type(handle).__name__)


SANDBOX_HELP = (
    "The Chromium sandbox could not start on this host. On Ubuntu 23.10+/24.04 "
    "run `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (or "
    "run the agent as a dedicated user that unprivileged user namespaces are "
    "allowed for). In Docker, run with `--security-opt "
    "seccomp=seccomp_profile.json` (shipped with the agent). To run without "
    "the sandbox, pass `--browser-sandbox off`.")


def launch_browser(launcher: Any, browser_name: str, mode: str,
                   **launch_kwargs: Any) -> tuple[Any, bool]:
    """Launch with the Chromium sandbox per `--browser-sandbox`; returns
    `(browser, sandboxed)`. Playwright's own default is NO sandbox, so it is
    asked for explicitly. `auto` falls back loudly, `on` refuses to."""
    if mode == "on" and browser_name != "chromium":
        raise RuntimeError(
            "--browser-sandbox on needs --browser chromium: the sandbox is "
            "only requested for Chromium, so %s would run unsandboxed"
            % browser_name)
    if mode == "off" or browser_name != "chromium":
        return launcher.launch(**launch_kwargs), False
    try:
        return launcher.launch(chromium_sandbox=True, **launch_kwargs), True
    except Exception as exc:
        if "sandbox" not in str(exc).lower():
            raise
        if mode == "on":
            raise RuntimeError(SANDBOX_HELP) from exc
    print("warning: browser sandbox unavailable on this host; running "
          "without it; --browser-sandbox on to require it", file=sys.stderr)
    return launcher.launch(**launch_kwargs), False


class BrowserSession:
    def __init__(self, headless: bool = True, timeout_ms: int = 15000,
                 capture: Optional[CaptureRules] = None,
                 user_agent: Optional[str] = DEFAULT_USER_AGENT,
                 browser_name: str = "chromium",
                 ignore_https_errors: bool = True,
                 extra_headers: Optional[dict[str, str]] = None,
                 cookies: Optional[dict[str, str]] = None,
                 cookie_url: Optional[str] = None,
                 secondary_headers: Optional[dict[str, str]] = None,
                 secondary_cookies: Optional[dict[str, str]] = None,
                 secondary_cookie_url: Optional[str] = None,
                 secondary_username: Optional[str] = None,
                 secondary_password: Optional[str] = None,
                 secondary_login_url: Optional[str] = None,
                 secondary_login_fields: Optional[str] = None,
                 secondary_additional_login_urls: Optional[list[str]] = None,
                 login_fields: Optional[str] = None,
                 additional_login_urls: Optional[list[str]] = None,
                 additional_logins: Optional[list[dict[str, str]]] = None,
                 json_login_url: Optional[str] = None,
                 json_login_body: Optional[str] = None,
                 json_login_username: Optional[str] = None,
                 json_login_password: Optional[str] = None,
                 scope_origins: Optional[list[str]] = None,
                 credential_origins: Optional[list[str]] = None,
                 deny_substrings: Optional[list[str]] = None,
                 allow_subdomains: bool = False,
                 max_depth: Optional[int] = None,
                 proxy_server: Optional[str] = None,
                 proxy_username: Optional[str] = None,
                 proxy_password: Optional[str] = None,
                 proxy_bypass: Optional[str] = None,
                 client_cert_path: Optional[str] = None,
                 client_key_path: Optional[str] = None,
                 client_cert_origin: Optional[str] = None,
                 ca_cert_path: Optional[str] = None,
                 target_auth_username: Optional[str] = None,
                 target_auth_password: Optional[str] = None,
                 allow_destructive: bool = False,
                 browser_sandbox: str = "auto",
                 verify_target_tls: bool = False,
                 strict_egress: bool = False):
        self.headless = headless
        self.browser_sandbox = browser_sandbox
        #: Whether the browser that actually launched has its sandbox on.
        self.sandboxed: Optional[bool] = None
        self.strict_egress = strict_egress
        # The operator opted in to checking the TARGET's certificate.
        if verify_target_tls:
            ignore_https_errors = False
        self.timeout_ms = timeout_ms
        self.allow_destructive = allow_destructive
        self.capture = capture or CaptureRules()
        self.user_agent = user_agent
        self.browser_name = browser_name
        self.ignore_https_errors = ignore_https_errors
        self.extra_headers = extra_headers or {}
        redaction.register_operator_headers(self.extra_headers)
        self.preset_cookies = cookies or {}
        self.cookie_url = cookie_url
        self.secondary_headers = secondary_headers or {}
        self.secondary_cookies = secondary_cookies or {}
        self.secondary_cookie_url = secondary_cookie_url
        # These values stay in the agent process. They are used only to create
        # the optional second browser context and are never serialized into a
        # directive, trace, or engine request.
        self.secondary_username = secondary_username
        self.secondary_password = secondary_password
        self.secondary_login_url = secondary_login_url
        self.secondary_login_fields = secondary_login_fields
        self.secondary_additional_login_urls = list(
            secondary_additional_login_urls or [])
        self.login_fields = login_fields
        self.additional_login_urls = list(additional_login_urls or [])
        self.additional_logins = [dict(item) for item in
                                  (additional_logins or [])
                                  if isinstance(item, dict)]
        # A JSON login. Same rule as the secondary credentials above: these
        # values stay in this process and are never serialized into a
        # directive, a trace, or an engine request.
        self.json_login_url = json_login_url
        self.json_login_body = json_login_body
        self.json_login_username = json_login_username
        self.json_login_password = json_login_password
        #: Set when a login was accepted only because a cookie already present
        #: before login kept the same value. See `_login_json_endpoint`.
        self.login_evidence_weak: Optional[str] = None
        # What `NODE_EXTRA_CA_CERTS` held before this session changed it, so
        # `stop()` can put it back.
        self._prior_node_ca: Optional[str] = None
        self._set_node_ca = False
        self.json_login_error: Optional[str] = None
        #: Set when the PRIMARY login did not establish a session. Read by
        #: `agent/cli.py` so the operator is told at the top of the run - a
        #: scan that silently fell back to anonymous reports "nothing found"
        #: about an application it never logged into.
        self.login_failed: Optional[str] = None
        self.scope_origins = list(scope_origins or [])
        # "In scope" and "may receive the operator's credentials" are NOT the
        # same policy: a scope covering both `www.example` and `api.example`
        # must not send a bearer that belongs only to `www.example` to both.
        # Callers that care about the distinction pass this narrower
        # list explicitly (`agent/cli.py` defaults it to just the target's
        # own origin); callers that do not are unaffected, since it falls
        # back to the same scope used for everything else.
        self.credential_origins = (list(credential_origins) if credential_origins
                                   is not None else list(self.scope_origins))
        self.deny_substrings = list(deny_substrings or [])
        self.allow_subdomains = allow_subdomains
        self.max_depth = max_depth
        self.proxy_server = proxy_server
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.proxy_bypass = proxy_bypass
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.client_cert_origin = client_cert_origin
        #: PEM bundle for a private CA the probe transport should trust.
        self.ca_cert_path = ca_cert_path
        # NTLM-to-the-TARGET (not a proxy). Agent-local only, same rule as
        # `client_cert_path`/secondary-identity credentials above - never
        # serialized into a directive or an engine request. Non-empty
        # in both fields is what `_maybe_start_relay()` reads to decide
        # whether the relay needs to start for THIS reason, independent of
        # whether `proxy_server` is set at all.
        self.target_auth_username = target_auth_username
        self.target_auth_password = target_auth_password
        # Set by `_maybe_start_relay()` in `start()`, when the configured proxy
        # is something Chromium cannot dial itself (SOCKS5 with credentials),
        # or when NTLM-to-target is configured.
        # `relay_port` is read by `_proxy_dict()` (so every context/
        # request-context built from it goes through the relay) and by
        # `execute.py::_probe_raw_query` (the one lane that never goes
        # through a Playwright context at all).
        self._relay: Optional["relaymod.Relay"] = None
        self.relay_port: Optional[int] = None
        # every out-of-scope request the page made, so the report can say
        # where this application sends its users' browsers
        self.egress: list[dict[str, Any]] = []
        # How many extra document requests the scope pre-flight cost the
        # target. Counted rather than put in `egress`, which is capped at
        # 200 and whose `blocked` entries drive the kill switch - flooding
        # it with routine pre-flights would push real refusals out of the
        # evidence and is the opposite of what that ledger is for.
        self.preflight_requests = 0
        # Original values of cookies the agent overwrote; never reported.
        self.cookie_originals: dict[tuple[str, str, str], Optional[str]] = {}
        # How many of those the guard actually REFUSED (a top-level
        # navigation off-scope, a `--deny` match, an off-scope redirect
        # hop). Separate from `egress` on purpose - see `_record_egress`.
        self.safety_incidents = 0
        self._pw = None
        self.browser = None
        self.context = None
        self.page = None
        self._anon_request: Any = None
        self._secondary_request: Any = None
        self._secondary_browser_context: Any = None
        self.secondary_login_error: Optional[str] = None
        self._responses: list[tuple[Any, float]] = []
        self._failures: list[dict[str, Any]] = []
        # Login requests made through Playwright's API client do not pass
        # through the page response event handler. Keep a redacted response
        # event so the engine can verify an explicit agent-side login without
        # mistaking a successful 2xx with no session for authentication.
        self._login_events: list[NetworkEvent] = []
        self._console: list[ConsoleEvent] = []
        self._ws_frames: list[dict[str, Any]] = []
        # Anonymous captures from `_observe_pre_login`, one per distinct
        # login endpoint - see `start()`. They record a pre-login
        # cookie fingerprint to compare against, since every login below is
        # otherwise the first traffic this session ever sends.
        self.pre_login_states: list[StateSnapshot] = []
        self._pre_login_urls: set[str] = set()

    # -- lifecycle ---------------------------------------------------------

    def _maybe_start_relay(self) -> None:
        """Start the local CONNECT relay (`agent/relay.py`) when either:

        * the configured proxy is one Chromium cannot dial on its own -
          SOCKS5 carrying credentials, which Chromium supports for
          HTTP(S)+Basic and for unauthenticated SOCKS5, but never for a
          SOCKS5 handshake that needs a login; or
        * NTLM-to-TARGET is configured - Chromium has no NTLM client of its
          own to hand a target that challenges it, so the relay
          TLS-intercepts and completes the handshake on the agent's behalf
          (see `relay.py`).

        Idempotent; a no-op with no proxy, no target-auth, or a proxy
        Chromium already handles, in which case `_proxy_dict()` takes the
        native path.

        Must run before `_network_context_kwargs()`/`_proxy_dict()` are
        first consulted - i.e. before `new_context()` - which is why this is
        the first thing `start()` does.
        """
        if self._relay is not None:
            return
        target_auth = bool(self.target_auth_username and self.target_auth_password)
        if not self.proxy_server and not target_auth:
            return
        spec = relaymod.parse_upstream(self.proxy_server, self.proxy_username,
                                       self.proxy_password)
        if not (target_auth or relaymod.needs_relay(spec)):
            return
        scope = ScopeRules(origins=self.scope_origins,
                           allow_subdomains=self.allow_subdomains,
                           deny_substrings=self.deny_substrings,
                           max_depth=self.max_depth)
        self._relay = relaymod.Relay(
            spec, scope,
            target_auth_username=self.target_auth_username,
            target_auth_password=self.target_auth_password)
        _, self.relay_port = self._relay.start()
        if target_auth:
            log.info("local relay on 127.0.0.1:%d for NTLM-to-target",
                     self.relay_port)
        else:
            log.info("local relay on 127.0.0.1:%d for socks5-with-auth upstream %s:%d",
                     self.relay_port, spec.host, spec.port)

    def _proxy_dict(self) -> Optional[dict[str, str]]:
        """Playwright's `proxy` dict, or `None` if no proxy was configured.

        Shared by `_network_context_kwargs()` (the primary/secondary browser
        contexts) AND every standalone `self._pw.request.new_context()` call
        (anonymous and secondary API request contexts) - those do not inherit
        anything from the browser context they sit beside, so each one has to
        be handed this explicitly or it goes out direct, unproxied. That
        sharing is also what makes the relay swap below apply everywhere for
        free: every one of those call sites reads this method rather than
        `self.proxy_server` directly.
        """
        if self._relay is not None:
            # Chromium dials the LOCAL relay in plain HTTP-CONNECT terms; the
            # relay is what actually speaks SOCKS5-with-credentials (or
            # completes NTLM) to the real upstream/target. No username/
            # password here - nothing needs to authenticate to a relay that
            # only ever listens on loopback.
            #
            # Checked BEFORE `self.proxy_server` below: an NTLM-to-target-only
            # run starts the relay with no `--proxy-server` at all, and
            # checking `proxy_server` first would send Chromium out direct,
            # bypassing the relay.
            return {"server": "http://127.0.0.1:%d" % self.relay_port}
        if not self.proxy_server:
            return None
        proxy: dict[str, str] = {"server": self.proxy_server}
        if self.proxy_username:
            proxy["username"] = self.proxy_username
        if self.proxy_password:
            proxy["password"] = self.proxy_password
        if self.proxy_bypass:
            proxy["bypass"] = self.proxy_bypass
        return proxy

    def _network_context_kwargs(self) -> dict[str, Any]:
        """`proxy`/`client_certificates` for `new_context()` - shared by the
        primary and secondary contexts, since an enterprise proxy or a
        client-cert requirement applies to the whole session, not to
        whichever identity happens to load first.

        Both are passthrough to Playwright's own support (`BrowserType.launch`'s
        `proxy`, `Browser.new_context`'s `client_certificates`).
        """
        kwargs: dict[str, Any] = {}
        proxy = self._proxy_dict()
        if proxy:
            kwargs["proxy"] = proxy
        if self.client_cert_path and self.client_key_path and self.client_cert_origin:
            kwargs["client_certificates"] = [{
                "origin": self.client_cert_origin,
                "certPath": self.client_cert_path,
                "keyPath": self.client_key_path,
            }]
        if self.strict_egress:
            kwargs["service_workers"] = "block"
        return kwargs

    def async_worker_kwargs(self) -> dict[str, Any]:
        """The ONE place the concurrent-probe transport's policy is derived
        from this session (TLS verification, proxy/relay, mTLS client cert,
        User-Agent): both `cli.py` and `browser_worker.py` construct
        `AsyncProbeWorker(**session.async_worker_kwargs())`, so the batch
        transport cannot drift from the sequential one."""
        return {
            "ignore_https_errors": self.api_ignore_https_errors,
            "proxy": self._proxy_dict(),
            "user_agent": self.user_agent,
            "client_certificates":
                self._network_context_kwargs().get("client_certificates"),
        }

    @property
    def api_ignore_https_errors(self) -> bool:
        """Whether the API (probe) transport should skip TLS verification.

        Supplying a CA is a statement that the operator WANTS verification -
        an option that only adds a root while everything stays
        `ignore_https_errors=True` changes nothing observable and would be a
        knob that does not turn. So a `--ca-cert` run verifies on this
        transport.

        The browser context deliberately keeps `ignore_https_errors`:
        Chromium runs its own verifier and never reads NODE_EXTRA_CA_CERTS
        (see `start()`), so turning verification on there would
        break every page load against exactly the private-CA target this
        option exists to support.
        """
        return False if self.ca_cert_path else self.ignore_https_errors

    def start(self) -> "BrowserSession":
        from playwright.sync_api import sync_playwright

        # Before anything else touches `_proxy_dict()`: `_network_context_kwargs()`
        # below is its first caller.
        self._maybe_start_relay()

        # A private/enterprise CA, for a target whose certificate is real but
        # signed by an authority no public trust store carries.
        #
        # It has to be in the environment BEFORE the driver process starts -
        # Playwright's Node driver reads NODE_EXTRA_CA_CERTS once, at launch
        # - which is why this sits here and not in `_network_context_kwargs`.
        #
        # This trusts the CA for the probe/API transport only. Chromium runs
        # its own verifier and does not read Node's environment, so the
        # browser transport still depends on `ignore_https_errors`.
        if self.ca_cert_path:
            # The variable is PROCESS-wide, so it is remembered here and put
            # back in `stop()`: a later session in the same process must not
            # inherit this run's trust anchor, and two concurrent sessions
            # would otherwise race over a single slot.
            self._prior_node_ca = os.environ.get("NODE_EXTRA_CA_CERTS")
            self._set_node_ca = True
            os.environ["NODE_EXTRA_CA_CERTS"] = self.ca_cert_path
        self._pw = sync_playwright().start()
        launcher = getattr(self._pw, self.browser_name)
        # No `proxy=` here, deliberately. Some older Chromium builds ignore a
        # context-level `proxy` unless the browser process itself was launched
        # with one (even a placeholder). The bundled Chromium honours
        # `new_context(proxy=...)` on its own, so no placeholder is used.
        self.browser, self.sandboxed = launch_browser(
            launcher, self.browser_name, self.browser_sandbox,
            headless=self.headless, args=["--disable-dev-shm-usage"])
        kwargs: dict[str, Any] = {
            "ignore_https_errors": self.ignore_https_errors,
            "viewport": {"width": 1280, "height": 900},
        }
        if self.user_agent:
            kwargs["user_agent"] = self.user_agent
        # `extra_http_headers` is NOT set here, deliberately. Playwright
        # applies context headers to every request the context makes, so a
        # bearer token or an `X-Tenant` header would also go to the target's
        # analytics host, its CDN, and anything else the page embedded. They
        # are added per-request by the route guard below, for credential
        # origins only.
        if self.extra_headers and not self.scope_origins:
            # no scope was supplied: fall back to context-wide headers rather
            # than silently dropping the operator's session
            kwargs["extra_http_headers"] = dict(self.extra_headers)
        kwargs.update(self._network_context_kwargs())
        self.context = self.browser.new_context(**kwargs)
        self.context.add_init_script(dialog_hook(self.allow_destructive))
        # The taint observer watches DOM sinks for values that came from a
        # URL-controlled source.  A sink reached through several function calls
        # is invisible to a pattern but visible to a wrapper.  It observes
        # only - it never injects.
        self.context.add_init_script(taint_script())
        # Records which elements the application wires a click handler onto, so
        # a control that is a `<div>` with a listener can still be driven.
        self.context.add_init_script(registry_script())
        # Counts in-flight fetch/XHR so `agent/settle.py` can ask the page
        # whether the network is quiet instead of waiting Playwright's fixed
        # 500ms `networkidle` floor to infer it. Observe-only; it costs one
        # counter per request.
        self.context.add_init_script(INFLIGHT_SCRIPT)
        if self.preset_cookies and self.cookie_url:
            from urllib.parse import urlparse

            host = urlparse(self.cookie_url).hostname or ""
            try:
                self.context.add_cookies([
                    {"name": name, "value": value, "domain": host, "path": "/"}
                    for name, value in self.preset_cookies.items()])
            except Exception:
                log.warning("could not preset cookies", exc_info=True)
        if self.scope_origins:
            # Installed whenever there is scope to enforce, not only when
            # there are also credentials to protect: an anonymous scan must
            # still notice a page that redirects off-site mid-crawl.
            self._install_egress_guard()
        if self.secondary_headers or self.secondary_cookies:
            secondary_kwargs: dict[str, Any] = {
                "ignore_https_errors": self.ignore_https_errors,
            }
            proxy = self._proxy_dict()
            if proxy:
                secondary_kwargs["proxy"] = proxy
            if self.user_agent:
                secondary_kwargs["user_agent"] = self.user_agent
            if self.secondary_cookies and self.secondary_cookie_url:
                from urllib.parse import urlparse

                host = urlparse(self.secondary_cookie_url).hostname or ""
                secondary_kwargs["storage_state"] = {"cookies": [
                    {"name": name, "value": value, "domain": host, "path": "/",
                     "expires": -1.0, "httpOnly": False, "secure": False,
                     "sameSite": "Lax"}
                    for name, value in self.secondary_cookies.items()]}
            self._secondary_request = self._pw.request.new_context(
                **secondary_kwargs) if self._pw else None
        self.context.set_default_timeout(self.timeout_ms)
        self.context.set_default_navigation_timeout(self.timeout_ms)
        self.page = self.context.new_page()
        self._wire()
        # Every login below is otherwise the FIRST traffic this session ever
        # sends, so without this no pre-login cookie fingerprint of the host
        # would exist to compare against. One shared step ahead of all the
        # login paths - see `_observe_pre_login`.
        self._observe_pre_login(
            [self.json_login_url, *self.additional_login_urls,
             *(login.get("url") for login in self.additional_logins)])
        # A failed PRIMARY login must be reported: otherwise the scan continues
        # ANONYMOUSLY, authenticated surfaces are never reached, and the
        # report says "nothing found" about an application it never logged
        # into. `login_failed` is carried so the agent can state it in the run
        # rather than leaving it in a log nobody reads.
        if self.json_login_url and self.json_login_body:
            if not self.login_json():
                self.login_failed = (self.json_login_error
                                     or "primary JSON login failed")
                log.error("PRIMARY LOGIN FAILED (%s) - this scan will run "
                          "ANONYMOUSLY and authenticated surfaces will not be "
                          "reached", self.login_failed)
        elif self.login_fields and self.json_login_url:
            if self.login_form_fields():
                for login_url in self.additional_login_urls:
                    if not self.login_form_fields(login_url):
                        log.warning("additional form login was not established: %s",
                                    login_url)
            else:
                self.login_failed = (self.json_login_error
                                     or "primary form-fields login failed")
                log.error("PRIMARY LOGIN FAILED (%s) - this scan will run "
                          "ANONYMOUSLY and authenticated surfaces will not be "
                          "reached", self.login_failed)
        for login in self.additional_logins:
            if not self.login_additional(login):
                log.warning("additional primary login was not established: %s",
                            login.get("url", ""))
        if self.secondary_username and self.secondary_password:
            if self.secondary_login_fields:
                established = self.login_secondary_fields(
                    self.secondary_login_url or self.cookie_url or "")
                if established:
                    for login_url in self.secondary_additional_login_urls:
                        if not self.login_secondary_fields(login_url):
                            log.warning(
                                "additional secondary login was not "
                                "established: %s", login_url)
            else:
                self.login_secondary(self.secondary_login_url or self.cookie_url or "")
        return self

    def stop_loading(self) -> None:
        """Abandon a navigation the server is still holding open.

        Playwright gives up on `goto` at its timeout, but Chromium keeps the
        navigation pending, and every later `page.evaluate` (observe's DOM
        collection first) then waits on a document that never arrives - sync
        `evaluate` has no timeout of its own. A server that holds a request
        open instead of answering (a tarpit, or a rate limiter that stalls)
        causes this.
        """
        try:
            cdp = self.context.new_cdp_session(self.page)
            try:
                cdp.send("Page.stopLoading")
            finally:
                cdp.detach()
        except Exception as exc:
            log.debug("stop_loading unavailable (%s)", type(exc).__name__)

    @contextlib.contextmanager
    def csp_bypassed(self):
        """Documents this page loads inside the block ignore their CSP -
        Chromium's own `Page.setBypassCSP`, the call behind Playwright's
        `bypass_csp` context option, but per page and for a bounded span.

        Runs on the primary page, so the session's cookies, the route/egress
        guard, the init scripts and the console/dialog listeners all still
        apply.

        The CDP session must stay ATTACHED for the whole span: the bypass
        belongs to it, and detaching silently reverts it. Switched off
        explicitly as well, so the next load is enforced either way.
        """
        cdp = self.context.new_cdp_session(self.page)
        try:
            cdp.send("Page.setBypassCSP", {"enabled": True})
            yield
        finally:
            try:
                cdp.send("Page.setBypassCSP", {"enabled": False})
            finally:
                cdp.detach()

    def _observe_pre_login(self, urls: list[Optional[str]]) -> None:
        """Anonymously visit each configured login endpoint, once, before any
        credentialed request in `start()` touches it.

        A real page navigation, not `self.context.request` (what
        `login_json`/`login_form_fields` use): that is a raw API call with no
        DOM, so it never goes near the capture path a check reads. `goto`
        here uses the SAME wired page and cookie jar an ordinary crawl visit
        does, and `observe_state` (agent/observe.py) is the SAME function
        that turns any other navigate into a `StateSnapshot`.

        Bounded to one GET per distinct URL - not per surface - and never
        lets a 404, a 405, a redirect, or a connection failure here break the
        login that follows.
        """
        for url in urls:
            url = str(url or "").strip()
            if not url or url in self._pre_login_urls:
                continue
            self._pre_login_urls.add(url)
            try:
                self.page.goto(url, timeout=self.timeout_ms)
            except Exception:
                log.debug("pre-login navigate failed: %s", url, exc_info=True)
                continue
            try:
                from .observe import observe_state  # deferred: observe.py
                                                     # imports this module
                self.pre_login_states.append(observe_state(self, self.capture))
            except Exception:
                log.debug("pre-login observation failed: %s", url, exc_info=True)

    @staticmethod
    def _login_fields(template: str, username: Optional[str],
                      password: Optional[str]) -> dict[str, str]:
        """Fill an explicit JSON form-field template without guessing names."""
        document = json.loads(template)
        if not isinstance(document, dict) or not document:
            raise ValueError("login fields must be a non-empty JSON object")
        out: dict[str, str] = {}
        for key, value in document.items():
            if not isinstance(key, str) or not isinstance(value, (str, int, float, bool)):
                raise ValueError("login fields must map names to scalar values")
            text = str(value).replace("{username}", username or "") \
                              .replace("{password}", password or "")
            out[key] = text
        return out

    def _record_login_response(self, url: str, response: Any,
                               content_type: str,
                               authenticated: bool = False) -> None:
        """Expose only the response side of an explicit local login."""
        try:
            headers = response.headers or {}
            body = redact_text(response.text(), self.capture.body_sample_bytes)
            self._login_events.append(NetworkEvent(
                method="POST", url=url, status=response.status,
                resource_type="fetch",
                mime=(headers.get("content-type") or content_type).split(";", 1)[0],
                request_headers={"content-type": content_type},
                response_headers=redact_headers(headers),
                response_body_sample=body,
                response_length=len(body),
                authenticated=authenticated,
            ))
        except Exception:
            log.debug("login response capture failed", exc_info=True)

    def _login_json_endpoint(self, endpoint: str, primary: bool = True,
                             body_template: Optional[str] = None,
                             username: Optional[str] = None,
                             password: Optional[str] = None) -> bool:
        r"""POST the configured JSON credentials to one explicit endpoint.

        The first endpoint establishes the primary session. Follow-up
        endpoints are useful for applications that mint an independent
        session cookie per module, and must set a NEW cookie or they are
        refused. A 2xx response alone is never evidence of authentication.
        """
        before = {}
        try:
            before = {c.get("name"): c.get("value")
                      for c in self.context.cookies() if c.get("name")}
        except Exception:
            pass
        try:
            template = self.json_login_body if body_template is None \
                else body_template
            login_username = (self.json_login_username if username is None
                               else username)
            login_password = (self.json_login_password if password is None
                               else password)
            body = template.replace(
                "{username}", json.dumps(login_username or "")[1:-1]
            ).replace(
                "{password}", json.dumps(login_password or "")[1:-1])
            json.loads(body)          # a template that broke is not a login
        except (TypeError, ValueError) as exc:
            self.json_login_error = "login body is not valid JSON: %s" % exc
            return False
        try:
            # `max_redirects=0`: a 307/308 preserves the METHOD AND BODY, so
            # following a redirect would re-send the credentials to whatever
            # `Location` names, including another origin.
            #
            # Stopping at the first hop does not weaken the login check,
            # because the cookie comparison below is the authority, not the
            # status. A 3xx is allowed through to that check rather than
            # treated as failure - a login that answers 302-to-dashboard is
            # the ordinary case.
            response = self.context.request.post(
                endpoint, data=body,
                headers={"content-type": "application/json"},
                timeout=self.timeout_ms, max_redirects=0)
        except Exception as exc:                       # noqa: BLE001
            self.json_login_error = "JSON login request failed: %s" % exc
            return False
        if not response.ok and not 300 <= response.status < 400:
            self.json_login_error = ("JSON login answered HTTP %d"
                                     % response.status)
            return False
        # A 200 is not a login. Something has to have been SET - otherwise
        # an application that politely answers `{"isValid":false}` reads as
        # a successful authentication for the rest of the run. For a
        # follow-up endpoint, require a cookie value that changed as a result
        # of this request rather than accepting the primary session again.
        try:
            cookies = {c.get("name"): c.get("value")
                       for c in self.context.cookies() if c.get("name")}
        except Exception:                              # noqa: BLE001
            cookies = {}
        if primary:
            # Any non-preset cookie counts. The anonymous visit to the login
            # PAGE just before this is when an application hands out a CSRF
            # token, a consent flag or a load-balancer cookie, so a FAILED
            # login can look authenticated.
            #
            # Unlike the follow-up branch below, a changed value is not
            # required: a login may keep the pre-login session cookie. When
            # the only evidence is a cookie already present with the same
            # value, the login is accepted and that is recorded as weak
            # evidence (`login_evidence_weak`).
            got = [name for name in cookies
                   if name not in self.preset_cookies]
            changed = [name for name in got
                       if before.get(name) != cookies.get(name)]
            if got and not changed:
                self.login_evidence_weak = (
                    "login accepted on cookies that were already present with "
                    "the same value (%s); the login may not have authenticated"
                    % ", ".join(sorted(got)[:4]))
                log.warning("%s", self.login_evidence_weak)
        else:
            got = [name for name, value in cookies.items()
                   if name not in self.preset_cookies and
                   before.get(name) != value]
        if not got:
            suffix = "new " if not primary else ""
            self.json_login_error = (
                "JSON login returned %d and set no %scookie"
                % (response.status, suffix))
            return False
        self._record_login_response(endpoint, response,
                                     "application/json", authenticated=True)
        if primary:
            log.info("JSON login accepted, %d cookie(s) held", len(got))
        else:
            log.info("additional JSON login accepted at %s", endpoint)
        return True

    def login_json(self) -> bool:
        r"""POST a JSON credential document and keep the session it returns.

        `login_secondary` below fills a RENDERED FORM. A single-page
        application often has none: it posts a JSON document and reads the
        session out of the response.

        Sent through the browser context's own request API, so the
        `Set-Cookie` that comes back lands in the context every later
        navigation uses. No cookie is parsed, copied, or re-attached by
        hand; the browser keeps its own jar.

        Fails CLOSED, the same rule `login_secondary` follows: a login that
        did not work must never quietly become an anonymous crawl that
        reports "no authenticated surfaces found".

        The password is substituted here, in this process. It is never
        serialized into a directive or an engine request - see
        `Credentials`, which carries a handle rather than the secret.
        """
        self.json_login_error = None
        if not (self.json_login_url and self.json_login_body):
            self.json_login_error = "no JSON login configured"
            return False
        if not self.context:
            self.json_login_error = "browser context is not started"
            return False
        if not self._login_json_endpoint(self.json_login_url, primary=True):
            return False
        before = dict(self._login_cookie_snapshot) \
            if hasattr(self, "_login_cookie_snapshot") else {}
        try:
            self._login_cookie_snapshot = {
                c.get("name"): c.get("value")
                for c in self.context.cookies() if c.get("name")
            }
        except Exception:
            self._login_cookie_snapshot = before
        for endpoint in self.additional_login_urls:
            if not self._login_json_endpoint(endpoint, primary=False):
                log.warning("additional JSON login was not established: %s",
                            endpoint)
            try:
                self._login_cookie_snapshot = {
                    c.get("name"): c.get("value")
                    for c in self.context.cookies() if c.get("name")
                }
            except Exception:
                pass
        return True

    def login_form_fields(self, login_url: Optional[str] = None,
                          fields: Optional[str] = None,
                          username: Optional[str] = None,
                          password: Optional[str] = None) -> bool:
        """POST an explicit URL-encoded primary login field document.

        ``login_url`` is optional for compatibility with the original single
        endpoint API. Additional endpoints are useful for applications that
        mint independent, module-scoped cookies from the same credentials.
        Each endpoint must set a fresh cookie; a polite 200 without one is not
        treated as another authenticated session.
        """
        self.json_login_error = None
        endpoint = login_url or self.json_login_url
        template = self.login_fields if fields is None else fields
        if not (endpoint and template):
            self.json_login_error = "no form-fields login configured"
            return False
        if not self.context:
            self.json_login_error = "browser context is not started"
            return False
        try:
            form_fields = self._login_fields(
                template,
                self.json_login_username if username is None else username,
                self.json_login_password if password is None else password)
            # `max_redirects=0` and a 3xx allowed through: see the JSON login
            # above - credentials must not be re-sent to a redirect target,
            # and the cookie check below is the real authority anyway.
            response = self.context.request.post(
                endpoint, form=form_fields, timeout=self.timeout_ms,
                max_redirects=0)
            if not response.ok and not 300 <= response.status < 400:
                self.json_login_error = (
                    "form-fields login answered HTTP %d" % response.status)
                return False
            got = [c for c in self.context.cookies()
                   if c.get("name") not in self.preset_cookies]
            if login_url:
                # The primary endpoint may already have populated the jar;
                # for a follow-up endpoint require a cookie value that was
                # not present before this request.
                before = getattr(self, "_login_cookie_snapshot", {})
                got = [c for c in got
                       if before.get(c.get("name")) != c.get("value")]
            if not got:
                self.json_login_error = (
                    "form-fields login returned %d and set no cookie"
                    % response.status)
                return False
            self._record_login_response(
                endpoint, response,
                "application/x-www-form-urlencoded", authenticated=True)
            self._login_cookie_snapshot = {
                c.get("name"): c.get("value")
                for c in self.context.cookies() if c.get("name")}
            log.info("form-fields login accepted, %d cookie(s) held", len(got))
            return True
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            self.json_login_error = "login fields are not valid: %s" % exc
            return False
        except Exception as exc:                       # noqa: BLE001
            self.json_login_error = "form-fields login request failed: %s" % exc
            return False

    def login_additional(self, login: dict[str, str]) -> bool:
        """Run one explicit primary login profile in the existing context.

        Applications sometimes expose several module sessions with different
        credentials or wire formats. This keeps those cookies in the primary
        browser context while allowing the optional secondary context to stay
        isolated for authorization comparisons.
        """
        endpoint = str(login.get("url") or "")
        username = login.get("username") or self.json_login_username
        password = login.get("password") or self.json_login_password
        if login.get("body") is not None:
            ok = self._login_json_endpoint(
                endpoint, primary=False, body_template=login.get("body"),
                username=username, password=password)
        else:
            ok = self.login_form_fields(
                endpoint, fields=login.get("fields"), username=username,
                password=password)
        try:
            self._login_cookie_snapshot = {
                c.get("name"): c.get("value")
                for c in self.context.cookies() if c.get("name")
            }
        except Exception:
            pass
        return ok

    def login_secondary_fields(self, login_url: str) -> bool:
        """Log the second identity into an API accepting URL-encoded fields.

        This is explicit rather than a fallback from the rendered-form
        adapter: an API endpoint has no DOM form to inspect, so the operator
        supplies the field document and accepts the request semantics.
        Passwords remain in the agent process and the request context keeps
        the returned cookie isolated from the primary browser.
        """
        self.secondary_login_error = None
        if not login_url:
            self.secondary_login_error = "secondary login URL is missing"
            return False
        if not self._pw:
            self.secondary_login_error = "browser is not started"
            return False
        try:
            before = dict(self.secondary_cookies)
            if self._secondary_request is None:
                kwargs: dict[str, Any] = {
                    "ignore_https_errors": self.api_ignore_https_errors,
                }
                proxy = self._proxy_dict()
                if proxy:
                    kwargs["proxy"] = proxy
                if self.user_agent:
                    kwargs["user_agent"] = self.user_agent
                self._secondary_request = self._pw.request.new_context(**kwargs)
            fields = self._login_fields(
                self.secondary_login_fields or "",
                self.secondary_username, self.secondary_password)
            # Same as the primary logins: stop at the
            # first hop so the second identity's credentials cannot be
            # forwarded, and let the cookie check that follows decide.
            # The second identity's headers ride on each request, never on the
            # context: a context-level header is replayed on every redirect
            # hop, including to an in-scope host outside `credential_origins`.
            response = self._secondary_request.post(
                login_url, form=fields, timeout=self.timeout_ms,
                max_redirects=0, headers=dict(self.secondary_headers) or None)
            if not response.ok and not 300 <= response.status < 400:
                raise ValueError("secondary login answered HTTP %d" % response.status)
            state = self._secondary_request.storage_state()
            cookies = {c["name"]: c["value"]
                       for c in (state.get("cookies") or []) if c.get("name")}
            fresh = {name: value for name, value in cookies.items()
                     if before.get(name) != value}
            if not fresh:
                raise ValueError(
                    "secondary form login returned no new session cookie")
            self.secondary_cookies = cookies
            return True
        except Exception as exc:
            self.secondary_login_error = str(exc)[:240]
            # An optional follow-up endpoint must not destroy the identity
            # already established by the primary secondary login. Keep the
            # existing request context when it already carries cookies; only
            # tear it down when the first login never established anything.
            if not before:
                try:
                    _release(self._secondary_request)
                except Exception:
                    pass
                self._secondary_request = None
            log.warning("secondary login was not established: %s",
                        self.secondary_login_error)
            return False

    def login_secondary(self, login_url: str) -> bool:
        """Log the optional second identity in an isolated browser context.

        This is deliberately a small, local form-login adapter for the
        operator-supplied second identity. Like the primary login, it runs
        locally from operator secrets: no password crosses the engine boundary.

        A missing or ambiguous form fails closed. In particular, this method
        never turns a failed secondary login into an anonymous or primary
        request context.
        """
        self.secondary_login_error = None
        if not login_url:
            self.secondary_login_error = "secondary login URL is missing"
            return False
        if not self.browser:
            self.secondary_login_error = "browser is not started"
            return False
        try:
            kwargs: dict[str, Any] = {
                "ignore_https_errors": self.ignore_https_errors,
                "viewport": {"width": 1280, "height": 900},
            }
            if self.user_agent:
                kwargs["user_agent"] = self.user_agent
            kwargs.update(self._network_context_kwargs())
            context = self.browser.new_context(**kwargs)
            self._secondary_browser_context = context
            page = context.new_page()
            page.set_default_timeout(self.timeout_ms)
            page.set_default_navigation_timeout(self.timeout_ms)
            page.goto(login_url, wait_until="domcontentloaded")

            password = page.locator("input[type='password']").first
            if password.count() == 0:
                raise ValueError("no password field on secondary login page")
            form = password.locator("xpath=ancestor::form[1]")
            if form.count() == 0:
                form = page.locator("form").first
            if form.count() == 0:
                raise ValueError("secondary login form is missing")

            username = _secondary_username_locator(form, password)
            if username is None:
                raise ValueError("no unambiguous username field on secondary login form")
            username.fill(self.secondary_username or "")
            password.fill(self.secondary_password or "")

            submit = form.locator(
                "button[type='submit'], input[type='submit'], button").first
            if submit.count():
                submit.click(no_wait_after=True, force=True)
            else:
                password.press("Enter")
            page.wait_for_timeout(min(self.timeout_ms, 1000))

            # "Any cookie/localStorage entry exists" is too weak: a FAILED
            # login commonly still sets an analytics or CSRF cookie. Still
            # being on the exact login url with the password field present is
            # not proof of failure either (some apps re-render the same route
            # on success), but it is strong evidence against success. This
            # tightens, rather than replaces, the state check below.
            still_on_login_form = False
            try:
                still_on_login_form = (
                    page.url == login_url and
                    page.locator("input[type='password']").count() > 0)
            except Exception:
                pass
            if still_on_login_form:
                raise ValueError(
                    "secondary login form is still present after submit - "
                    "login did not appear to succeed")

            state = context.storage_state()
            if not (state.get("cookies") or state.get("origins")):
                raise ValueError("secondary login produced no browser session state")
            # `_probe_ws` cannot use `_secondary_request` (a Playwright
            # APIRequestContext has no method to read its own cookie jar
            # back out) the way `_probe_http` does - it needs the flat
            # name/value form `self.secondary_cookies` carries. A fresh login
            # replaces whatever was passed in.
            self.secondary_cookies = {
                c["name"]: c["value"] for c in (state.get("cookies") or [])
                if c.get("name")}
            self._secondary_request = self._pw.request.new_context(
                ignore_https_errors=self.api_ignore_https_errors,
                user_agent=self.user_agent,
                # `secondary_headers` are NOT set here: `_probe_http` adds them
                # per request (see there), so a redirect hop can drop them.
                proxy=self._proxy_dict(),
                storage_state=state) if self._pw else None
            if self._secondary_request is None:
                raise ValueError("secondary request context could not be created")
            context.close()
            self._secondary_browser_context = None
            return True
        except Exception as exc:
            # Do not include form values in an operator-visible error. The
            # locator and navigation context are enough to diagnose setup.
            self.secondary_login_error = str(exc)[:240]
            try:
                if self._secondary_browser_context:
                    self._secondary_browser_context.close()
            except Exception:
                pass
            self._secondary_browser_context = None
            self._secondary_request = None
            log.warning("secondary login was not established: %s",
                        self.secondary_login_error)
            return False


    @staticmethod
    def _is_document_navigation(request: Any) -> bool:
        try:
            return bool(request.is_navigation_request()) and \
                request.resource_type == "document"
        except Exception:
            return request.resource_type == "document"

    #: Statuses whose `Location` the browser follows without asking us.
    REDIRECT_STATUSES = (301, 302, 303, 307, 308)

    #: Chain length we are willing to validate before handing back to the
    #: browser, which enforces its own cap anyway.
    MAX_NAV_REDIRECTS = 10

    def _credential_headers_for(self, url: str) -> dict:
        from ..protocol import scoping

        if not self.extra_headers:
            return {}
        allowed = bool(scoping.decide(
            url, self.credential_origins,
            allow_subdomains=self.allow_subdomains).allowed)
        return dict(self.extra_headers) if allowed else {}

    def _offscope_hop(self, response: Any, url: str) -> Optional[str]:
        """Walk a navigation's redirect chain and name the first hop that
        leaves scope, or None if the whole chain stays inside.

        **Why this exists.** Playwright does not invoke a route handler for a
        server redirect hop - Chromium follows `Location` inside its own
        network stack - so the guard below sees only the in-scope URL, attaches
        the operator's credentials, and gets no further say. Chromium replays
        the original request's headers across the redirect, so an application
        with an open redirect would forward the operator's `Authorization`
        header to a third party, and the scan would then crawl and send
        payloads to that third party.

        **Why a pre-flight.** The alternatives are worse:

          * `route.fulfill(response=...)` of the fetched document contains the
            redirect, but silently stops out-of-scope SUBRESOURCES from
            loading afterwards, so the page renders differently from what the
            application would serve.
          * post-navigation detection only stops the crawl leaving, but the
            leaking request has already carried the credential off-site. It is
            kept as a second layer (see
            `execute.py::_contain_offscope_navigation`).
          * this: fetch the chain ourselves with redirects disabled, and hand
            the route back to the browser only when every hop is in scope.
            Costs one extra document request per navigation, which is the
            right trade against sending the operator's session to somebody
            else.

        Applied to GET navigations only. Duplicating a POST would re-submit
        whatever the form does, which is a worse harm than the one being
        prevented; those fall through to the second layer.
        """
        from urllib.parse import urljoin

        from ..protocol import scoping

        current, hops = url, 0
        while (response is not None
               and response.status in self.REDIRECT_STATUSES):
            location = (response.headers or {}).get("location")
            if not location:
                return None
            target = urljoin(current, location)
            allowed = scoping.decide(
                target, self.scope_origins,
                deny_substrings=self.deny_substrings,
                allow_subdomains=self.allow_subdomains,
                max_depth=self.max_depth).allowed
            if not allowed:
                return target
            # In scope is not authorised for THIS credential: Chromium replays
            # the headers onto every hop it follows itself, so a hop onto an
            # in-scope origin outside `credential_origins` would receive the
            # operator's Authorization. Fail it like an off-scope hop.
            if self.extra_headers and not self.credentials_allowed(target):
                return target
            hops += 1
            if hops >= self.MAX_NAV_REDIRECTS:
                # Refuse: Chromium would follow the rest unseen, replaying
                # the operator's headers on every hop.
                return target
            try:
                response = self.context.request.get(
                    target, headers=self._credential_headers_for(target),
                    max_redirects=0)
            except Exception as exc:
                # Unverifiable rather than known-bad: fall through to the
                # post-navigation layer, which still stops the crawl from
                # continuing off-scope.
                log.debug("could not verify redirect hop %s: %s",
                          target[:120], exc)
                # --strict-egress fails closed on an unverifiable hop.
                return target if self.strict_egress else None
            current = target
        return None

    def _fulfill_contained(self, route: Any, request: Any, sent: dict) -> None:
        """Send a request that carries the operator's headers, other than a
        GET navigation, without letting a redirect take them anywhere.

        Chromium follows a redirect without consulting the route handler and
        replays the headers it was given. So the agent sends the request with
        redirects off and follows each hop itself while the hop is in scope
        and allowed these credentials; the browser gets the final response.
        A hop that is not allowed is handed to the browser, which follows it
        without the operator's headers (it never had them).

        A navigation (a form POST) redirected by 301/302/303 is answered
        with a page that refreshes to the target, so the follow-up GET is a
        new navigation this guard sees; a 307/308 to a host not allowed
        these credentials is refused. A form POST's own result page,
        fulfilled this way, loads no out-of-scope subresources.
        """
        from urllib.parse import urljoin

        from ..protocol import scoping

        url, method = request.url, (request.method or "GET").upper()
        body = request.post_data_buffer
        hdrs = {k: v for k, v in sent.items() if k.lower() != "cookie"}
        navigation = self._is_document_navigation(request)
        try:
            for _ in range(self.MAX_NAV_REDIRECTS):
                response = route.fetch(url=url, method=method, headers=hdrs,
                                       post_data=body, max_redirects=0)
                location = (response.headers or {}).get("location")
                if response.status not in self.REDIRECT_STATUSES or not location:
                    break
                target = urljoin(url, location)
                if navigation and response.status in (301, 302, 303):
                    route.fulfill(status=200, content_type="text/html",
                                  body='<meta http-equiv="refresh" content="0;url=%s">'
                                       % html.escape(target, quote=True))
                    return
                if not (scoping.decide(target, self.scope_origins,
                                       deny_substrings=self.deny_substrings,
                                       allow_subdomains=self.allow_subdomains,
                                       max_depth=self.max_depth).allowed
                        and (self.credentials_allowed(target)
                             or (self.strict_egress
                                 and not self.extra_headers))):
                    if navigation or self.strict_egress:
                        # A 307/308 would make the browser re-send this
                        # form's body to that host unseen: stop here.
                        self._record_egress({
                            "url": target[:400], "type": request.resource_type,
                            "method": method, "blocked": True,
                            "via_redirect_from": url[:400],
                            "safety_incident": False}, count_safety_incident=False)
                        route.abort()
                        return
                    break
                if response.status in (301, 302, 303) and method not in ("GET", "HEAD"):
                    method, body = "GET", None
                    hdrs = {k: v for k, v in hdrs.items()
                            if k.lower() not in ("content-type", "content-length")}
                url = target
            else:
                if self.strict_egress:
                    # chain longer than we can verify: the browser would
                    # follow the rest unseen
                    route.abort()
                    return
        except Exception as exc:
            log.debug("credentialed request failed: %s", exc)
            route.abort()
            return
        route.fulfill(response=response)

    def _guard_websockets(self) -> None:
        """--strict-egress: close page WebSockets that leave the scope. Needs
        Playwright's `route_web_socket`; without it they are not covered."""
        from ..protocol import scoping

        def ws_handler(ws: Any) -> None:
            url = ws.url or ""
            http_url = re.sub(r"^ws", "http", url, count=1)
            if scoping.decide(
                    http_url, self.scope_origins,
                    deny_substrings=self.deny_substrings,
                    allow_subdomains=self.allow_subdomains,
                    max_depth=self.max_depth).allowed:
                ws.connect_to_server()
                return
            self._record_egress({"url": url[:400], "type": "websocket",
                                 "method": "GET", "blocked": True,
                                 "safety_incident": False},
                                count_safety_incident=False)
            ws.close()

        route_ws = getattr(self.context, "route_web_socket", None)
        if route_ws is None:
            # Fail closed: the operator asked for a control; running without
            # it would contradict that.
            raise RuntimeError(
                "--strict-egress needs Playwright >= 1.48 "
                "(context.route_web_socket) to contain page WebSockets; "
                "upgrade Playwright or drop --strict-egress")
        route_ws("**/*", ws_handler)

    def _install_egress_guard(self) -> None:
        """Credentials for the target, and only for the target.

        The policy has three parts, and the middle one is the compromise that
        makes the other two safe to hold:

          * an in-scope request gets the operator's headers;
          * an out-of-scope SUBRESOURCE is allowed through without them, so
            the page still renders and its third-party resources can still be
            recorded - a scanner looking at a broken page is not looking at
            the application;
          * every out-of-scope request is recorded either way, because "this
            application sends its users to fourteen other hosts" is a finding
            somebody wants.

        Cookies need no handling here: the browser scopes them by origin
        already, which is precisely what `extra_http_headers` failed to do.
        """
        from ..protocol import scoping

        headers = dict(self.extra_headers)

        def handler(route: Any, request: Any) -> None:
            url = request.url or ""
            decision = scoping.decide(
                url, self.scope_origins,
                deny_substrings=self.deny_substrings,
                allow_subdomains=self.allow_subdomains,
                max_depth=self.max_depth)
            if decision.allowed:
                # Being IN SCAN SCOPE is not being AUTHORIZED FOR THIS
                # CREDENTIAL - a scope covering several origins does not mean
                # one origin's bearer belongs on all of them.
                credential_ok = bool(scoping.decide(
                    url, self.credential_origins,
                    allow_subdomains=self.allow_subdomains).allowed)
                sent = {**request.headers, **headers} if credential_ok \
                    else request.headers
                # This pre-flight is a REAL extra request (`route.fetch()` then
                # `route.continue_()`), and its response never reaches
                # `_on_response`, so it does not appear among the recorded
                # network events. It exists so THIS request's credential
                # cannot cross scope, so it runs only when a credential
                # applies to this URL; with none there is nothing to leak.
                # Scope containment itself is not weakened: a navigation that
                # lands off-scope is still failed by
                # `execute._contain_offscope_navigation`.
                get_navigation = (self._is_document_navigation(request)
                                  and (request.method or "GET").upper() == "GET")
                # --strict-egress: EVERY in-scope request's redirect chain is
                # walked before the browser may follow it (Chromium never asks
                # the handler about a redirect hop), credential or not.
                strict = self.strict_egress
                if (credential_ok and headers or strict) and not get_navigation:
                    self._fulfill_contained(route, request, sent)
                    return
                if (credential_ok or strict) and get_navigation:
                    self.preflight_requests += 1
                    try:
                        first = route.fetch(headers=sent, max_redirects=0)
                    except Exception as exc:
                        log.debug("navigation pre-flight failed: %s", exc)
                        first = None
                        if strict:
                            route.abort()
                            return
                    offscope = (self._offscope_hop(first, url)
                                if first is not None else None)
                    if offscope:
                        # The redirect was discovered by our own pre-flight
                        # before Chromium received the response, so no
                        # off-scope request was sent. Keep the refusal in the
                        # evidence ledger, but do not spend the run-level
                        # budget reserved for actual egress. The POST/action
                        # path below cannot pre-flight safely and remains a
                        # real incident when it lands off-scope.
                        self._record_egress({
                            "url": offscope[:400], "type": "document",
                            "method": request.method, "blocked": True,
                            "via_redirect_from": url[:400],
                            "safety_incident": False},
                            count_safety_incident=False)
                        log.warning("blocked out-of-scope redirect: %s -> %s",
                                    url[:120], offscope[:200])
                        route.abort()
                        return
                route.continue_(headers=sent)
                return
            navigation = self._is_document_navigation(request)
            if self.strict_egress and not navigation:
                # --strict-egress: the page may not reach anything off-scope.
                self._record_egress({"url": url[:400],
                                     "type": request.resource_type,
                                     "method": request.method,
                                     "blocked": True,
                                     "safety_incident": False},
                                    count_safety_incident=False)
                route.abort()
                return
            # A `--deny` match (a logout link, a destructive action) is
            # refused outright, in every resource type - the operator's
            # promise is "never request URLs containing this substring"
            denied = decision.reason.startswith("deny pattern matched")
            # A route-aborted navigation/deny never reaches the destination;
            # it is a recorded refusal, not a safety incident. Subresources
            # are continued without operator credentials, so they are also
            # not blocked and do not arm the breaker. Actual post-submit
            # off-scope landings are handled by
            # `_contain_offscope_navigation`, not this pre-network branch.
            self._record_egress({"url": url[:400],
                                 "type": request.resource_type,
                                 "method": request.method,
                                 "blocked": navigation or denied,
                                 "safety_incident": False
                                 if (navigation or denied) else None},
                                count_safety_incident=False
                                if (navigation or denied) else True)
            if navigation or denied:
                # A top-level navigation off-scope is the browser LEAVING the
                # engagement - which a redirect, a target=_blank or a bit of
                # JavaScript can trigger without any directive being wrong.
                # Subresources are let through so the page still renders; a
                # navigation is not a subresource.
                log.warning("blocked %s: %s",
                           "deny-listed request" if denied else
                           "out-of-scope navigation", url[:200])
                route.abort()
                return
            # continue WITHOUT the operator's headers
            stripped = {k: v for k, v in request.headers.items()
                        if k.lower() not in {h.lower() for h in headers}}
            route.continue_(headers=stripped)

        if self.strict_egress:
            self._guard_websockets()
        try:
            self.context.route("**/*", handler)
        except Exception as exc:  # pragma: no cover - routing unavailable
            # This IS the containment control - a session that cannot install
            # it can enforce neither credential scoping nor navigation
            # containment. Fail the whole session rather than run uncontained.
            raise RuntimeError(
                "could not install the scope/egress route guard - refusing "
                "to continue without it") from exc


    def _wire(self) -> None:
        self.context.on("response", self._on_response)
        self.context.on("requestfailed", self._on_requestfailed)
        self.page.on("console", self._on_console)
        self.page.on("pageerror", self._on_pageerror)
        # Passive only: this NEVER sends a frame, it only watches the ones
        # the application's own client-side code sends and receives. Active
        # websocket probing opens its own independent connection through
        # `_probe_ws`, for the same reason `_probe_http` goes through
        # `context.request` rather than the live page: a probe needs a clean
        # status/body, which a live client's own framing and reconnect logic
        # does not give.
        self.page.on("websocket", self._on_websocket)
        # Deliberately *no* `dialog` listener.  Playwright auto-dismisses every
        # dialog - `beforeunload` included - only while nothing is listening;
        # register a handler and dismissal becomes our job, which means calling
        # a blocking API from inside an event callback, which deadlocks the sync
        # client.
        # `DIALOG_HOOK` already turns alert/confirm/prompt into console
        # messages before page script runs.

    def stop(self) -> None:
        # Independent of the Playwright teardown below - it never touched
        # `self._pw` - so it runs first and unconditionally.
        if self._relay is not None:
            try:
                self._relay.stop()
            except Exception:
                pass
            self._relay = None
        # Restore the process environment this session changed, BEFORE
        # anything below can raise. A leaked `NODE_EXTRA_CA_CERTS` outlives the
        # run that set it.
        if getattr(self, "_set_node_ca", False):
            if self._prior_node_ca is None:
                os.environ.pop("NODE_EXTRA_CA_CERTS", None)
            else:
                os.environ["NODE_EXTRA_CA_CERTS"] = self._prior_node_ca
            self._set_node_ca = False
        for closer in (self._secondary_request, self._secondary_browser_context,
                       self._anon_request,
                       self.context, self.browser):
            try:
                _release(closer)
            except Exception:
                pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    def __enter__(self) -> "BrowserSession":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- recorders ---------------------------------------------------------

    def _on_response(self, response: Any) -> None:
        if len(self._responses) < self.capture.max_network_events:
            self._responses.append((response, time.time()))

    def _on_requestfailed(self, request: Any) -> None:
        if len(self._failures) >= self.capture.max_network_events:
            return
        try:
            self._failures.append({
                "method": request.method, "url": request.url,
                "resource_type": request.resource_type,
                "failure": (request.failure or "request failed"),
                "is_document": request.resource_type == "document",
            })
        except Exception:
            pass

    def _on_console(self, message: Any) -> None:
        if len(self._console) >= self.capture.max_console_events:
            return
        try:
            loc = message.location or {}
            self._console.append(ConsoleEvent(
                type=message.type, text=redact_text(message.text, 1500),
                location=f"{loc.get('url', '')}:{loc.get('lineNumber', '')}"))
        except Exception:
            pass

    def _on_pageerror(self, error: Any) -> None:
        if len(self._console) >= self.capture.max_console_events:
            return
        text = getattr(error, "message", None) or str(error)
        self._console.append(ConsoleEvent(type="pageerror",
                                          text=redact_text(text, 1500)))

    def _on_websocket(self, ws: Any) -> None:
        url = _safe(lambda: ws.url, "") or ""

        def record(direction: str, payload: Any) -> None:
            if len(self._ws_frames) >= self.capture.max_network_events:
                return
            # Playwright's Python binding calls the frame handler with the
            # payload itself (str for a text frame, bytes for binary); guard
            # against a dict-shaped payload defensively rather than assume
            # one binding's exact calling convention forever.
            text = payload.get("payload") if isinstance(payload, dict) else payload
            if isinstance(text, bytes):
                text = decode_body(text)
            self._ws_frames.append({
                "url": url, "direction": direction,
                "payload": redact_text(str(text or ""),
                                       self.capture.body_sample_bytes),
            })

        try:
            ws.on("framesent", lambda payload: record("sent", payload))
            ws.on("framereceived", lambda payload: record("received", payload))
        except Exception:
            log.debug("websocket frame capture failed", exc_info=True)

    # -- draining ----------------------------------------------------------

    def drain_network(self) -> list[NetworkEvent]:
        events: list[NetworkEvent] = []
        # A few embedders construct a session with `__new__` when they only
        # need passive capture helpers. Missing optional buffers should behave
        # like an empty buffer, just as an unstarted session does.
        login_events, self._login_events = getattr(self, "_login_events", []), []
        events.extend(login_events)
        responses, self._responses = self._responses, []
        failures, self._failures = self._failures, []

        for response, _ts in responses:
            try:
                request = response.request
                resource_type = request.resource_type
                # `all_headers()`, not `headers`: Playwright documents the
                # cheap accessor as omitting cookie headers (`Set-Cookie`),
                # so using it would make every application look cookie-less.
                # `all_headers()` is an IPC round trip, a small cost per
                # response. The fallback keeps the cheap value if the round
                # trip fails rather than losing the event.
                headers = (_safe(lambda: response.all_headers(), None)
                           or _safe(lambda: response.headers, {}) or {})
                # `all_headers()` is still a map, so a response setting more
                # than one `Set-Cookie` (a session cookie plus a CSRF cookie,
                # say) would collapse to whichever arrived last.
                # `headers_array()` is the Playwright accessor that does not
                # combine repeated header names - see `NetworkEvent.set_cookie`.
                # The whole comprehension goes through `_safe`, not just the
                # `headers_array()` call: an unexpected return value that is
                # not iterable must not drop the entire response event.
                set_cookie = _safe(lambda: [
                    redact_text(str(pair.get("value", "")), 400)
                    for pair in response.headers_array() or []
                    if str(pair.get("name", "")).lower() == "set-cookie"
                ], [])
                req_headers = _safe(lambda: request.headers, {}) or {}
                mime = (headers.get("content-type") or "").split(";")[0].strip()
                body: Optional[str] = None
                length = None
                # `response.body()` buffers the ENTIRE response before the
                # sample limit is applied, so a single huge response (a data
                # export, an unbounded API dump) would become a very large
                # allocation. A declared Content-Length far past what any
                # sample could use is rejected before that read starts.
                declared_length = None
                try:
                    declared_length = int(headers.get("content-length") or 0) or None
                except ValueError:
                    pass
                is_binary_grpc = grpcweb.content_type_is_grpc_web(mime) and \
                    not grpcweb.content_type_is_text(mime)
                if resource_type in BODY_TYPES and (_texty(mime) or is_binary_grpc) and (
                        declared_length is None or
                        declared_length <= _MAX_BUFFERED_BODY_BYTES):
                    if is_streaming_body(headers) or _still_downloading(request):
                        # A stream has no end to buffer to. See `is_streaming_body`:
                        # passive capture runs outside the action deadline, so an
                        # SSE endpoint would otherwise wedge the whole agent. A
                        # long-poll is the same wait in a JSON content type - see
                        # `_still_downloading`.
                        raw = None
                    else:
                        raw = _safe(lambda: response.body(), None)

                    if raw is not None:
                        length = len(raw)
                        # Charset-aware: see `bodies.decode_body`. A
                        # legacy page decoded as UTF-8 loses every non-ASCII
                        # byte to U+FFFD before any check sees it.
                        if is_binary_grpc:
                            rendered = grpcweb.render_response(raw, headers)
                            decoded = rendered if rendered is not None \
                                else decode_body(raw, headers)
                        else:
                            decoded = decode_body(raw, headers)
                        body = redact_text(decoded, self.capture.body_sample_bytes)
                elif declared_length is not None:
                    length = declared_length
                if length is None:
                    try:
                        length = int(headers.get("content-length") or 0) or None
                    except ValueError:
                        length = None
                is_binary_request = (
                    mime in ("application/grpc-web", "application/grpc-web+proto"))
                (request_body_sample, request_body_length,
                 request_body_truncated, request_body_encoding) = \
                    _request_body_details(
                        request, self.capture.body_sample_bytes,
                        binary=is_binary_request)
                elapsed_ms = _response_elapsed_ms(request)
                events.append(NetworkEvent(
                    method=request.method, url=response.url, status=response.status,
                    resource_type=resource_type, mime=mime,
                    request_headers=redact_headers(_pick_request_headers(req_headers)),
                    response_headers=redact_headers(headers),
                    set_cookie=set_cookie,
                    request_body_sample=request_body_sample,
                    request_body_encoding=request_body_encoding,
                    request_body_length=request_body_length,
                    request_body_truncated=request_body_truncated,
                    response_body_sample=body, response_length=length,
                    elapsed_ms=elapsed_ms,
                    is_document=(resource_type == "document"),
                ))
            except Exception:  # never let capture break the run
                log.debug("response capture failed", exc_info=True)

        for failure in failures:
            events.append(NetworkEvent(
                method=failure["method"], url=failure["url"],
                resource_type=failure["resource_type"], failure=failure["failure"],
                is_document=failure["is_document"]))

        frames, self._ws_frames = self._ws_frames, []
        for frame in frames:
            # One row per frame, sent and received both recorded, so the actual
            # conversation is visible. Modelled on `NetworkEvent` rather than
            # a new type, so everything that already reads `obs.network`
            # handles frames without a separate path.
            sent = frame["direction"] == "sent"
            events.append(NetworkEvent(
                method="WS", url=frame["url"], resource_type="websocket",
                request_body_sample=frame["payload"] if sent else None,
                request_body_length=len(frame["payload"]) if sent else None,
                response_body_sample=frame["payload"] if not sent else None,
                response_length=len(frame["payload"]) if not sent else None,
            ))
        return events

    def drain_console(self) -> list[ConsoleEvent]:
        console, self._console = self._console, []
        return console

    def _record_egress(self, entry: dict[str, Any], *,
                       count_safety_incident: bool = True) -> None:
        """One event, two consumers with different retention needs.

        `self.egress` is the report's evidence and is capped at 200 entries
        - a scan should not carry a megabyte of near-identical rows.
        `self.safety_incidents` is the kill switch's counter and is NOT
        capped: a runaway is precisely the case where the 201st refusal is
        the one that matters, and a capped counter would go quiet exactly
        when the application started misbehaving hardest.
        """
        if (count_safety_incident and entry.get("blocked")
                and not _is_unreachable_destination(entry.get("url"))):
            self.safety_incidents += 1
        if len(self.egress) < 200:
            self.egress.append(entry)

    def record_scope_refusal(self, url: str, via: str) -> None:
        """A scope refusal from a NON-browser transport.

        The route guard (`_install_egress_guard`) only ever sees traffic the
        Chromium context itself makes. Both probe transports - `_probe_http`
        on the sync side and the `async_probe` batch worker - follow their
        own redirects and refuse off-scope hops on their own. Those refusals
        are recorded here so that they are visible in the egress ledger.

        `via` distinguishes them in the ledger. A probe transport's refusal
        is evidence that the application produced an off-scope redirect, but
        it is not an egress incident: the guard refused it before that
        transport opened a connection. Counting probe-generated redirects as
        incidents makes a legitimate open-redirect test abort a run after a
        few payloads. Browser traffic remains governed by `_record_egress`,
        where a real off-scope request still arms the breaker.
        """
        self._record_egress({"url": (url or "")[:400], "type": via,
                             "method": "GET", "blocked": True,
                             "safety_incident": False},
                            count_safety_incident=False)

    def drain_egress(self) -> list[dict[str, Any]]:
        """Out-of-scope requests seen so far; mirrors `drain_console`.

        `self.egress` is filled by `_install_egress_guard`'s handler. The CLI
        drains it into the trace file and a one-line summary.
        """
        egress, self.egress = self.egress, []
        return egress

    # -- helpers -----------------------------------------------------------

    def screenshot(self, path: str) -> Optional[str]:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self.page.screenshot(path=path, full_page=False)
            return path
        except Exception:
            log.debug("screenshot failed", exc_info=True)
            return None

    def anonymous_request_context(self) -> Any:
        """A request context with no cookies and no auth headers, or `None`.

        Used to ask "what does this page look like to someone who is not
        logged in". It never falls back to `self.context.request`, the
        AUTHENTICATED primary context, if `_pw` is unset or context creation
        fails (for example a shutdown race): that would make a broken
        anonymous identity look like an access-control failure. It returns
        `None` instead, as `secondary_request_context()` does.
        """
        if self._anon_request is not None and self._anon_carries_cookies():
            # It stopped being anonymous. An `APIRequestContext` keeps its own
            # cookie jar for its whole life and has no way to empty it, so the
            # FIRST `Set-Cookie` any anonymous probe receives would be carried
            # by every anonymous probe afterwards, silently turning the
            # "anonymous" identity into a logged-in one and inverting any
            # access-control comparison made with it.
            #
            # Disposed and rebuilt rather than emptied, because Playwright
            # exposes no cookie-clearing on a request context. The check is a
            # single `storage_state()` call.
            try:
                self._anon_request.dispose()
            except Exception:
                pass
            self._anon_request = None
        if self._anon_request is None:
            self._anon_request = self._pw.request.new_context(
                ignore_https_errors=self.api_ignore_https_errors,
                user_agent=self.user_agent,
                proxy=self._proxy_dict()) if self._pw else None
        return self._anon_request

    def _anon_carries_cookies(self) -> bool:
        """Has the anonymous context been handed a cookie by anybody?"""
        try:
            state = self._anon_request.storage_state() or {}
        except Exception:
            return True  # cannot prove it is clean, so rebuild it
        return bool(state.get("cookies"))

    def credentials_allowed(self, url: Optional[str]) -> bool:
        """Whether the operator's primary session headers may go to `url`.

        Separate from `scope_origins` (what the scanner may TOUCH) - see
        `_install_egress_guard`'s docstring. `_probe_http` does not route
        through the browser's page, so it needs this same decision made
        directly rather than relying on the route guard.
        """
        from ..protocol import scoping

        return bool(scoping.decide(
            url, self.credential_origins,
            allow_subdomains=self.allow_subdomains).allowed)

    def secondary_request_context(self) -> Any:
        """The optional second operator-supplied session, never a fallback.

        Returning ``None`` when it was not configured is intentional: falling
        back to the primary context would turn a missing secondary identity
        into a false IDOR result.
        """
        return self._secondary_request

    def cookies(self) -> list[dict[str, Any]]:
        try:
            return list(self.context.cookies())
        except Exception:
            return []


def _secondary_username_locator(form: Any, password: Any) -> Any:
    """Choose a visible username control without guessing across forms."""
    hints = ("user", "login", "email", "account", "name", "handle")
    candidates = form.locator(
        "input:not([type='hidden']):not([type='password']), textarea").all()
    visible = []
    for candidate in candidates:
        try:
            if candidate.is_visible():
                visible.append(candidate)
        except Exception:
            continue
    if not visible:
        return None
    for candidate in visible:
        try:
            name = ((candidate.get_attribute("name") or "") + " " +
                    (candidate.get_attribute("id") or "")).lower()
            if any(hint in name for hint in hints):
                return candidate
        except Exception:
            continue
    # The conventional login form places the username immediately before the
    # password. Refuse a form with multiple equally plausible controls.
    if len(visible) == 1:
        return visible[0]
    try:
        password_box = password.bounding_box()
        if password_box:
            before = [candidate for candidate in visible
                      if (box := candidate.bounding_box()) and
                      box["y"] < password_box["y"]]
            if len(before) == 1:
                return before[0]
    except Exception:
        pass
    return None


def _texty(mime: str) -> bool:
    m = (mime or "").lower()
    return any(tok in m for tok in TEXTY) or m == ""


def _still_downloading(request: Any) -> bool:
    """Headers are in, the body is not: `response.body()` would wait for it.

    Playwright reports `timing["responseEnd"] == -1` until the body has ended.
    A request without that figure (a fake, an old driver) counts as finished.
    """
    end = _safe(lambda: request.timing.get("responseEnd"), None)
    return isinstance(end, (int, float)) and end < 0


def _safe(fn: Any, default: Any) -> Any:
    try:
        return fn()
    except Exception:
        return default


_KEEP_REQUEST_HEADERS = {"content-type", "accept", "origin", "referer",
                         "x-requested-with", "user-agent", "accept-language",
                         "soapaction", "graphql-operation-name", "prefer"}
_DROP_PROBE_HEADERS = {"x-api-key", "x-auth-token", "x-access-token",
                       "x-csrf-token", "x-xsrf-token", "x-session-token",
                       "x-client-secret", "x-signature", "x-forwarded-for",
                       "x-forwarded-host", "x-forwarded-proto"}


def _pick_request_headers(headers: dict[str, str]) -> dict[str, str]:
    """Which request headers are worth keeping for the report, and how.

    An arbitrary `X-*` header's VALUE may be sensitive even when its NAME has
    no obvious keyword (auth, token, secret, key, password, credential): the CLI
    supports custom headers as a session handoff (`--header "X-Session:
    abcd1234"`), and a short opaque value is not caught by `redact_headers`'s
    generic, length-gated patterns. The header's existence is useful for
    reporting; its value is not - keep the name, redact the value.
    """
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        low = k.lower()
        if low in _KEEP_REQUEST_HEADERS:
            out[k] = v
        elif (low.startswith("x-") and low not in _DROP_PROBE_HEADERS
                and not any(token in low for token in
                           ("auth", "token", "secret", "key",
                            "password", "credential"))):
            out[k] = REDACTED
    return out


def _request_body(request: Any, limit: int) -> tuple[Optional[str], Optional[int], bool]:
    return _request_body_details(request, limit)[:3]


def _request_body_details(request: Any, limit: int, *,
                          binary: bool = False
                          ) -> tuple[Optional[str], Optional[int], bool,
                                     Optional[str]]:
    if binary:
        raw = _safe(lambda: request.post_data_buffer, None)
        if callable(raw):
            raw = _safe(raw, None)
        if isinstance(raw, (bytes, bytearray)):
            sample = bytes(raw)[:limit]
            return (base64.b64encode(sample).decode("ascii"), len(raw),
                    len(raw) > limit, "base64")
    data = _safe(lambda: request.post_data, None)
    if not data:
        return None, None, False, None
    redacted = redact_text(data, limit)
    # Raw length alone is not a truncation test: redaction can shrink or
    # expand a body before the sample limit is applied.
    return redacted, len(data), len(redacted) >= limit and len(data) > limit, None


def _response_elapsed_ms(request: Any) -> Optional[int]:
    """Return one response's browser timing, if Playwright exposed it.

    Request timing is a browser observation, not a new request.  Some
    Playwright versions return ``None`` or omit one of the fields for cached
    and failed responses, so timing capture must fail closed and never affect
    the scan itself.

    `request.timing` is a property in the Python API, not a method. Of the
    Resource Timing fields it exposes, only `startTime` is an absolute
    timestamp; every other field, `responseEnd` included, is already
    milliseconds relative to `startTime`, so `responseEnd` alone is the
    elapsed time.
    """
    timing = _safe(lambda: request.timing, {}) or {}
    end = timing.get("responseEnd")
    if not isinstance(end, (int, float)) or end < 0:
        return None
    return max(0, int(round(float(end))))
