# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Directive execution.

Every branch is a mechanical browser operation.  The only local policy the
agent applies is scope enforcement (and it refuses rather than improvises).
"""

from __future__ import annotations

from concurrent.futures import TimeoutError as FuturesTimeout

import base64
import zlib

import logging
import http.client
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional
from urllib.parse import quote, urldefrag, urljoin, urlparse

from ..protocol.models import (ActionResult, CAPTURE_PLACEHOLDER, COOKIE_NAME_RE, CaptureRules,
                               Directive, ProbeResponse, is_preserve, secret_name)
from ..protocol import grpcweb
from . import relay as relaymod
from . import settle
from .bodies import decode_body, is_streaming_body
from .browser import BrowserSession
from .redaction import redact_cookie_header, redact_headers, redact_text
from . import pacing, transient
from .scope import ScopeGuard

log = logging.getLogger("sekuscan.agent.execute")

# Pause after a browser action. Playwright's `networkidle` wait already
# supplies about 500ms of real settle evidence before this fixed sleep starts,
# so a long blind pad on top of it only adds latency.
SETTLE_MS = 150

# The adaptive settle (`agent/settle.py`) measures when a page is done instead
# of always paying `networkidle`'s 500ms floor plus `SETTLE_MS`. It is on by
# default. Each origin is calibrated both ways: the DOM is compared before the
# fast path is trusted, the calibration is re-checked periodically, and any
# disagreement or error falls back to the full wait.
#
# `SEKUSCAN_FAST_SETTLE=0` turns it off and every action uses `_slow_settle`.
ENABLE_FAST_SETTLE = os.environ.get("SEKUSCAN_FAST_SETTLE", "1") not in (
    "0", "false", "no", "off")

# The agent's secret vault: process memory, never written anywhere, never sent
# to the engine. The engine plans a fill with a handle; only this process can
# turn that handle back into a value.
_SECRETS: dict[str, str] = {}


def load_secrets(secrets: dict[str, str]) -> None:
    """Called once at startup with whatever the operator supplied locally."""
    _SECRETS.clear()
    _SECRETS.update({k: v for k, v in (secrets or {}).items() if v})


def resolve_secret(value: str) -> str:
    """A handle becomes its secret; anything else is returned untouched.

    An unknown handle resolves to the empty string rather than to the literal
    handle text: sending `\x00sekuscan-secret:password\x00` into a login form
    would be a confusing failure, and silently typing a sentinel into a
    target's database is worse than typing nothing.
    """
    name = secret_name(value)
    if name is None:
        return value
    if name not in _SECRETS:
        log.warning("no local secret for handle %r", name)
        return ""
    return _SECRETS[name]


_SECRET_HANDLE_RE = re.compile(r"\x00sekuscan-secret:([A-Za-z0-9_-]+)\x00")
_ESCAPED_SECRET_HANDLE_RE = re.compile(
    r"\\u0000sekuscan-secret:([A-Za-z0-9_-]+)\\u0000")


def resolve_secret_text(value: str) -> str:
    """Resolve handles embedded in a request body inside the agent only."""
    if not value:
        return value

    def replace(match: re.Match[str]) -> str:
        return _SECRETS.get(match.group(1), "")

    value = _SECRET_HANDLE_RE.sub(replace, value)
    return _ESCAPED_SECRET_HANDLE_RE.sub(replace, value)


def _directive_body(directive: Directive) -> str | bytes:
    """Resolve and, when declared, decode a binary directive body.

    The engine transports binary payloads as base64 because the agent/engine
    protocol is JSON. Only the closed `base64` encoding is accepted; an
    unknown encoding is a refusal rather than an accidental text request.
    """
    body = resolve_secret_text(directive.body or "")
    encoding = directive.body_encoding
    if not encoding:
        return body
    if encoding != "base64":
        raise ValueError("probe body refused: unsupported body encoding")
    try:
        return base64.b64decode(body, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("probe body refused: invalid base64 encoding") from exc


@dataclass
class Outcome:
    action_result: ActionResult
    probe: Optional[ProbeResponse] = None
    http_status: Optional[int] = None
    load_error: Optional[str] = None
    capture_state: bool = True
    screenshots: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LocalExecutionPolicy:
    """What THIS run of the CLI was actually told, on this machine.

    The agent keeps its own local copy of the risk model rather than trusting
    the engine to have applied `risk`/`allow_destructive`/`allow_upload_cleanup`/
    `allow_authz_non_get`. Like scope enforcement (`ScopeGuard`), it is built
    once, in `cli.py`, from the operator's own CLI flags and never from anything
    the engine sends back, so a buggy or compromised engine cannot widen what
    the agent will do.
    """
    risk: int = 1
    allow_destructive: bool = False
    allow_upload_cleanup: bool = False
    upload_cleanup_url: Optional[str] = None
    allow_authz_non_get: bool = False


def resolve_captured_text(value: str, captured: str) -> str:
    """Substitute the captured value, in whichever encoding it was written.

    The placeholder appears RAW in a header or a JSON body, and PERCENT-ENCODED
    wherever it was written through a urlencoder - a form body or a query
    string. The encoding it arrives in says which context it is in, so the
    value is escaped for that context and only that one: a token containing
    `&` or `=` must not become request structure, and a token in a header must
    not arrive percent-escaped.
    """
    if not value:
        return value
    escaped_marker = quote(CAPTURE_PLACEHOLDER, safe="")
    if escaped_marker in value:
        value = value.replace(escaped_marker, quote(captured, safe=""))
    return value.replace(CAPTURE_PLACEHOLDER, captured)


def resolve_captured_url(url: str, captured: str) -> str:
    """The same substitution, for a value that rides in the query string.

    Body and headers were covered and the URL was not, which is an arbitrary
    gap rather than a decision: a form that rotates an anti-CSRF token and
    submits by GET puts that token in the query, and without this the probe
    sends whatever the token was when the page was first read. The application
    rejects it.

    Two encodings, because whatever built the query may have percent-escaped
    the placeholder on the way in, and the captured value is escaped on the way
    out - it is a query value, and a token containing `&` or `=` would
    otherwise change the shape of the request.
    """
    if not url:
        return url
    # A URL is always an escaping context, including for the raw form: a
    # placeholder that reached the query unencoded still lands in a query
    # VALUE, so the captured token is escaped either way.
    escaped = quote(captured, safe="")
    return (url.replace(quote(CAPTURE_PLACEHOLDER, safe=""), escaped)
               .replace(CAPTURE_PLACEHOLDER, escaped))


def _strip_credentials(session: Any, headers: dict[str, Any]) -> None:
    """Drop the operator's session headers and any Cookie override from
    `headers`, in place. Used on a redirect hop whose origin is in scope but
    not in `credential_origins`, so a redirect from the credential origin
    cannot carry Authorization/Cookie to a sibling in-scope host.
    """
    drop = {h.lower() for h in (getattr(session, "extra_headers", None) or {})}
    drop |= {h.lower() for h in (getattr(session, "secondary_headers", None) or {})}
    drop.add("cookie")
    for name in [n for n in headers if n.lower() in drop]:
        del headers[name]


def _perform_capture(request_context: Any, capture_from: Any,
                     guard: ScopeGuard, operator_cookies: Optional[dict] = None) -> Any:
    """Fetch `capture_from.url`, return its own regex match - or an
    `Outcome` describing why it could not, for the caller to return as-is.

    Scope-checked exactly like a redirect hop: `capture_from.url` is
    engine-supplied like anything else in a directive, and this fetch must
    not be the one outbound request that skips the guard every other one
    goes through.
    """
    decision = guard.check(capture_from.url)
    if not decision.allowed:
        return Outcome(action_result=ActionResult(
            ok=False, error="capture url refused: %s" % decision.reason),
            capture_state=False)
    cookie_name = str(getattr(capture_from, "cookie_name", None) or "")
    if cookie_name and cookie_name in (operator_cookies or {}):
        # A cookie the operator supplied is a credential: never read back.
        return Outcome(action_result=ActionResult(
            ok=False, error="capture refused: an operator cookie"), capture_state=False)
    if cookie_name:
        # The engine receives only a redacted JWT preview, while the agent's
        # live request context still holds the complete cookie. Extract it
        # locally so a capture marker never becomes an invalid HTTP header.
        try:
            state = request_context.storage_state() or {}
            cookies = state.get("cookies") or []
        except Exception as exc:
            return Outcome(action_result=ActionResult(
                ok=False, error=("capture cookie read failed: %s" % exc)[:250]),
                capture_state=False)
        raw_value = next((str(item.get("value") or "") for item in cookies
                          if str(item.get("name") or "") == cookie_name), None)
        if raw_value is None:
            return Outcome(action_result=ActionResult(
                ok=False, error="capture cookie was not present"),
                capture_state=False)
        match = re.search(capture_from.pattern, raw_value)
        if not match:
            return Outcome(action_result=ActionResult(
                ok=False, error="capture pattern did not match cookie"),
                capture_state=False)
        try:
            return match.group(capture_from.group)
        except IndexError:
            return Outcome(action_result=ActionResult(
                ok=False, error="capture pattern has no group %d"
                            % capture_from.group),
                capture_state=False)
    try:
        # Hop by hop with redirects off: Playwright's own following would
        # carry the context's cookies/headers to a `Location` the guard has
        # never seen, and this fetch is engine-directed like any other.
        url = capture_from.url
        for hop in range(_DEFAULT_MAX_REDIRECTS + 1):
            response = request_context.fetch(
                url, method="GET", timeout=12000,
                fail_on_status_code=False, max_redirects=0)
            location = response.headers.get("location")
            if (response.status not in _REDIRECT_STATUSES or not location
                    or hop == _DEFAULT_MAX_REDIRECTS):
                break
            url = urljoin(url, location)
            hop_decision = guard.check(url)
            if not hop_decision.allowed:
                return Outcome(action_result=ActionResult(
                    ok=False, error="capture redirect refused: %s"
                                    % hop_decision.reason),
                    capture_state=False)
        body = decode_body(response.body(), dict(response.headers))
    except Exception as exc:
        return Outcome(action_result=ActionResult(
            ok=False, error=("capture fetch failed: %s"
                            % f"{type(exc).__name__}: {exc}")[:250]),
            capture_state=False)
    match = re.search(capture_from.pattern, body)
    if not match:
        return Outcome(action_result=ActionResult(
            ok=False, error="capture pattern did not match"),
            capture_state=False)
    try:
        captured = match.group(capture_from.group)
    except IndexError:
        return Outcome(action_result=ActionResult(
            ok=False, error="capture pattern has no group %d"
                            % capture_from.group),
            capture_state=False)
    return captured


def _urls_match(a: Optional[str], b: Optional[str]) -> bool:
    pa, pb = urlparse(a or ""), urlparse(b or "")
    return ((pa.scheme.lower(), (pa.hostname or "").lower(), pa.port,
             pa.path.rstrip("/"), pa.query) ==
            (pb.scheme.lower(), (pb.hostname or "").lower(), pb.port,
             pb.path.rstrip("/"), pb.query))


def _carries_a_file(directive: "Directive") -> bool:
    """A multipart body with a file part that has content. An empty file
    part (`filename=""` or a filename alone) uploads nothing."""
    body = directive.body or ""
    if directive.body_encoding == "base64":
        try:
            body = base64.b64decode(body).decode("latin-1")
        except Exception:
            return False
    if not re.search(r"(?i)content-disposition:[^\r\n]*\bfilename\*?=", body):
        return False
    for part in re.split(r"(?m)^--[^\r\n]*\r?\n?", body):
        head, sep, content = part.partition("\r\n\r\n")
        if not sep:
            head, sep, content = part.partition("\n\n")
        if re.search(r"(?i)content-disposition:[^\r\n]*\bfilename\*?=", head) \
                and content.strip("\r\n"):
            return True
    return False


def _authorize_locally(directive: "Directive",
                       policy: LocalExecutionPolicy) -> Optional[str]:
    """`None` means authorized; otherwise the refusal reason.

    Deliberately narrow and additive to the checks each handler already
    makes (the fixed upload fixture, the empty-body-DELETE cleanup shape,
    scope) - this is specifically the risk/capability layer those checks
    did not cover.
    """
    method = (directive.method or "GET").upper()

    # An upload the application ACCEPTS is a write (risk 2). The cleanup that
    # deletes it afterwards is destructive and has its own explicit flag
    # (`--allow-upload-cleanup`, checked below).
    if (directive.kind == "upload_file" or getattr(directive, "upload_fixture", None)) \
            and policy.risk < 2:
        return "upload requires risk >= 2"

    if directive.kind == "upload_cleanup":
        if not policy.allow_upload_cleanup:
            return "upload cleanup was not authorized locally"
        if (policy.upload_cleanup_url and
                not _urls_match(directive.url, policy.upload_cleanup_url)):
            return "cleanup url was not the one explicitly authorized"

    if directive.kind == "fill_submit":
        if (directive.extra_values or directive.form_method) and \
                policy.risk < 2 and not policy.allow_destructive:
            return "form mutation (extra fields or a method override) " \
                   "requires risk >= 2 or --allow-destructive"

    if directive.kind == "probe_http":
        # A non-GET request the engine declares effect="read" (a GraphQL
        # query, a JSON search body - a request that changes no server state
        # whatever verb carries it) is sent at any risk level. The agent
        # cannot verify that declaration: below risk 2 a non-GET probe rests
        # on the engine's word. Any other declared effect needs risk >= 2.
        if (method not in ("GET", "HEAD", "OPTIONS")
                and getattr(directive, "effect", "read") != "read"
                and policy.risk < 2):
            return "a non-read-only probe method requires risk >= 2"
        # Whatever the engine declares: a DELETE, or a body carrying a file,
        # is never read-only.
        if policy.risk < 2 and (method == "DELETE" or _carries_a_file(directive)):
            return "a DELETE or a file upload requires risk >= 2"

    return None


def _credentials_only_for_its_own_host(directive: Directive) -> Directive:
    """A directive whose own `Host` header names a host other than its URL's
    is sent without the operator's headers and cookies: behind a shared
    front end that header, not the URL, decides who receives them."""
    named = [v for k, v in (directive.headers or {}).items()
             if k.lower() in ("host", ":authority")]
    if not named or directive.anonymous:
        return directive
    try:
        own = (urlparse(directive.url or "").hostname or "").lower()
        claimed = {(urlparse("//" + str(v).strip()).hostname or "").lower() for v in named}
    except ValueError:
        claimed = {None}
    if claimed == {own}:
        return directive
    return directive.model_copy(update={"anonymous": True})


def _pre_authorize(directive: Directive,
                   guard: ScopeGuard,
                   policy: LocalExecutionPolicy) -> Optional[Outcome]:
    """The two checks every directive pays before any handler runs - scope,
    then local risk authorization. Returns a refusal `Outcome` or `None`.
    Shared by `execute()` (one directive) and `execute_batch()` (N
    independent `probe_http` directives dispatched concurrently) so a
    batched directive is refused by exactly the same rules a sequential one
    always was - nothing about authorization changes because of batching.
    """
    kind = directive.kind
    if directive.url:
        # `deny_exemption` waives the engine's own deny entries for this one
        # directive - never the operator's `--deny`, never origin/scheme/depth,
        # and never a redirect hop taken later (those re-check strictly).
        decision = guard.check(directive.url,
                               deny_exempt=bool(directive.deny_exemption))
        if not decision.allowed:
            return Outcome(
                action_result=ActionResult(
                    directive_id=directive.id, kind=kind, ok=False,
                    error="refused: out of scope", refused_reason=decision.reason,
                    elapsed_ms=0, detail={"url": directive.url}),
                capture_state=False)

    refused = _authorize_locally(directive, policy)
    if refused:
        return Outcome(
            action_result=ActionResult(
                directive_id=directive.id, kind=kind, ok=False,
                error=f"refused: {refused}", elapsed_ms=0,
                detail={"url": directive.url}),
            capture_state=False)
    return None


def execute(session: BrowserSession, directive: Directive, guard: ScopeGuard,
            capture: CaptureRules, out_dir: str, seq: int,
            policy: LocalExecutionPolicy = LocalExecutionPolicy()) -> Outcome:
    started = time.monotonic()
    kind = directive.kind

    refusal = _pre_authorize(directive, guard, policy)
    if refusal is not None:
        return refusal
    directive = _credentials_only_for_its_own_host(directive)
    secret_refusal = (_secret_in_body_refused(session, directive)
                      if kind in ("probe_http", "probe_ws") else None)
    if secret_refusal:
        return Outcome(action_result=ActionResult(
            directive_id=directive.id, kind=kind, ok=False,
            error="refused: " + secret_refusal), capture_state=False)

    try:
        if kind == "navigate":
            outcome = _navigate(session, directive)
        elif kind == "script_load":
            outcome = _script_load(session, directive)
        elif kind == "click":
            outcome = _click(session, directive)
        elif kind == "fill_submit":
            outcome = _fill_submit(session, directive, guard)
        elif kind == "upload_file":
            outcome = _upload_file(session, directive, guard)
        elif kind == "upload_cleanup":
            outcome = _upload_cleanup(session, directive, guard, capture)
        elif kind == "set_cookie":
            outcome = _set_cookie(session, directive)
        elif kind == "probe_http":
            # Compatibility guard for stored/generic plans that carry a
            # websocket URL under the HTTP kind. Current websocket-aware
            # producers emit probe_ws directly, but this boundary must still
            # choose a transport that can speak the URL.
            scheme = urlparse(directive.url or "").scheme.lower()
            outcome = (_probe_ws(session, directive, capture, guard)
                       if scheme in {"ws", "wss"} else
                       _probe_http(session, directive, capture, guard))
        elif kind == "probe_ws":
            outcome = _probe_ws(session, directive, capture, guard)
        elif kind == "screenshot":
            outcome = _screenshot(session, directive, out_dir, seq)
        elif kind == "wait":
            time.sleep(min(directive.wait_ms, 5000) / 1000.0)
            outcome = Outcome(action_result=ActionResult(ok=True))
        else:
            outcome = Outcome(
                action_result=ActionResult(ok=False, error=f"unknown kind: {kind}"),
                capture_state=False)
    except Exception as exc:
        log.debug("directive failed", exc_info=True)
        if kind in _NAVIGATING_KINDS:
            # A timed-out navigation is still pending in Chromium; see
            # `BrowserSession.stop_loading`.
            session.stop_loading()
        outcome = Outcome(
            action_result=ActionResult(ok=False,
                                       error=f"{type(exc).__name__}: {exc}"[:400]),
            load_error=f"{type(exc).__name__}: {exc}"[:200],
            capture_state=(kind != "probe_http"))

    if kind in _NAVIGATING_KINDS:
        _contain_offscope_navigation(session, guard, outcome, kind)

    outcome.action_result.directive_id = directive.id
    outcome.action_result.kind = kind
    outcome.action_result.elapsed_ms = int((time.monotonic() - started) * 1000)

    if directive.screenshot and capture.screenshots and kind != "probe_http":
        path = os.path.join(out_dir, "screenshots", f"{seq:04d}-{kind}.png")
        saved = session.screenshot(path)
        if saved:
            outcome.screenshots.append(saved)
    return outcome


#: Actions after which the browser may be sitting on a different document.
_NAVIGATING_KINDS = ("navigate", "click", "fill_submit")


def _contain_offscope_navigation(session: BrowserSession, guard: ScopeGuard,
                                 outcome: Outcome, kind: str) -> None:
    """The second layer: if the browser LANDED off-scope, stop crawling there.

    `browser.py::_offscope_hop` prevents the common case before the request
    leaves - a GET navigation whose redirect chain leaves scope. It cannot cover
    everything: a POST form submit is not pre-flighted (duplicating it would
    re-submit whatever the form does), a hop whose check failed is treated as
    unverifiable rather than blocked, and script can call `window.location` or
    open a `target=_blank` at any moment.

    In those cases the request has already happened, so this is damage control
    rather than prevention: mark the action failed, record it where the report
    can see it, and put the page back on the last in-scope document.
    `capture_state` is cleared too, so an off-scope page never becomes a state
    that further exploration starts from.
    """
    page = getattr(session, "page", None)
    landed = getattr(page, "url", "") or ""
    if not landed or landed.startswith(("about:", "data:", "chrome-error:")):
        return
    if guard.check(landed).allowed:
        return
    if len(session.egress) < 200:
        session.egress.append({"url": landed[:400], "type": "document",
                               "method": "GET", "blocked": True,
                               "landed_after": kind})
    log.warning("out-of-scope landing after %s: %s", kind, landed[:200])
    outcome.action_result.ok = False
    outcome.action_result.error = (
        "out-of-scope landing: %s left the engagement scope at %s"
        % (kind, landed[:200]))
    outcome.capture_state = False
    outcome.state = None
    try:
        page.go_back(wait_until="domcontentloaded")
    except Exception:
        pass
    if not guard.check(getattr(page, "url", "") or "").allowed:
        try:
            page.goto("about:blank")
        except Exception:  # pragma: no cover - nothing left to do
            pass


# --------------------------------------------------------------------------
# browser actions
# --------------------------------------------------------------------------


def _navigate(session: BrowserSession, directive: Directive) -> Outcome:
    url = directive.url or ""
    # `--max-rps` applies to navigations as well as direct probes: a navigation is
    # a request to the target exactly like a probe is.
    #
    # Known limit: the subresources a PAGE fetches (XHR, fetch, images, scripts)
    # are not paced. Pacing them would mean sleeping inside the route handler,
    # which throttles the browser itself and delays `networkidle`; a settle that
    # times out silently reduces coverage.
    wait = pacing.claim(_host_of(url))
    if wait:
        time.sleep(wait)
    if directive.bypass_csp:
        # One navigation with the page's CSP not enforced, always switched
        # back afterwards. A real load, never the hash-route shortcut.
        with session.csp_bypassed():
            response = session.page.goto(url, wait_until="domcontentloaded")
            _settle(session.page)
        return Outcome(action_result=ActionResult(
            ok=True, detail={"url": session.page.url, "bypass_csp": True}),
            http_status=response.status if response is not None else None)
    page = session.page
    current_base = urldefrag(page.url or "")[0]
    target_base, fragment = urldefrag(url)
    if target_base == current_base and (not fragment or
                                        fragment.startswith(("/", "!/"))):
        # Hash routers are same-document navigations. Calling page.goto() for
        # them can wait for a document event that will never arrive, and the
        # old reload fallback turns a cheap route change into a full reload.
        # Parameter fragments are different: traditional pages often read
        # location.hash only during initial load, so assigning the hash after
        # the document is live never exercises the handler. Those fall through
        # to goto/reload below with the fragment present from the beginning.
        #
        # Same reasoning as `_click`'s network-idle skip below: a hash-route
        # change is a client-side route change, not a real document load - a
        # live SPA with polling/WebSocket traffic never goes network-idle, so
        # waiting for it here pays up to 3s for nothing on exactly the kind of
        # target this exists to crawl.
        page.evaluate("url => { window.location.hash = new URL(url).hash; }", url)
        _settle(page, wait_network_idle=False)
        return Outcome(action_result=ActionResult(ok=True,
                                                  detail={"url": page.url}),
                       http_status=None)
    response = page.goto(url, wait_until="domcontentloaded")
    status: Optional[int] = None
    if response is None:
        # same-document navigation (fragment only) - force a real load
        if fragment or target_base == current_base:
            response = page.reload(wait_until="domcontentloaded")
    if response is not None:
        status = response.status
    _settle(page)
    return Outcome(action_result=ActionResult(ok=True, detail={"url": page.url}),
                   http_status=status)


def _script_load(session: BrowserSession, directive: Directive) -> Outcome:
    """Load one in-scope URL as a script without replacing the document.

    JSONP is executable only when a browser consumes the response as a script;
    fetching it or visiting it as a document tests a different thing. Keep the
    agent-side operation narrow: primary, same-origin GET with no body/headers.
    """
    if ((directive.method or "GET").upper() != "GET" or
            directive.body is not None or directive.headers or
            directive.anonymous or directive.auth_profile != "primary" or
            not directive.url):
        return Outcome(action_result=ActionResult(
            ok=False, error="script load refused: only an empty primary GET is allowed"),
            capture_state=False)
    page = session.page
    if not settle.timers_run(page):
        # The promise below resolves only from a timer (its own timeout
        # included), and a CSP-sandboxed document runs neither scripts nor
        # timers - it would never resolve. See `settle.timers_run`.
        return Outcome(action_result=ActionResult(ok=True, detail={
            "url": directive.url, "script_load": True, "loaded": False,
            "error": "document cannot run scripts (CSP sandbox)"}),
            capture_state=False)
    result = page.evaluate(
        """async ({url, timeoutMs}) => {
            const script = document.createElement('script');
            script.src = url;
            script.async = false;
            const outcome = await new Promise(resolve => {
                let done = false;
                const finish = (loaded, error = '') => {
                    if (done) return;
                    done = true;
                    script.remove();
                    resolve({loaded, error});
                };
                script.onload = () => finish(true);
                script.onerror = () => finish(false, 'script request failed');
                document.head.appendChild(script);
                setTimeout(() => finish(false, 'script request timed out'), timeoutMs);
            });
            return outcome;
        }""",
        {"url": directive.url, "timeoutMs": 4000})
    _settle(page, wait_network_idle=False)
    detail = {"url": directive.url, "script_load": True}
    if isinstance(result, dict):
        detail.update(result)
    return Outcome(action_result=ActionResult(ok=True, detail=detail),
                   capture_state=True)


_COOKIE_NAME_RE = COOKIE_NAME_RE


def _set_cookie(session: BrowserSession, directive: Directive) -> Outcome:
    """Set one same-origin cookie for a browser-only proof step.

    This is deliberately not a general cookie-edit API. It accepts one
    RFC-shaped name/value pair and never accepts headers, a body, or another
    auth profile. The cookie value is set in the browser, not sent in
    engine-side request headers.
    """
    name = str(directive.cookie_name or "")
    value = str(directive.cookie_value or "")
    if (not directive.url or directive.method.upper() != "GET"
            or directive.headers or directive.body is not None
            or directive.anonymous or directive.auth_profile != "primary"
            or not _COOKIE_NAME_RE.fullmatch(name)
            # RFC 6265 requires support for at least 4096 bytes of cookie value, so the
            # limit sits above that floor. Values carrying `;`/CR/LF are refused
            # regardless of length.
            or len(value) > 4096 or any(c in value for c in "\r\n;")):
        return Outcome(action_result=ActionResult(
            ok=False, error="cookie proof refused: invalid same-origin cookie directive"),
            capture_state=False)
    host = urlparse(directive.url).hostname
    if not host:
        return Outcome(action_result=ActionResult(
            ok=False, error="cookie proof refused: URL has no host"),
            capture_state=False)
    path = str(directive.cookie_path or "/")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        return Outcome(action_result=ActionResult(
            ok=False, error="cookie proof refused: invalid cookie path"),
            capture_state=False)
    # The value this cookie had before the run first overrode it, kept here
    # and never reported: it can be a session secret. See
    # `Directive.cookie_restore`.
    originals = session.cookie_originals
    key = (name, host, path)
    if not directive.cookie_restore:
        if key not in originals:
            originals[key] = next(
                (c["value"] for c in session.context.cookies(directive.url)
                 if c.get("name") == name and c.get("path", "/") == path), None)
    elif key in originals:
        # No snapshot (a respawned browser) falls through to the engine's
        # seed in `value`.
        original = originals.pop(key)
        if original is None:
            session.context.clear_cookies(name=name, domain=host, path=path)
            return Outcome(action_result=ActionResult(
                ok=True, detail={"cookie_name": name, "url": directive.url,
                                 "restored": True}),
                capture_state=False)
        value = original
    session.context.add_cookies([{
        "name": name, "value": value, "domain": host, "path": path,
    }])
    return Outcome(action_result=ActionResult(
        ok=True, detail={"cookie_name": name, "url": directive.url}),
        capture_state=False)


def _click(session: BrowserSession, directive: Directive) -> Outcome:
    page = session.page
    selector = directive.selector or ""
    if not selector:
        return Outcome(action_result=ActionResult(ok=False, error="no selector"),
                       capture_state=False)
    locator = page.locator(selector).first
    try:
        # Only controls captured as visible are requested. Re-check that
        # immediately before dispatch, then bypass Playwright's
        # stability/receives-events wait: animated descendants (a rotating image or a
        # live link) can otherwise spend the whole timeout without changing what the
        # button's handler receives.
        if not locator.is_visible():
            return Outcome(action_result=ActionResult(
                ok=False, error="control is no longer visible"),
                # The selector came from an older DOM observation.  The
                # current page is exactly the useful evidence now: returning
                # it lets the engine discard any stale menu queue and plan
                # against the controls that are actually present.
                capture_state=True)
    except Exception as exc:
        return Outcome(action_result=ActionResult(
            ok=False, error=f"control visibility check failed: {exc}"[:300]),
            capture_state=False)
    try:
        locator.scroll_into_view_if_needed(timeout=2000)
    except Exception:
        pass
    locator.click(timeout=3000, no_wait_after=True, force=True)
    # A click in a live SPA does not have a useful network-idle point: a
    # WebSocket, analytics stream, or long-poll keeps the page busy forever.
    # Waiting for the three-second network-idle timeout on every menu button
    # turns a bounded exploration into a very slow crawl. The fixed DOM settle
    # window is enough before the next observation; navigation and form
    # submission retain the stronger default below.
    _settle(page, wait_network_idle=False)
    # Then wait for requests this click started, so a `fetch()` it issues is
    # captured. Returns at once when nothing is outstanding.
    settle.drain_click_requests(page)
    return Outcome(action_result=ActionResult(ok=True,
                                              detail={"selector": selector,
                                                      "url": page.url}))


def _fill_submit(session: BrowserSession, directive: Directive,
                 guard: ScopeGuard) -> Outcome:
    page = session.page
    selector = directive.selector or "form"
    current_base = urldefrag(page.url or "")[0]
    target_base = urldefrag(directive.url or "")[0]
    form = page.locator(selector).first
    if (directive.url and guard.allowed(directive.url)
            and target_base != current_base):
        # A previous proof can submit a reflected form action and leave the
        # browser on a different document while the old form still exists in
        # the DOM. Reusing it sends the next proof to the attacker's action
        # rather than to the directive's target page.
        page.goto(directive.url, wait_until="domcontentloaded")
        _settle(page)
        form = page.locator(selector).first
    if form.count() == 0:
        if (directive.url and guard.allowed(directive.url)):
            # A form submission can replace the document with a response that
            # keeps the same URL but contains no form.  The next proof still
            # names the original page, so reload it before falling back to a
            # generic selector.
            page.goto(directive.url, wait_until="domcontentloaded")
            _settle(page)
            form = page.locator(selector).first
    if form.count() == 0:
        # Never fall back to `page.locator("form").first`: that would submit
        # WHATEVER form happens to exist on the page when the one the directive
        # named is gone. That is not the proof the directive asked for; refuse rather
        # than guess.
        return Outcome(action_result=ActionResult(
            ok=False, error="no form found: the exact observed form no "
                            "longer exists on this page"),
            capture_state=True)

    # Keep the browser's resolved action beside the directive.  The directive
    # names the document containing the form, while a native form may submit
    # to a different same-origin path.  This lets the later network-to-proof
    # adapter prefer the actual submission when the browser also emitted an
    # analytics or autosave POST during the same settle window.
    form_action = _form_action(page, form, directive.url)
    decision = guard.check(form_action)
    if not decision.allowed:
        # The page itself can carry a form whose `action` points outside scope.
        # The RESOLVED action is checked, not only the page url the form was found
        # on, so probe values are never filled in and submitted to wherever the
        # page's own markup says.
        return Outcome(action_result=ActionResult(
            ok=False, error="form submission refused: action is out of scope",
            refused_reason=decision.reason), capture_state=False)

    original_form_method = None
    override_method = str(directive.form_method or "").upper()
    if override_method:
        if override_method not in ("GET", "POST"):
            return Outcome(action_result=ActionResult(
                ok=False, error="form proof refused: invalid method override"),
                capture_state=True)
        try:
            original_form_method = str(
                form.get_attribute("method") or "GET").upper()
            form.evaluate("(f, method) => { f.method = method; }",
                          override_method)
        except Exception as exc:
            return Outcome(action_result=ActionResult(
                ok=False,
                error=f"form proof refused: method override failed: {exc}"[:300]),
                capture_state=True)

    submit_method = override_method or str(form.get_attribute("method") or "GET").upper()
    for name, value in (directive.values or {}).items():
        handle = secret_name(value)
        if handle and not (submit_method == "POST" and session.credentials_allowed(form_action)
                           and (handle != "password" or _field_type(form, name) == "password")):
            return Outcome(action_result=ActionResult(
                ok=False, error="form refused: a secret goes only into a POST to a credential "
                                "origin, and the password only into a password field"),
                capture_state=True)

    filled: dict[str, str] = {}
    for name, value in (directive.values or {}).items():
        if is_preserve(value):
            # the browser already holds the right value - an anti-CSRF token
            # the engine was never shown. Typing anything here breaks the
            # submission; typing nothing is both correct and the point.
            filled[name] = "<preserved>"
            continue
        real = resolve_secret(value)
        if _fill_field(form, name, real):
            # the LOG records the handle, never the substituted value - this
            # dict ends up in the agent trace
            filled[name] = ("<secret:%s>" % secret_name(value)
                            if secret_name(value) else real[:60])

    extra_filled: list[str] = []
    if directive.extra_values:
        try:
            extra_filled = _add_extra_fields(form, directive.extra_values)
        except ValueError as exc:
            return Outcome(action_result=ActionResult(
                ok=False, error=f"form proof refused: {exc}"),
                capture_state=True)

    # Planted before the submission is dispatched, so a replaced document can
    # be told from the same idle one afterwards. See
    # `settle.settle_after_submit`; `None` keeps the fixed wait.
    submit_token = _interaction_token(page)
    submitted = "requestSubmit"
    if directive.submit_selector:
        try:
            target = page.locator(directive.submit_selector).first
            if target.is_visible():
                # Synthetic forms sometimes point at a framework wrapper
                # rather than a native button.  Use the same bounded dispatch
                # as ordinary controls; waiting for actionability here costs
                # four seconds for a target that was never pressable.
                target.click(timeout=2500, no_wait_after=True, force=True)
                submitted = "submit-button"
            else:
                submitted = _submit_via_dom(form)
        except Exception:
            submitted = _submit_via_dom(form)
    else:
        try:
            # Tried in PRIORITY order, not as one combined CSS selector.
            # `"button[type=submit],input[type=submit],button"` matches whichever button
            # comes FIRST IN DOM ORDER, not the most specific one - and a login form is
            # where that breaks, because some UI frameworks put a visibility-toggle
            # `<button type="button">` before the real `<button type="submit">`.
            # Clicking the toggle throws no exception and sends no request, so the submit
            # would be reported as done when nothing was sent.
            #
            # A bare `button` with no `type` attribute defaults to `type="submit"` per
            # the HTML spec, so it belongs in the fallback tier alongside the explicit
            # ones - just never ahead of them.
            btn = None
            for selector in ("button[type=submit]", "input[type=submit]",
                             "button:not([type]), button[type=button]"):
                candidate = form.locator(selector).first
                if candidate.count() > 0:
                    btn = candidate
                    break
            if btn is not None:
                btn.click(timeout=4000, no_wait_after=True)
                submitted = "form-button"
            else:
                submitted = _submit_via_dom(form)
        except Exception:
            submitted = _submit_via_dom(form)
    # Form handlers in SPAs commonly use XHR while a socket keeps the page
    # permanently non-idle. The fixed post-submit window still lets the response
    # and session observers run, without charging every form attempt the
    # network-idle timeout.
    _settle_after_interaction(page, submit_token, extra_ms=400)
    if override_method and original_form_method:
        # Do not let a proof-stage override bleed into the next directive when
        # the form handler stayed on the same document (common in SPAs).
        try:
            form.evaluate("(f, method) => { f.method = method; }",
                          original_form_method)
        except Exception:
            pass
    return Outcome(action_result=ActionResult(
        ok=True, detail={"selector": selector, "filled": list(filled),
                         "extra_filled": extra_filled,
                         "submitted_via": submitted, "url": page.url,
                         "form_action": form_action,
                         "form_method": override_method or original_form_method}))


# A closed set of fixed filenames, not an operator-controlled one: both
# name a fixed, inert, byte-for-byte identical fixture, and only the
# extension differs. The second tests dangerous-extension acceptance
# (CWE-434) without ever sending executable content.
_ALLOWED_UPLOAD_FILE_NAMES = ("sekuscan-probe.txt", "sekuscan-probe.php")

# --------------------------------------------------------------------------
# transport upload fixtures
# --------------------------------------------------------------------------
# The bytes of every file this scanner will ever upload, and the ONLY place
# they exist. The engine names one; it never sends content. (The browser path
# above instead receives `file_content` and compares it to the fixed fixture.)
#
# `{marker}` is the run's own `sks` token and is the only thing that varies.
# Every fixture is INERT: a custom element and an SVG title carry no script,
# no handler and no scheme - and executable content is not
# something this scanner uploads to anybody's server.
UPLOAD_FIXTURES: dict[str, tuple[str, str, str]] = {
    # (filename, mime, content template)
    "text": ("sekuscan-probe.txt", "text/plain",
             "SEKUSCAN_UPLOAD_SENTINEL {marker}\n"),
    # A dangerous EXTENSION on inert text - CWE-434 acceptance, never
    # execution. The same trade the browser path's `.php` fixture makes.
    "php_extension": ("sekuscan-probe.php", "text/plain",
                      "SEKUSCAN_UPLOAD_SENTINEL {marker}\n"),
    # Markup. The element is a custom tag: a browser parses it and does
    # nothing with it.
    "html_marker": ("sekuscan-probe.html", "text/html",
                    "<sks-{marker}>SEKUSCAN_UPLOAD_SENTINEL</sks-{marker}>\n"),
    # SVG fixture. It contains no script.
    "svg_marker": ("sekuscan-probe.svg", "image/svg+xml",
                   "<svg xmlns=\"http://www.w3.org/2000/svg\">"
                   "<title>SEKUSCAN_UPLOAD_SENTINEL {marker}</title></svg>\n"),
    # An internal DTD entity only - no SYSTEM identifier, nothing fetched,
    # nothing read off this host's filesystem.
    "svg_internal_entity": (
        "sekuscan-probe.svg", "image/svg+xml",
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY sksxxe "{marker}">]>'
        '<svg xmlns="http://www.w3.org/2000/svg"><title>&sksxxe;</title>'
        '</svg>\n'),
}

#: The marker is the only variable, and it is one of ours.
_UPLOAD_MARKER_RE = re.compile(r"^sks[a-z0-9]{3,16}$")

#: Fixed multipart filenames. The CONTENT stays the inert text fixture; only
#: the name changes, and the shapes are a closed set rather than anything a
#: caller supplies.
#: Filename shape -> (template, does the fixture's own extension follow?).
#: `{marker}` is the per-probe token. `False` means the template IS the
#: whole name.
#:
#: The largest padding the agent will generate, whatever it is asked for.
#:
#: Four mebibytes is a file, not an outage. The ceiling lives in the AGENT
#: because that is where the bytes are made - an engine asking for a
#: gigabyte gets nothing.
MAX_UPLOAD_FILL_BYTES = 4 * 1024 * 1024

UPLOAD_FILENAMES: dict[str, tuple[str, bool]] = {
    "plain": ("sekuscan-probe", True),
    "traversal": ("../../sekuscan-probe", True),
    "nul_extension": ("sekuscan-probe.php\x00.txt", True),
    # Markup in the name. Nothing executable: a custom element with no
    # handler and no script.
    "markup": ("sekuscan-<{marker}>-probe", True),
    # The same, ending in an image extension.
    "markup_image": ("sekuscan-<{marker}>-probe.png", False),
    # An image name only.
    "image": ("sekuscan-probe.png", False),
    # An image extension after a NUL byte.
    "nul_image": ("sekuscan-probe.php\x00.png", False),
}

#: Every filename shape but one must stay a single path component.
#:
#: `markup` puts caller-controlled text in a filename, and a `/` in it would
#: turn a name into a path; only the `traversal` shape may contain one.
_UPLOAD_NAME_SEPARATORS = ("/", "\\")


def upload_part(directive: Any) -> Optional[dict[str, Any]]:
    """The multipart part for a named fixture, or None if it is not allowed.

    Refuses anything the table does not name. There is no path from a
    directive to bytes that are not written above.
    """
    fixture = UPLOAD_FIXTURES.get(str(getattr(directive, "upload_fixture", "")))
    if fixture is None:
        return None
    marker = str(getattr(directive, "upload_marker", "") or "")
    if not _UPLOAD_MARKER_RE.match(marker):
        return None
    name, mime, template = fixture
    shape = str(getattr(directive, "upload_filename", "") or "plain")
    if shape not in UPLOAD_FILENAMES:
        return None
    if shape != "plain":
        stem, keep_extension = UPLOAD_FILENAMES[shape]
        stem = stem.format(marker=marker)
        name = ("%s%s" % (stem, os.path.splitext(name)[1]) if keep_extension
                else stem)
    if shape != "traversal" and any(sep in name
                                    for sep in _UPLOAD_NAME_SEPARATORS):
        return None
    if len(name) > 128:
        return None
    content = template.format(marker=marker)
    if len(content.encode("utf-8")) > 512:
        return None
    body = content.encode("utf-8")
    fill = getattr(directive, "upload_fill_bytes", None)
    if fill:
        # An exact integer. `int(1.5)` would silently become a 1-byte
        # request, and a size that quietly becomes a different size is the
        # kind of thing nobody notices until the finding is wrong.
        if not isinstance(fill, int) or isinstance(fill, bool):
            return None
        wanted = fill
        if wanted <= 0 or wanted > MAX_UPLOAD_FILL_BYTES:
            return None
        # Padded HERE, from a size the engine asked for. The agent owning every byte
        # that reaches the wire is the contract the fixture table exists to keep,
        # and it would not survive an engine that can post two megabytes through a
        # directive.
        #
        # `max(0, ...)` clamps the PADDING, not the result, so a requested size
        # SMALLER than the fixture would produce a body larger than both. Refusing is
        # the only honest answer: the fixture cannot be truncated without destroying
        # its marker, and a size that quietly becomes a different size is not
        # acceptable.
        if wanted <= len(body):
            return None
        # A repeated single byte: it compresses to nothing in transit, it
        # is not a payload, and it cannot be mistaken for content.
        body = body + (b"\n" + b"A" * (wanted - len(body) - 1))
    return {"name": name, "mimeType": mime, "buffer": body}


def upload_multipart(directive: Any, part: dict[str, Any],
                     field: str) -> dict[str, Any]:
    """The full multipart body: the file part plus any OTHER form fields.

    A form with other REQUIRED fields beside the file can reject a multipart
    body carrying only the file part. `directive.extra_values` is the same
    "other form field values" bag `fill_submit` already fills during a browser
    form submission (see `_fill_submit`); it is reused here as plain string
    parts beside the file, in the one multipart body Playwright's
    `context.request` sends, since that API accepts a dict mixing strings and
    file payloads.
    """
    extra = {str(name): str(value)
             for name, value in (getattr(directive, "extra_values", None) or {}).items()
             if re.match(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,39}$", str(name))
             and str(name) != field}
    return {**extra, field: part}


def _upload_file(session: BrowserSession, directive: Directive,
                 guard: ScopeGuard) -> Outcome:
    """Submit only the fixed, harmless upload fixture.

    This validation is repeated in the agent because the engine is not a trust
    boundary. A future caller cannot turn this directive into an arbitrary file
    writer by forging JSON or by changing the check's constants.
    """
    if (directive.file_name not in _ALLOWED_UPLOAD_FILE_NAMES or
            directive.file_mime != "text/plain" or
            directive.file_content != "SEKUSCAN_UPLOAD_SENTINEL\n" or
            len((directive.file_content or "").encode("utf-8")) > 128):
        return Outcome(action_result=ActionResult(
            ok=False, error="upload refused: only the fixed benign fixture is allowed"),
            capture_state=False)
    page = session.page
    selector = directive.selector or "form"
    form = page.locator(selector).first
    if form.count() == 0 and directive.url and guard.allowed(directive.url):
        page.goto(directive.url, wait_until="domcontentloaded")
        _settle(page)
        form = page.locator(selector).first
    if form.count() == 0:
        return Outcome(action_result=ActionResult(ok=False, error="no upload form found"),
                       capture_state=True)
    form_action = _form_action(page, form, directive.url)
    decision = guard.check(form_action)
    if not decision.allowed:
        # As in `_fill_submit`: an in-scope page can carry a form whose
        # `action` points elsewhere, so the RESOLVED destination is checked
        # before the fixture is submitted.
        return Outcome(action_result=ActionResult(
            ok=False, error="upload refused: form action is out of scope",
            refused_reason=decision.reason), capture_state=False)
    inputs = form.locator('input[type="file"]')
    if inputs.count() <= directive.file_index:
        return Outcome(action_result=ActionResult(
            ok=False, error="upload refused: file input was not found"),
            capture_state=True)
    inputs.nth(directive.file_index).set_input_files({
        "name": directive.file_name,
        "mimeType": directive.file_mime,
        "buffer": (directive.file_content or "").encode("utf-8"),
    })
    submitted = False
    if directive.submit_selector:
        page.locator(directive.submit_selector).first.click(
            timeout=4000, no_wait_after=True)
        submitted = True
        _settle(page, extra_ms=400)
    return Outcome(action_result=ActionResult(
        ok=True, detail={"selector": selector, "submitted": submitted,
                         "file_name": directive.file_name, "url": page.url,
                         "form_action": form_action}),
        capture_state=True)


def _form_action(page: Any, form: Any, fallback: Optional[str]) -> str:
    """Resolve a native form action without trusting browser-side metadata.

    Playwright resolves relative actions in the page, but only the local agent
    needs that URL.  A synthetic form or a mocked/test locator may not expose
    an action; in that case the directive's document URL remains the safe
    fallback and the network proof helper can still use its SPA/XHR heuristic.
    """
    try:
        action = form.get_attribute("action")
    except Exception:
        action = None
    if not isinstance(action, str):
        return str(fallback or getattr(page, "url", "") or "")
    base = str(getattr(page, "url", "") or fallback or "")
    return urljoin(base, action or base)


def _upload_cleanup(session: BrowserSession, directive: Directive,
                    guard: ScopeGuard, capture: CaptureRules) -> Outcome:
    """Run only an explicitly authorized, empty-body DELETE cleanup request."""
    if ((directive.method or "").upper() != "DELETE"
            or directive.body is not None or directive.headers):
        return Outcome(action_result=ActionResult(
            ok=False,
            error="upload cleanup refused: only an empty-body DELETE is allowed"),
                       capture_state=False)
    decision = guard.check(directive.url)
    if not decision.allowed:
        return Outcome(action_result=ActionResult(
            ok=False, error="upload cleanup refused: out of scope",
            refused_reason=decision.reason), capture_state=False)
    return _probe_http(session, directive, capture, guard)


_EXTRA_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\[\]-]{0,80}$")


def _add_extra_fields(form: Any, values: dict[str, str]) -> list[str]:
    """Add bounded hidden controls for an explicitly authorized proof.

    This is intentionally separate from `_fill_field`: an ordinary form
    directive may only fill controls the application exposed.  Extra fields are
    the one opt-in exception, limited to eight simple names and short values
    so a directive cannot become an arbitrary DOM or header injection API.
    """
    if len(values) > 8:
        raise ValueError("too many extra form fields")
    items: list[dict[str, str]] = []
    for raw_name, raw_value in values.items():
        name = str(raw_name)
        value = str(raw_value)
        if (not _EXTRA_FIELD_NAME_RE.fullmatch(name)
                or len(value) > 256 or any(char in value for char in "\r\n")):
            raise ValueError("invalid extra form field")
        items.append({"name": name, "value": value})
    if not items:
        return []
    result = form.evaluate(
        """(form, items) => {
          const out = [];
          for (const item of items) {
            let input = Array.from(form.elements || [])
              .find(el => el.name === item.name);
            if (!input) {
              input = document.createElement('input');
              input.type = 'hidden';
              input.name = item.name;
              form.appendChild(input);
            }
            if (input.type !== 'file') input.value = item.value;
            out.push(item.name);
          }
          return out;
        }""", items)
    return [str(name) for name in (result or [])]


# `locator.fill()` is asked ONE cheap question first, and a field that is not
# fillable yet is given a bounded wait rather than the full deadline.
#
# Letting `fill()` run to its full timeout on a field that will not fill
# wastes seconds to learn something one round trip can answer, and the
# answer was discarded with the exception. But probing with a short deadline
# and giving up is wrong: a field revealed shortly after we reach it is not
# fillable when a short probe expires and is fillable a moment later. Writing
# `el.value` to it fires no events, and a framework-controlled input then
# overwrites the value from its own state, so the original value would be
# submitted silently.
#
# So: ask, and if the answer is no, WAIT for it to change, long enough to
# cover a dynamic reveal and no longer. A field still un-fillable after that
# gets the direct assignment.
FILL_FULL_MS = 3000
# How long a not-yet-fillable field is given to become fillable. Covers a
# framework mounting an input after a fetch.
FILL_REVEAL_MS = 900
_FILL_POLL_MS = 60

# Deliberately the three conditions `fill()` itself cannot resolve by waiting
# once they are settled. Everything else is left to `fill()`.
_FILLABLE_JS = """el => {
    if (el.disabled || el.readOnly) return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
}"""


def _fillable_now(field: Any) -> bool:
    """Can `fill()` work on this field right now? One round trip.

    Fails OPEN: if the question cannot be answered, say yes and let `fill()`
    spend its own deadline.
    """
    try:
        return bool(field.evaluate(_FILLABLE_JS))
    except Exception:
        return True


def _wait_until_fillable(field: Any, budget_ms: int = FILL_REVEAL_MS) -> bool:
    """Poll the same cheap predicate until it turns true or the budget runs
    out. A dynamic reveal is the case this exists for."""
    deadline = time.monotonic() + budget_ms / 1000.0
    while True:
        if _fillable_now(field):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_FILL_POLL_MS / 1000.0)


def _field_type(form: Any, name: str) -> str:
    """The `type` of the field `_fill_field` would fill, or ""."""
    for sel in (f'[name="{name}"]', f'#{name}'):
        try:
            field = form.locator(sel).first
            if field.count():
                return field.evaluate("el => (el.type || '').toLowerCase()") or ""
        except Exception:
            continue
    return ""


def _secret_in_body_refused(session: Any, directive: Directive) -> Optional[str]:
    """A probe body may carry a secret handle only in a request with a body
    (or a websocket message) to a credential origin - never into a URL."""
    body = directive.body or ""
    if not (_SECRET_HANDLE_RE.search(body) or _ESCAPED_SECRET_HANDLE_RE.search(body)):
        return None
    method = "POST" if directive.kind == "probe_ws" else (directive.method or "GET").upper()
    if method not in ("GET", "HEAD") and session.credentials_allowed(directive.url):
        return None
    return "a secret goes only into a request body to a credential origin"


def _fill_field(form: Any, name: str, value: str) -> bool:
    candidates = [f'[name="{name}"]', f'#{name}']
    for sel in candidates:
        try:
            field = form.locator(sel).first
            if field.count() == 0:
                continue
            tag = (field.evaluate("el => el.tagName.toLowerCase()") or "")
            itype = (field.evaluate("el => (el.type || '').toLowerCase()") or "")
            if tag == "select":
                try:
                    field.select_option(value=value, timeout=2000)
                except Exception:
                    field.select_option(index=0, timeout=2000)
                return True
            if itype in ("checkbox", "radio"):
                field.check(timeout=2000)
                return True
            if itype in ("hidden",):
                field.evaluate("(el, v) => { el.value = v; }", value)
                return True
            if itype in ("file", "submit", "button", "image", "reset"):
                return False
            if not _fillable_now(field) and not _wait_until_fillable(field):
                # Structurally un-fillable. Go straight to the assignment the
                # exception handler below would have reached anyway.
                raise RuntimeError("field is not fillable")
            field.fill(value, timeout=FILL_FULL_MS)
            return True
        except Exception:
            try:
                form.locator(sel).first.evaluate("(el, v) => { el.value = v; }", value)
                return True
            except Exception:
                continue
    # A framework-generated id is often different after the directive navigates
    # back to the observed state. Placeholders are stable and are the selector
    # hint the engine supplies when the application exposes one. Use
    # Playwright's semantic locator so quotes or CSS punctuation in the
    # placeholder cannot change the selector.
    try:
        field = form.get_by_placeholder(name, exact=True).first
        if field.count() == 0:
            return False
        tag = (field.evaluate("el => el.tagName.toLowerCase()") or "")
        itype = (field.evaluate("el => (el.type || '').toLowerCase()") or "")
        if tag == "select" or itype in ("file", "submit", "button", "image", "reset"):
            return False
        if itype in ("checkbox", "radio"):
            field.check(timeout=2000)
        elif itype == "hidden":
            field.evaluate("(el, v) => { el.value = v; }", value)
        elif not _fillable_now(field) and not _wait_until_fillable(field):
            field.evaluate("(el, v) => { el.value = v; }", value)
        else:
            field.fill(value, timeout=FILL_FULL_MS)
        return True
    except Exception:
        try:
            form.get_by_placeholder(name, exact=True).first.evaluate(
                "(el, v) => { el.value = v; }", value)
            return True
        except Exception:
            return False
    return False


def _submit_via_dom(form: Any) -> str:
    """Last resort when no control could be pressed.

    Only meaningful on a real `<form>`.  A synthetic group is a container with no
    submit semantics at all - `requestSubmit` does not exist on it, and the
    request the application would have made is built by its own click handler -
    so pressing something inside it is the only thing that can work.
    """
    try:
        tag = (form.evaluate("el => el.tagName.toLowerCase()") or "")
    except Exception:
        tag = ""
    if tag != "form":
        for sel in ("button", "[role=button]", "input[type=submit]",
                    "input[type=button]"):
            try:
                control = form.locator(sel).first
                if control.count() > 0:
                    control.click(timeout=2500, no_wait_after=True, force=True)
                    return "group-control"
            except Exception:
                continue
        return "not-submitted"
    try:
        form.evaluate(
            "f => { if (f.requestSubmit) { f.requestSubmit(); } else { f.submit(); } }")
        return "dom-submit"
    except Exception:
        return "not-submitted"


def _slow_settle(page: Any, extra_ms: int = 0,
                 wait_network_idle: bool = True) -> None:
    """Playwright's `networkidle` (a 500ms floor by its own definition) plus
    a fixed sleep. Used for an origin that has not proven it can be settled
    faster, for a submit-heavy directive (`extra_ms`), and whenever the fast
    path fails - see `agent/settle.py`."""
    idle_ms = None
    if wait_network_idle:
        idle_start = time.monotonic()
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass
        idle_ms = (time.monotonic() - idle_start) * 1000.0
    try:
        page.wait_for_timeout(SETTLE_MS + extra_ms)
    except Exception:
        time.sleep((SETTLE_MS + extra_ms) / 1000.0)
    if log.isEnabledFor(logging.DEBUG):
        log.debug("_settle: networkidle_wait_ms=%s fixed_sleep_ms=%s",
                  None if idle_ms is None else round(idle_ms, 1),
                  SETTLE_MS + extra_ms)


def _interaction_token(page: Any) -> Optional[str]:
    """Mark the current document, but only where the measured settle is
    already trusted for this origin."""
    if not ENABLE_FAST_SETTLE:
        return None
    origin = settle.origin_of(getattr(page, "url", "") or "")
    if settle.mode_for(origin) != "fast":
        # An origin still calibrating, or one that has been shown to need the
        # full wait, does not get a measured settle on its submissions either.
        return None
    return settle.mark_before_interaction(page)


def _settle_after_interaction(page: Any, token: Optional[str],
                              extra_ms: int = 0) -> None:
    """The interaction settle: observe what the action started, then wait.

    Replaces a flat fixed wait. A CLICK that starts a navigation gets a flat
    delay otherwise, which can be less than the navigation needs, so observing
    the work is a correctness improvement as well as a speed one.

    Falls back to the flat wait whenever the measurement could not be taken,
    and is capped by each call site's own previous fixed cost, so this can
    never be the slower choice.
    """
    if token is None:
        _slow_settle(page, extra_ms, False)
        return
    if settle.settle_after_interaction(
            page, token, cap_ms=SETTLE_MS + extra_ms) is None:
        _slow_settle(page, extra_ms, False)


def _settle(page: Any, extra_ms: int = 0,
            wait_network_idle: bool = True) -> None:
    """Wait for the page to be done - measured, where that has been proven
    safe for this origin, and by the original fixed wait everywhere else.

    See `agent/settle.py` for what is measured and why this is calibrated per
    origin rather than tuned to a smaller constant.

    Deliberately NOT fast-pathed, both conservative on purpose:

    * `wait_network_idle=False` call sites - a hash-route change and a click
      that must not wait for a live SPA's polling to go quiet. They already
      skip the expensive wait.
    * `extra_ms > 0` - the submit-heavy directives, which carry an extra 400ms
      because a form submission's own navigation and re-render are the case a
      settle is most likely to cut short.
    """
    if not ENABLE_FAST_SETTLE or not wait_network_idle or extra_ms:
        _slow_settle(page, extra_ms, wait_network_idle)
        return

    if not settle.timers_run(page):
        # A CSP-sandboxed document: the measured settle would wait forever on
        # a timer that never fires (see `settle.timers_run`). Nothing can run
        # in it, so nothing can change it after load - there is nothing to
        # wait for. Not counted toward calibration either: it says nothing
        # about whether this ORIGIN's live pages settle fast.
        return

    origin = settle.origin_of(getattr(page, "url", "") or "")
    settle.note_navigation(origin)
    mode = settle.mode_for(origin)

    if mode == "fast":
        if settle.fast_settle(page) is not None:
            return
        _slow_settle(page, extra_ms, wait_network_idle)
        return

    if mode == "calibrate":
        # Settle BOTH ways and compare what a check would actually have
        # seen. The fast fingerprint is taken first, then the full wait
        # runs from where the fast path stopped - so this measures exactly
        # "would stopping early have changed the DOM", not two unrelated
        # page loads.
        waited = settle.fast_settle(page)
        if waited is None:
            settle.record(origin, False)
            _slow_settle(page, extra_ms, wait_network_idle)
            return
        fast_fp = settle.fingerprint(page)
        _slow_settle(page, extra_ms, wait_network_idle)
        slow_fp = settle.fingerprint(page)
        if fast_fp is None or slow_fp is None:
            settle.record(origin, False)
        else:
            settle.record(origin, fast_fp == slow_fp)
        return

    _slow_settle(page, extra_ms, wait_network_idle)


# --------------------------------------------------------------------------
# http probe (browser request context: same cookies, same TLS stack)
# --------------------------------------------------------------------------


def _set_cookie_values(pairs: Any) -> list[str]:
    """Every `Set-Cookie` value out of a raw header pair list, redacted the
    same way `redact_headers` treats the (necessarily collapsed) single
    `set-cookie` dict key - see that function's own note for why the value is
    kept whole rather than blanked.

    `pairs` is whatever a transport hands back before it gets `dict()`-ed:
    `http.client`'s `response.getheaders()`, or a `{"name": ..., "value":
    ...}` sequence from Playwright's `headers_array()`. `dict()` over either
    keeps only the LAST `Set-Cookie`, so this reads the pairs directly, in
    order, before that collapse happens.
    """
    out: list[str] = []
    for pair in pairs or ():
        if isinstance(pair, dict):
            name, value = pair.get("name", ""), pair.get("value", "")
        else:
            name, value = pair
        if str(name).lower() == "set-cookie":
            out.append(redact_text(str(value), 400))
    return out


def _probe_raw_query(session: BrowserSession, directive: Directive,
                     capture: CaptureRules) -> Outcome:
    """Send one literal GET, or one POST with a literal body, without URL
    canonicalisation.

    Playwright correctly percent-encodes delimiters in a URL before sending
    them, so that path cannot test targets that read the undecoded query
    string. The same literal bytes are sent in the PATH: `%2e` reaches the
    server as written, not re-encoded to `%252e`. This transport is narrower
    than the browser request context: GET or POST only, primary session
    only, no redirects, and no control characters in the request target or
    body.
    """
    started = time.monotonic()
    method = (directive.method or "GET").upper()
    if (method not in ("GET", "POST")
            or (method == "GET" and directive.body is not None)
            or directive.auth_profile != "primary"
            or not directive.url):
        return Outcome(action_result=ActionResult(
            ok=False, error="raw query refused: only primary GET or POST is allowed"),
                       capture_state=False)
    parsed = urlparse(directive.url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or any(char in (parsed.path or "") + (parsed.query or "")
                          + (directive.body or "")
                   for char in "\r\n")):
        return Outcome(action_result=ActionResult(
            ok=False, error="raw query refused: invalid URL"),
                       capture_state=False)

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    headers = (dict(session.extra_headers)
               if session.extra_headers and not directive.anonymous
               and session.credentials_allowed(directive.url) else {})
    headers.update(directive.headers or {})
    headers.setdefault("Host", parsed.netloc)
    headers.setdefault("Connection", "close")
    cookie_values = []
    for cookie in ([] if directive.anonymous else session.cookies()):
        if _cookie_applies(cookie, directive.url):
            cookie_values.append("%s=%s" % (cookie.get("name", ""),
                                            cookie.get("value", "")))
    if cookie_values and "cookie" not in {key.lower() for key in headers}:
        headers["Cookie"] = "; ".join(cookie_values)

    wait = pacing.claim(_host_of(directive.url))
    if wait:
        time.sleep(wait)
    connection = None
    try:
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "https":
            context = (ssl._create_unverified_context()
                       if session.ignore_https_errors else ssl.create_default_context())
            connection = http.client.HTTPSConnection(
                parsed.hostname, target_port, timeout=12000 / 1000,
                context=context)
        else:
            context = None
            connection = http.client.HTTPConnection(
                parsed.hostname, target_port, timeout=12000 / 1000)
        relay_port = getattr(session, "relay_port", None)
        if relay_port:
            # This transport owns its socket outright and never passes
            # through a Playwright context - the one lane a relay-active
            # run would otherwise still send straight to the target,
            # bypassing whatever SOCKS5-with-credentials upstream the relay
            # exists to route through. Dial the relay and CONNECT instead of
            # letting `HTTPConnection.connect()` reach the target directly.
            host, port = parsed.hostname, target_port

            def _connect_via_relay(conn=connection, ctx=context,
                                   host=host, port=port) -> None:
                sock = relaymod.connect_through_relay(
                    "127.0.0.1", relay_port, host, port, timeout=12000 / 1000)
                conn.sock = ctx.wrap_socket(sock, server_hostname=host) if ctx else sock

            connection.connect = _connect_via_relay
        body_bytes = directive.body.encode("utf-8") if directive.body else None
        connection.request(method, target, body=body_bytes, headers=headers)
        response = connection.getresponse()
        # Read no more than the caller needs: a probe result only ever keeps
        # `capture.body_sample_bytes` of the body. This transport owns the raw socket
        # directly (unlike `_probe_http`'s Playwright-buffered path below, which
        # cannot cheaply stop a read already in progress), so it reads exactly one
        # byte more than the sample limit needs and stops there.
        raw = response.read(capture.body_sample_bytes + 1)[:capture.body_sample_bytes]
        header_pairs = response.getheaders()
        response_headers = redact_headers(dict(header_pairs))
        set_cookie = _set_cookie_values(header_pairs)
        body = redact_text(decode_body(raw, response_headers),
                           capture.body_sample_bytes)
        safe_headers = directive.headers or {}
        # Prefer the server's own declared length when it gave one - the
        # read above is deliberately bounded to the sample size, so
        # `len(raw)` alone would under-report a genuinely larger body.
        content_length = response_headers.get("content-length") or \
            response_headers.get("Content-Length")
        probe = ProbeResponse(
            url=directive.url, status=response.status, ok=True,
            headers=response_headers, set_cookie=set_cookie, body_sample=body,
            body_length=(int(content_length)
                        if content_length and str(content_length).isdigit()
                        else len(raw)),
            elapsed_ms=round((time.monotonic() - started) * 1000, 3),
            redirect_location=response_headers.get("location"),
            raw_request=_raw_request(
                directive, {"method": method, "headers": safe_headers,
                           "data": directive.body}),
            raw_response=_raw_response(response.status, response_headers, body),
            body_z=compress_body(body))
        return Outcome(
            action_result=ActionResult(ok=True,
                                       detail={"status": response.status,
                                               "transport": "raw-query"}),
            probe=probe, capture_state=False)
    except Exception as exc:
        probe = ProbeResponse(
            url=directive.url, ok=False,
            error=f"{type(exc).__name__}: {exc}"[:300],
            elapsed_ms=round((time.monotonic() - started) * 1000, 3))
        return Outcome(action_result=ActionResult(
            ok=True, detail={"probe": "raw-query-failed"}),
                       probe=probe, capture_state=False)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _cookie_applies(cookie: dict[str, Any], url: str) -> bool:
    """Whether a browser-held cookie would actually be sent to `url`.

    The domain check honours the cookie's scope: a HOST-ONLY cookie (no
    leading dot) applies to that exact host only, while a DOMAIN-scoped cookie
    (a leading dot) applies to subdomains too. A host-only `example.com` cookie
    is therefore never replayed to `api.example.com`, matching what the browser
    itself would do. The leading dot is not cosmetic - RFC 6265 (and
    Playwright's own docs) use it to distinguish the two.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    request_path = parsed.path or "/"

    raw_domain = str(cookie.get("domain") or "").lower()
    domain_cookie = raw_domain.startswith(".")
    domain = raw_domain.lstrip(".")
    host_ok = (host == domain) or (domain_cookie and host.endswith("." + domain))

    path = str(cookie.get("path") or "/")
    path_ok = (request_path == path or
              request_path.startswith(path.rstrip("/") + "/"))

    scheme_ok = (not cookie.get("secure")) or parsed.scheme == "https"

    return host_ok and path_ok and scheme_ok


def _cookie_wire_value(value: str) -> str:
    """Percent-encode a cookie value ONLY when RFC 6265 parsers would drop it
    raw (space, `"`, `,`, `\\`, control, non-ASCII)."""
    if all(0x20 < ord(c) < 0x7f and c not in '",\\' for c in value):
        return value
    return quote(value, safe="")


def _cookie_override_header(session: BrowserSession, directive: Directive) -> str:
    """Return the primary session's cookies with one observed cookie replaced.

    Cookie mutation is kept per-request: the browser context remains intact,
    so a failed proof cannot poison later authentication or stateful probes.
    """
    name = str(directive.cookie_name or "")
    value = str(directive.cookie_value or "")
    if (not directive.url or directive.auth_profile != "primary"
            or directive.anonymous or not _COOKIE_NAME_RE.fullmatch(name)
            # Twin guard: see the sibling check in `_set_cookie` above for
            # why 4096, not 1024.
            or len(value) > 4096 or any(c in value for c in "\r\n;")):
        raise ValueError("cookie proof refused: invalid cookie override")
    parsed = urlparse(directive.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("cookie proof refused: invalid URL")
    target_path = str(directive.cookie_path or "/")
    if not target_path.startswith("/"):
        raise ValueError("cookie proof refused: invalid cookie path")
    pairs = []
    replaced = False
    for cookie in session.cookies():
        cookie_name = str(cookie.get("name") or "")
        if not _cookie_applies(cookie, directive.url):
            continue
        # BY NAME, not by name AND path. A `Cookie` header carries no paths, so two
        # entries of the same name are two values of that cookie and the server picks
        # one - which is never reliably the one this probe is trying to test.
        #
        # A `Set-Cookie` with no `Path` attribute defaults to the REQUEST'S
        # DIRECTORY, so a jar cookie and the directive's cookie of the same name can
        # carry different paths. Matching the path too would keep both and send two
        # cookies with one name, which many applications reject whichever order they
        # arrive in.
        #
        # `_cookie_applies` above has already decided this cookie would be sent to
        # this URL. Ours replaces it; the path it was scoped to is not something the
        # request can express.
        if cookie_name == name:
            if not replaced:
                pairs.append(f"{name}={_cookie_wire_value(value)}")
                replaced = True
        else:
            pairs.append(f"{cookie_name}={cookie.get('value', '')}")
    if not replaced:
        pairs.append(f"{name}={_cookie_wire_value(value)}")
    return "; ".join(pairs)


_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_DEFAULT_MAX_REDIRECTS = 20  # for a probe that does not set its own cap
_MAX_BUFFERED_BODY_BYTES = 25 * 1024 * 1024  # ceiling for a response

def _content_length(headers: dict[str, str]) -> Optional[int]:
    value = headers.get("content-length") or headers.get("Content-Length")
    return int(value) if value and str(value).isdigit() else None




# --------------------------------------------------------------------------
# rate limiting
#
# Real sites rate-limit: CDNs, WAFs, nginx `limit_req`, API gateways. Against
# one of those, continuing at full rate spends the request budget on 429s,
# and a probe answered by the rate limiter tests nothing.
#
# The backoff is per host and strictly bounded. Being polite to a target is a
# side effect; the reason this is here is that the requests are WASTED.
# --------------------------------------------------------------------------

_RATE_LIMIT_STATUSES = (429, 503)
_RATE_LIMIT_MAX_SLEEP_S = 10.0     # never stall a scan on one hostile host

#: Highest exponent the backoff will ever evaluate. Past this the
#: `min()` below returns the ceiling anyway, so a larger shift buys
#: nothing and costs an unbounded integer - see `_rate_limit_pause`.
_MAX_BACKOFF_SHIFT = 16
_RATE_LIMIT_BASE_SLEEP_S = 0.5
_rate_limit_streak: dict[str, int] = {}


_host_of = pacing.host_key


def _retry_after_seconds(headers: dict[str, str],
                         now: Optional[float] = None) -> Optional[float]:
    """`Retry-After`, in either legal form: delta-seconds or an HTTP date."""
    raw = ""
    for key, value in (headers or {}).items():
        if str(key).lower() == "retry-after":
            raw = str(value).strip()
            break
    if not raw:
        return None
    try:
        return max(0.0, float(int(raw)))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    reference = now if now is not None else time.time()
    return max(0.0, when.timestamp() - reference)


def _rate_limit_pause(host: str, status: Optional[int],
                      headers: dict[str, str]) -> float:
    """How long to wait before the next request to this host.

    A 503 alone is not rate limiting - it is also an ordinary outage - so it
    only counts when the server actually asked us to come back later.
    """
    if status not in _RATE_LIMIT_STATUSES:
        _rate_limit_streak.pop(host, None)
        return 0.0
    asked = _retry_after_seconds(headers)
    if status == 503 and asked is None:
        return 0.0
    streak = _rate_limit_streak.get(host, 0) + 1
    _rate_limit_streak[host] = streak
    if asked is not None:
        return min(asked, _RATE_LIMIT_MAX_SLEEP_S)
    # No guidance given: back off geometrically from a small base.
    #
    # The cap must be applied BEFORE the exponential is built: `_rate_limit_streak`
    # has no ceiling, and a target that answers 429 forever drives it high enough
    # that the float conversion raises `OverflowError`. A target must not be able
    # to crash the agent merely by rate-limiting it.
    #
    # The shift is therefore bounded before it is evaluated. Past about streak 5
    # the result already clamps to `_RATE_LIMIT_MAX_SLEEP_S`, so anything above
    # `_MAX_BACKOFF_SHIFT` gives the same answer without building a huge integer.
    shift = min(streak - 1, _MAX_BACKOFF_SHIFT)
    return min(_RATE_LIMIT_BASE_SLEEP_S * (2 ** shift),
               _RATE_LIMIT_MAX_SLEEP_S)


def _probe_http(session: BrowserSession, directive: Directive,
                capture: CaptureRules, guard: ScopeGuard,
                retried: bool = False) -> Outcome:
    if directive.raw_query:
        return _probe_raw_query(session, directive, capture)
    if directive.browser_context:
        return _probe_page_context(session, directive, capture)
    started = time.monotonic()
    kwargs: dict[str, Any] = {
        "method": (directive.method or "GET").upper(),
        # A directive may carry its own `timeout_ms`; everything else keeps
        # the short default, so a dead host costs 12 s.
        "timeout": directive.timeout_ms or 12000,
        "fail_on_status_code": False,
        # Always fetched one hop at a time, below - Playwright's own automatic
        # following forwards `headers` (including any Authorization/Cookie override
        # this probe carries) to wherever a `Location` points, BEFORE the agent can
        # scope-check that url. An in-scope page could otherwise redirect a probe to
        # an attacker-controlled host with the operator's Authorization header
        # attached, since `execute()` only scope-checks the directive's OWN url.
        "max_redirects": 0,
    }
    # `_probe_http` fetches through `context.request`, NOT through the page -
    # Playwright's route guard (which normally injects the operator's headers,
    # per-request, for in-scope origins only) does not intercept these calls.
    # Without this, a bearer or custom-header session would authenticate ordinary
    # page traffic while every direct probe replayed unauthenticated. Cookie auth
    # survives only because the request context shares the browser's cookie jar.
    if (directive.auth_profile == "primary" and not directive.anonymous and
            session.extra_headers and session.credentials_allowed(directive.url)):
        kwargs["headers"] = dict(session.extra_headers)
    elif (directive.auth_profile == "secondary" and not directive.anonymous and
            getattr(session, "secondary_headers", None) and
            session.credentials_allowed(directive.url)):
        kwargs["headers"] = dict(session.secondary_headers)
    if directive.headers:
        kwargs.setdefault("headers", {}).update(directive.headers)
    if directive.cookie_name and directive.cookie_value is not None:
        try:
            kwargs.setdefault("headers", {})["Cookie"] = \
                _cookie_override_header(session, directive)
        except ValueError as exc:
            return Outcome(action_result=ActionResult(ok=False, error=str(exc)),
                           capture_state=False)
    if getattr(directive, "upload_fixture", None):
        # A transport upload. The engine named a fixture; the bytes are built
        # HERE, from `UPLOAD_FIXTURES`, and a name the table does not carry
        # is refused outright rather than passed through as data.
        part = upload_part(directive)
        if part is None:
            return Outcome(action_result=ActionResult(
                ok=False,
                error="upload refused: not a named fixture"),
                capture_state=False)
        field = str(getattr(directive, "upload_field", "") or "file")
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,39}$", field):
            return Outcome(action_result=ActionResult(
                ok=False, error="upload refused: implausible field name"),
                capture_state=False)
        kwargs["multipart"] = upload_multipart(directive, part, field)
    elif directive.body is not None:
        try:
            kwargs["data"] = _directive_body(directive)
        except ValueError as exc:
            return Outcome(action_result=ActionResult(ok=False, error=str(exc)),
                           capture_state=False)
    follow_cap = (_DEFAULT_MAX_REDIRECTS if directive.max_redirects is None
                 else max(0, int(directive.max_redirects)))
    try:
        if directive.auth_profile == "secondary":
            request_context = session.secondary_request_context()
            if request_context is None:
                probe = ProbeResponse(
                    url=directive.url or "", ok=False,
                    error="secondary auth profile is not configured",
                    elapsed_ms=round((time.monotonic() - started) * 1000, 3))
                return Outcome(
                    action_result=ActionResult(
                        ok=False, detail={"probe": "secondary-unavailable"}),
                    probe=probe, capture_state=False)
        elif directive.anonymous:
            request_context = session.anonymous_request_context()
            if request_context is None:
                probe = ProbeResponse(
                    url=directive.url or "", ok=False,
                    error="anonymous request context is unavailable",
                    elapsed_ms=round((time.monotonic() - started) * 1000, 3))
                return Outcome(
                    action_result=ActionResult(
                        ok=False, detail={"probe": "anonymous-unavailable"}),
                    probe=probe, capture_state=False)
        else:
            request_context = session.context.request
        if directive.capture_from is not None:
            captured = _perform_capture(request_context, directive.capture_from, guard,
                                        operator_cookies=getattr(session, "preset_cookies", None))
            if isinstance(captured, Outcome):
                return captured
            if kwargs.get("data") is not None:
                kwargs["data"] = resolve_captured_text(kwargs["data"], captured)
            if kwargs.get("headers"):
                kwargs["headers"] = {name: resolve_captured_text(value, captured)
                                     for name, value in kwargs["headers"].items()}
        url = directive.url or ""
        if directive.capture_from is not None:
            url = resolve_captured_url(url, captured)
        for hop in range(follow_cap + 1):
            # The operator's agreed per-host ceiling, if one was set. Inside
            # the redirect loop on purpose: a hop is another request to
            # (possibly) another host, and a limiter that only counts the
            # first request of each directive does not honour the number.
            for attempt in range(len(transient.RETRY_DELAYS_S) + 1):
                wait = pacing.claim(_host_of(url))
                if wait:
                    time.sleep(wait)
                tried = time.monotonic()
                try:
                    response = request_context.fetch(url, **kwargs)
                    break
                except Exception as exc:
                    delay = transient.retry_delay(exc, kwargs["method"], attempt)
                    if delay is None:
                        raise
                    log.info("probe %s retried after %s", url[:200], exc)
                    time.sleep(delay)
                    # The failed attempt and the wait are not the application's
                    # response time - keep them out of elapsed_ms.
                    started += time.monotonic() - tried
            if response.status not in _REDIRECT_STATUSES or hop == follow_cap:
                break
            location = response.headers.get("location")
            if not location:
                break
            next_url = urljoin(url, location)
            decision = guard.check(next_url)
            if not decision.allowed:
                # Stop here rather than raise: the hop that WAS reached is
                # still a real, informative response - just do not take the
                # probe's credentials anywhere further.
                log.warning("redirect to %s refused: %s", next_url[:200],
                           decision.reason)
                session.record_scope_refusal(next_url, via="probe-redirect")
                break
            if not session.credentials_allowed(next_url):
                _strip_credentials(session, kwargs.get("headers") or {})
            if response.status == 303 or (response.status in (301, 302)
                                          and kwargs["method"] != "GET"):
                kwargs["method"] = "GET"
                kwargs.pop("data", None)
            url = next_url
    except Exception as exc:
        probe = ProbeResponse(url=directive.url or "", ok=False,
                              error=f"{type(exc).__name__}: {exc}"[:300],
                              elapsed_ms=round((time.monotonic() - started) * 1000, 3))
        return Outcome(action_result=ActionResult(ok=True, detail={"probe": "failed"}),
                       probe=probe, capture_state=False)

    headers = {}
    try:
        headers = redact_headers(dict(response.headers))
    except Exception:
        pass
    body = ""
    limit = directive.max_body_bytes or capture.body_sample_bytes
    # `response.body()` buffers the ENTIRE response before the sample limit above
    # is applied, so a 200MB reply becomes a 200MB allocation. Playwright's
    # buffered API gives no way to stop a read already in progress, but a
    # response that DECLARES a huge Content-Length can be rejected before that
    # read starts.
    declared_length = _content_length(headers)
    if is_streaming_body(headers):
        # See `STREAMING_CONTENT_TYPES`: this one never ends, so buffering it
        # is a hang and not an allocation.
        body_length = 0
        body = redact_text("[streaming response, not buffered]", limit)
    elif declared_length is not None and declared_length > _MAX_BUFFERED_BODY_BYTES:
        body_length = declared_length
        body = redact_text(f"[{declared_length} bytes, not buffered - "
                           f"exceeds {_MAX_BUFFERED_BODY_BYTES} byte cap]", limit)
    else:
        try:
            raw = response.body()
            rendered = grpcweb.render_response(raw, headers)
            body = redact_text(rendered if rendered is not None
                               else decode_body(raw, headers), limit)
            body_length = len(raw)
        except Exception:
            body_length = 0
    # Measured BEFORE any backoff sleep: a rate-limit pause is our own wait,
    # not the application's response time.
    # Kept to microsecond precision on purpose - see `ProbeResponse.elapsed_ms`.
    elapsed_ms = round((time.monotonic() - started) * 1000, 3)
    pause = _rate_limit_pause(_host_of(response.url), response.status, headers)
    if pause > 0:
        time.sleep(pause)
    if response.status == 429 and not retried:
        # The target refused to process it - send it once more after the
        # pause. Concurrent batches against a target that admits few simultaneous requests
        # can otherwise see most probes answered 429.
        return _probe_http(session, directive, capture, guard, retried=True)
    probe = ProbeResponse(
        url=response.url, status=response.status, ok=True, headers=headers,
        body_sample=body, body_length=body_length,
        elapsed_ms=elapsed_ms,
        redirect_location=headers.get("location") or headers.get("Location"),
        # `response.url` rather than `directive.url`: the redirect loop above
        # may have moved both the target AND the method, and this is the hop
        # the response beside it came from.
        raw_request=_raw_request(directive, kwargs, url=response.url),
        raw_response=_raw_response(response.status, headers, body),
        body_z=compress_body(body),
    )
    # An HTTP probe goes out through the request context, not the page: the
    # live DOM belongs to whatever was last navigated, so capturing state here
    # would attribute a stale document to this probe. The agent enforces the
    # same rule (`outcome.capture_state and kind != "probe_http"`); this is
    # where it is decided.
    return Outcome(
        action_result=ActionResult(ok=True, detail={"status": response.status}),
        probe=probe, capture_state=False)


# --------------------------------------------------------------------------
# concurrent probe_http dispatch - more than one directive per step
#
# `_probe_http` above is the only code path for a single directive.
# Everything below is a SEPARATE path for the case the engine hands back
# more than one directive in one step - it reuses `_probe_http`'s own pure helpers
# (`_cookie_override_header`, `_content_length`, `_rate_limit_pause`,
# `_host_of`, `_raw_request`, `_raw_response`, `redact_headers`,
# `redact_text`, `decode_body`) rather than re-deriving any of that logic,
# so a batched probe's finding is built by the exact same rules a
# sequential one's always was - only the transport that fetched the bytes
# differs. See `sekuscan/agent/async_probe.py` for the actual concurrent
# network I/O; nothing in THIS module ever touches a Playwright object
# from anywhere but the main thread.
# --------------------------------------------------------------------------


def _build_probe_spec(session: BrowserSession, directive: Directive
                      ) -> tuple[Optional[dict[str, Any]], Optional[Outcome]]:
    """The kwargs-building half of `_probe_http`, for a directive the engine
    has already marked batchable (primary auth profile, not anonymous, not
    `raw_query`, not `browser_context`). Returns `(spec, None)` on success, or
    `(None, outcome)` if the directive cannot be turned into a request at all -
    the same cookie-override refusal `_probe_http` itself can hit - so the
    caller can fail just THIS directive without touching the rest of the batch.
    """
    headers: dict[str, str] = {}
    if (directive.auth_profile == "primary" and not directive.anonymous and
            session.extra_headers and session.credentials_allowed(directive.url)):
        headers.update(session.extra_headers)
    if directive.headers:
        headers.update(directive.headers)
    if directive.cookie_name and directive.cookie_value is not None:
        try:
            headers["Cookie"] = _cookie_override_header(session, directive)
        except ValueError as exc:
            return None, Outcome(
                action_result=ActionResult(ok=False, error=str(exc), elapsed_ms=0),
                capture_state=False)
    try:
        body = _directive_body(directive) if directive.body is not None else None
    except ValueError as exc:
        return None, Outcome(
            action_result=ActionResult(ok=False, error=str(exc)),
            capture_state=False)
    follow_cap = (_DEFAULT_MAX_REDIRECTS if directive.max_redirects is None
                 else max(0, int(directive.max_redirects)))
    spec = {
        "directive_id": directive.id,
        "url": directive.url or "",
        "method": (directive.method or "GET").upper(),
        "headers": headers,
        "body": body,
        "body_encoding": directive.body_encoding,
        "timeout_ms": directive.timeout_ms or 12000,
        "max_redirects": follow_cap,
        # Names the async hop loop must drop when a redirect leaves
        # `credential_origins` (it carries no session object).
        "credential_headers": list(session.extra_headers or {}),
        # No session cookies: the worker sends it through its own context.
        "anonymous": bool(directive.anonymous),
    }
    return spec, None


def _outcome_from_async_result(directive: Directive, spec: dict[str, Any],
                               raw: dict[str, Any],
                               capture: CaptureRules) -> Outcome:
    """The response-processing half of `_probe_http`, applied to one
    `agent/async_probe.py` result dict. Mirrors that function's own body -
    same redaction, same body-size guard, same rate-limit pause, same
    `ProbeResponse` shape.
    """
    if not raw.get("ok"):
        probe = ProbeResponse(url=raw.get("url") or spec["url"], ok=False,
                              error=raw.get("error") or "probe failed",
                              elapsed_ms=raw.get("elapsed_ms") or 0)
        return Outcome(
            action_result=ActionResult(ok=True, detail={"probe": "failed"},
                                       elapsed_ms=raw.get("elapsed_ms") or 0),
            probe=probe, capture_state=False)

    headers = {}
    try:
        headers = redact_headers(dict(raw.get("headers") or {}))
    except Exception:
        pass
    body = ""
    body_length = 0
    declared_length = raw.get("declared_length")
    limit = directive.max_body_bytes or capture.body_sample_bytes
    if is_streaming_body(headers):
        # See `STREAMING_CONTENT_TYPES`: this one never ends, so buffering it
        # is a hang and not an allocation.
        body_length = 0
        body = redact_text("[streaming response, not buffered]", limit)
    elif declared_length is not None and declared_length > _MAX_BUFFERED_BODY_BYTES:
        body_length = declared_length
        body = redact_text(f"[{declared_length} bytes, not buffered - "
                           f"exceeds {_MAX_BUFFERED_BODY_BYTES} byte cap]", limit)
    else:
        raw_body = raw.get("body")
        if raw_body is not None:
            try:
                rendered = grpcweb.render_response(raw_body, headers)
                body = redact_text(rendered if rendered is not None
                                   else decode_body(raw_body, headers), limit)
                body_length = len(raw_body)
            except Exception:
                body_length = 0
    elapsed_ms = raw.get("elapsed_ms") or 0
    status = raw.get("status")
    url = raw.get("url") or spec["url"]
    pause = _rate_limit_pause(_host_of(url), status, headers)
    if pause > 0:
        time.sleep(pause)
    final_kwargs = {"method": raw.get("final_method") or spec["method"],
                    "headers": spec["headers"], "data": raw.get("final_data")}
    probe = ProbeResponse(
        url=url, status=status, ok=True, headers=headers,
        body_sample=body, body_length=body_length, elapsed_ms=elapsed_ms,
        redirect_location=headers.get("location") or headers.get("Location"),
        # `url` is `raw["url"]`, the hop the batch worker finished on, and
        # `final_kwargs` already carries its final method and body.
        raw_request=_raw_request(directive, final_kwargs, url=url),
        raw_response=_raw_response(status, headers, body),
        body_z=compress_body(body),
    )
    return Outcome(
        action_result=ActionResult(ok=True, detail={"status": status},
                                   elapsed_ms=elapsed_ms),
        probe=probe, capture_state=False)


def _not_batchable(directive: Directive) -> Optional[str]:
    """Why `directive` cannot go through the concurrent path, or None.

    That path sends a primary-session HTTP request, or an anonymous one from a
    fresh cookie-less context of its own (`async_probe`), and nothing else, so
    anything it would silently ignore or mis-send is refused instead."""
    if directive.kind != "probe_http":
        return "only probe_http directives may be batched"
    if (directive.auth_profile != "primary"
            or directive.capture_from is not None or directive.raw_query
            or directive.browser_context or getattr(directive, "upload_fixture", None)):
        return "this probe cannot be batched"
    return None


def execute_batch(session: BrowserSession, directives: list[Directive],
                  guard: ScopeGuard, capture: CaptureRules,
                  policy: LocalExecutionPolicy, async_worker: Any,
                  batch_timeout_s: float) -> list[Outcome]:
    """Dispatch N independent, already-batchable `probe_http` directives
    concurrently via `async_worker` (an `async_probe.AsyncProbeWorker`,
    typed loosely so this module carries no import-time dependency on it -
    it is only ever needed when `PROBE_BATCH_SIZE > 1`).

    Returns one `Outcome` per directive, in the SAME order as `directives`
    (`agent/cli.py` zips this back against directive ids to build the
    batch `Observation`). Each directive still pays exactly the scope and
    local-risk authorization `execute()` always applies (`_pre_authorize`)
    BEFORE it is ever included in the network dispatch - a refused
    directive never reaches the async worker, and its refusal `Outcome` is
    byte-for-byte what a sequential refusal would produce.
    """
    outcomes: list[Optional[Outcome]] = [None] * len(directives)
    specs: list[dict[str, Any]] = []
    spec_positions: list[int] = []

    for i, directive in enumerate(directives):
        refusal = _pre_authorize(directive, guard, policy)
        if refusal is not None:
            outcomes[i] = refusal
            continue
        directive = _credentials_only_for_its_own_host(directive)
        unbatchable = _secret_in_body_refused(session, directive) or _not_batchable(directive)
        if unbatchable:
            outcomes[i] = Outcome(action_result=ActionResult(
                directive_id=directive.id, kind=directive.kind, ok=False,
                error="refused: %s" % unbatchable), capture_state=False)
            continue
        spec, error_outcome = _build_probe_spec(session, directive)
        if error_outcome is not None:
            outcomes[i] = error_outcome
            continue
        specs.append(spec)
        spec_positions.append(i)

    if specs:
        cookies = session.cookies()

        def scope_check(url: str) -> tuple[bool, str]:
            decision = guard.check(url)
            if not decision.allowed:
                # The run-level breaker must see refusals from EVERY
                # transport, not just the browser's route guard. This is the
                # batch path's only scope decision point (an off-scope
                # redirect hop mid-probe), so recording here covers all of
                # it without threading a session through `async_probe`,
                # which deliberately owns no sync object.
                session.record_scope_refusal(url, via="probe-batch")
            return decision.allowed, decision.reason

        timed_out = False
        try:
            raw_results = async_worker.dispatch_batch(
                specs, cookies, scope_check, batch_timeout_s,
                credential_check=session.credentials_allowed)
        except FuturesTimeout:
            # A batch timeout must not end the whole run: abandon the ACTION, report it
            # as a failed step so the engine sees a reason rather than silence, and let
            # the crawl carry on, as the single-directive path does with `_ActionTimeout`.
            #
            # Easy to hit: the batch deadline is fixed while the work inside it includes
            # rate-limit pacing, so a low `--max-rps` can exceed it with healthy probes.
            #
            # Every directive in the batch falls through to the "no result" branch below,
            # which builds a failed `Outcome` per position - the same shape a partial
            # dispatch produces.
            log.warning("batch of %d exceeded %.0fs and was abandoned; "
                        "the run continues", len(specs), batch_timeout_s)
            raw_results = []
            timed_out = True
        by_directive_id = {r["directive_id"]: r for r in raw_results}
        for spec, position in zip(specs, spec_positions):
            raw = by_directive_id.get(spec["directive_id"])
            directive = directives[position]
            if raw is None:
                outcomes[position] = Outcome(
                    action_result=ActionResult(
                        ok=False,
                        error=("batch-timeout after %.0fs" % batch_timeout_s
                               if timed_out else "no result from batch dispatch"),
                        detail={"timeout_s": batch_timeout_s} if timed_out else {},
                        elapsed_ms=0),
                    capture_state=False)
            else:
                outcomes[position] = _outcome_from_async_result(
                    directive, spec, raw, capture)
                probe = outcomes[position].probe
                if probe is not None and probe.status == 429:
                    # Concurrency is the likeliest reason a batch member is
                    # refused, so the one retry goes out alone - see the
                    # sequential path.
                    outcomes[position] = _probe_http(
                        session, directive, capture, guard, retried=True)

    finalized: list[Outcome] = []
    for directive, outcome in zip(directives, outcomes):
        assert outcome is not None
        outcome.action_result.directive_id = directive.id
        outcome.action_result.kind = directive.kind
        finalized.append(outcome)
    return finalized


def _probe_page_context(session: BrowserSession, directive: Directive,
                        capture: CaptureRules) -> Outcome:
    """Perform one harmless GET through the live page's auth state.

    This is deliberately narrower than the ordinary HTTP probe. A page
    context may carry an application token in local/session storage, so only
    an in-scope GET without a body or caller-supplied headers is allowed. The
    token is read and used inside the browser process; only the redacted
    response crosses the agent boundary.
    """
    if (directive.auth_profile != "primary" or directive.anonymous or
            (directive.method or "GET").upper() != "GET" or
            directive.body is not None or directive.headers):
        return Outcome(
            action_result=ActionResult(
                ok=False,
                error="page-context probe refused: only an empty GET is allowed"),
            capture_state=False)
    # A token found in localStorage/sessionStorage belongs to the page's own
    # origin. It is only sent as a bearer credential to that same origin, never
    # to a *different* scoped origin (a scan covering both `app.example` and
    # `api.example` must not send `app.example`'s token to `api.example`).
    page_origin = urlparse(session.page.url or "")
    target_origin = urlparse(directive.url or "")
    if ((page_origin.scheme, page_origin.hostname, page_origin.port) !=
            (target_origin.scheme, target_origin.hostname, target_origin.port)):
        # The page can be elsewhere when a static route discovered before login is
        # retried after the crawler has followed a redirect or an external link.
        # Refusing here would make the authenticated retry indistinguishable from an
        # endpoint that rejected the credentials. Navigate to the target first so
        # storage is read only from the target origin. We never take a token from the
        # old page and send it across origins; the post-navigation check below
        # preserves that invariant.
        try:
            session.page.goto(directive.url, wait_until="domcontentloaded")
        except Exception as exc:
            return Outcome(
                action_result=ActionResult(
                    ok=False,
                    error="page-context probe could not establish target "
                          f"origin: {type(exc).__name__}: {exc}"[:300]),
                capture_state=False)
        page_origin = urlparse(session.page.url or "")
        if ((page_origin.scheme, page_origin.hostname, page_origin.port) !=
                (target_origin.scheme, target_origin.hostname,
                 target_origin.port)):
            return Outcome(
                action_result=ActionResult(
                    ok=False,
                    error="page-context probe refused: target origin differs "
                          "from the current page's origin"),
                capture_state=False)
    started = time.monotonic()
    limit = directive.max_body_bytes or capture.body_sample_bytes
    try:
        raw = session.page.evaluate(
            """
            async ({url, limit}) => {
              const tokenKeys = new Set([
                "token", "access_token", "accessToken", "jwt",
                "authToken", "authentication", "id_token"
              ]);
              const candidate = (key, value) => {
                if (!tokenKeys.has(String(key)) || !value) return "";
                let text = String(value).trim();
                if (text.startsWith("Bearer ")) text = text.slice(7).trim();
                if (text.startsWith("{") && text.endsWith("}")) {
                  try {
                    const obj = JSON.parse(text);
                    for (const name of ["token", "access_token", "accessToken", "jwt"])
                      if (obj && obj[name]) return candidate(name, obj[name]);
                  } catch (_) {}
                }
                return /^[A-Za-z0-9._~+/=-]{20,}$/.test(text) ? text : "";
              };
              let token = "";
              for (const storage of [window.localStorage, window.sessionStorage]) {
                for (const key of Object.keys(storage)) {
                  token = candidate(key, storage.getItem(key));
                  if (token) break;
                }
                if (token) break;
              }
              const headers = token ? {"Authorization": "Bearer " + token} : {};
              const response = await fetch(url, {
                method: "GET", headers: headers, credentials: "include",
                redirect: "manual"
              });
              const text = await response.text();
              const responseHeaders = {};
              response.headers.forEach((value, key) => { responseHeaders[key] = value; });
              return {
                url: response.url || url, status: response.status,
                headers: responseHeaders, body: text.slice(0, limit),
                body_length: text.length, auth_used: !!token
              };
            }
            """,
            {"url": directive.url or "", "limit": int(limit)},
        )
        headers = redact_headers(dict(raw.get("headers") or {}))
        body = redact_text(str(raw.get("body") or ""), limit)
        status = raw.get("status")
        # Same backoff as the request-context path: a rate limiter does not
        # care which of our two transports asked. Measured before the sleep.
        page_elapsed_ms = int((time.monotonic() - started) * 1000)
        page_pause = _rate_limit_pause(
            _host_of(str(raw.get("url") or directive.url or "")),
            status, headers)
        if page_pause > 0:
            time.sleep(page_pause)
        probe = ProbeResponse(
            url=str(raw.get("url") or directive.url or ""), status=status,
            ok=True, headers=headers, body_sample=body,
            body_length=int(raw.get("body_length") or len(body)),
            elapsed_ms=page_elapsed_ms,
            raw_request=_page_raw_request(directive, bool(raw.get("auth_used"))),
            raw_response=_raw_response(status, headers, body),
            body_z=compress_body(body),
        )
        return Outcome(action_result=ActionResult(
            ok=True, detail={"status": status, "page_context": True}),
            probe=probe, capture_state=False)
    except Exception as exc:
        return Outcome(
            action_result=ActionResult(ok=True, detail={"probe": "failed"}),
            probe=ProbeResponse(url=directive.url or "", ok=False,
                                error=f"{type(exc).__name__}: {exc}"[:300],
                                elapsed_ms=round((time.monotonic() - started) * 1000, 3)),
            capture_state=False)


_WS_SCHEME_EQUIV = {"ws": "http", "wss": "https"}


def _as_http_url(url: str) -> str:
    """The http(s) form of a ws(s) url - same host/path, for cookie lookup.

    Playwright's own cookie jar is keyed by scheme/domain/path like any
    browser's; a websocket probe still authenticates with the SAME cookies
    the page's http(s) origin holds, so the lookup asks for the http(s) form.
    """
    parsed = urlparse(url)
    scheme = _WS_SCHEME_EQUIV.get(parsed.scheme, parsed.scheme)
    return parsed._replace(scheme=scheme).geturl()


def _ws_cookie_header(session: BrowserSession, url: str) -> Optional[str]:
    try:
        cookies = session.context.cookies([_as_http_url(url)])
    except Exception:
        return None
    if not cookies:
        return None
    return "; ".join("%s=%s" % (c.get("name"), c.get("value")) for c in cookies)


def _report_safe_headers(headers: dict[str, str],
                         keep_cookie: Optional[str] = None) -> dict[str, str]:
    """Headers as a REQUEST reconstruction may record them.

    The request-rebuilding paths below (`_ws_raw_request`, `_raw_request`,
    `_network_raw_request`) take the LIVE header set; `redact_text` alone
    redacts bodies and covers no header. This redacts the operator's own
    `Cookie` and `Authorization` so they never reach finding proof, the report
    or the stored scan data. `redact_headers` handles the RESPONSE direction.

    `keep_cookie` names the cookie this directive deliberately set, whose value
    is the probe's own payload rather than a credential - see
    `redact_cookie_header` for why that exemption has to exist.
    """
    safe = redact_headers(headers or {})
    for name, value in (headers or {}).items():
        if name.lower() == "cookie":
            safe[name] = redact_cookie_header(value, keep=keep_cookie)
    return safe


def _ws_raw_request(url: str, headers: dict[str, str], origin: Optional[str],
                    body: Optional[str], limit: int = 2000) -> str:
    lines = [f"GET {urlparse(url).path or '/'} HTTP/1.1",
             f"Host: {urlparse(url).netloc}",
             "Upgrade: websocket", "Connection: Upgrade"]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    for name, value in _report_safe_headers(headers).items():
        lines.append(f"{name}: {value}")
    text = "\r\n".join(lines) + "\r\n\r\n" + (body or "")
    return redact_text(text, limit)


#: Headroom over the caller's capture limit for frame headers and for a
#: continuation sequence the library reassembles. Generous on purpose: this
#: guards against a hostile frame, it is not a sampling knob.
_WS_FRAME_MARGIN = 65536


class _BoundedSocket:
    """A socket that refuses to deliver more than `budget` bytes.

    `connection.recv()` materialises an ENTIRE WebSocket frame before
    `max_body_bytes` is applied, so a server answering with one enormous frame
    could exhaust memory whatever the caller asked for.

    `websocket-client` exposes no frame-size ceiling, and its read path goes
    through `sock.recv()`. Capping the SOCKET therefore bounds the frame
    without reaching into library internals that a future release may rename.

    Exhaustion raises, and the caller treats an exception here as "dropped
    after a successful handshake": we did not get a frame we can trust, and we
    did not stay to collect it. Everything except `recv` delegates, so
    close/send/settimeout still work.
    """

    def __init__(self, sock: Any, budget: int):
        self._sock = sock
        self._remaining = int(budget)

    def recv(self, bufsize: int, *args: Any, **kw: Any) -> bytes:
        if self._remaining <= 0:
            raise OSError("websocket frame exceeded the capture budget")
        chunk = self._sock.recv(min(bufsize, self._remaining), *args, **kw)
        self._remaining -= len(chunk)
        return chunk

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)


def _probe_ws(session: BrowserSession, directive: Directive,
              capture: CaptureRules, guard: ScopeGuard) -> Outcome:
    """Open one independent websocket connection, send one message, and read
    at most one reply - the websocket analogue of `_probe_http`.

    Deliberately its own connection rather than the live page's: a check
    needs a clean status/reply to judge (did the handshake complete, what
    came back), which the application's own client-side reconnect/framing
    logic does not give you, exactly the reasoning `_probe_http` already
    documents for going through `context.request` instead of the page.

    One reply frame, not "whatever arrives before a deadline": a fixed-size
    collection window would make every probe pay the full timeout whenever a
    server sends nothing further (most message types, most of the time),
    turning a triage sweep across many surfaces into a multi-second-per-probe
    cannon. One recv with a bounded wait is the websocket equivalent of one
    HTTP response and costs nothing extra when the server stays quiet.
    """
    import websocket as ws_client

    started = time.monotonic()
    url = directive.url or ""

    if directive.auth_profile == "secondary" and not directive.anonymous:
        # Mirrors `_probe_http`: a probe explicitly asking for the optional
        # second identity gets a clean "not configured" answer rather than
        # silently connecting as anonymous, which would read a genuinely
        # unmeasured comparison as "no leak found".
        if not (session.secondary_cookies or session.secondary_headers):
            probe = ProbeResponse(
                url=url, ok=False,
                error="secondary auth profile is not configured",
                elapsed_ms=round((time.monotonic() - started) * 1000, 3))
            return Outcome(action_result=ActionResult(
                ok=False, detail={"probe": "secondary-unavailable"}),
                probe=probe, capture_state=False)

    headers: dict[str, str] = {}
    if (directive.auth_profile == "primary" and not directive.anonymous and
            session.extra_headers and session.credentials_allowed(url)):
        headers.update(session.extra_headers)
    elif (directive.auth_profile == "secondary" and not directive.anonymous and
            session.secondary_headers and session.credentials_allowed(url)):
        headers.update(session.secondary_headers)
    if directive.headers:
        headers.update(directive.headers)
    # `Origin` is handed to the client's dedicated parameter rather than
    # left to collide with whatever the library would otherwise send.
    origin = headers.pop("Origin", headers.pop("origin", None))
    if directive.anonymous:
        cookie_header = None
    elif directive.auth_profile == "secondary":
        cookie_header = ("; ".join(f"{k}={v}" for k, v in
                                   session.secondary_cookies.items())
                         if session.secondary_cookies and session.credentials_allowed(url) else None)
    elif directive.auth_profile == "primary":
        cookie_header = _ws_cookie_header(session, url)
    else:
        cookie_header = None

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    connect_timeout_s = (directive.timeout_ms or 8000) / 1000.0
    reply_timeout_s = min(connect_timeout_s, 4.0)
    sslopt = {"cert_reqs": ssl.CERT_NONE} if session.ignore_https_errors else None
    raw_request = _ws_raw_request(url, headers, origin, directive.body)
    wait = pacing.claim(_host_of(url))
    if wait:
        time.sleep(wait)

    # Never follow a handshake redirect: the hop would carry these credentials
    # to a URL nobody checked. The 3xx comes back as a refused handshake.
    # With a local relay running, connect through it as every other lane does.
    relay_port = getattr(session, "relay_port", None)
    via_relay = ({"http_proxy_host": "127.0.0.1", "http_proxy_port": relay_port,
                  "proxy_type": "http"} if relay_port else {})
    try:
        connection = ws_client.create_connection(
            url, timeout=connect_timeout_s,
            header=[f"{k}: {v}" for k, v in headers.items()],
            cookie=cookie_header, origin=origin, sslopt=sslopt,
            enable_multithread=False, redirect_limit=0, **via_relay)
    except ws_client.WebSocketBadStatusException as exc:
        # The handshake completed and the server answered - a real,
        # informative result (a hostile Origin refused, an anonymous
        # connection refused), not a transport failure. Mirrors `_probe_http`
        # treating any completed exchange, error status included, as `ok`.
        probe = ProbeResponse(
            url=url, status=exc.status_code, ok=True,
            headers=redact_headers(dict(getattr(exc, "resp_headers", None) or {})),
            raw_request=raw_request,
            raw_response="HTTP %s (handshake refused)" % exc.status_code,
            elapsed_ms=elapsed_ms())
        return Outcome(action_result=ActionResult(
            ok=True, detail={"probe": "handshake-refused"}),
            probe=probe, capture_state=False)
    except Exception as exc:
        probe = ProbeResponse(url=url, ok=False,
                              error=f"{type(exc).__name__}: {exc}"[:300],
                              raw_request=raw_request, elapsed_ms=elapsed_ms())
        return Outcome(action_result=ActionResult(ok=True, detail={"probe": "failed"}),
                       probe=probe, capture_state=False)

    reply = ""
    # A server that rejects at the application layer commonly cannot refuse the
    # HTTP-level Upgrade at all (most ASGI/Node frameworks have no clean way to
    # answer an Upgrade request with a plain 403 - `WebSocketBadStatusException`
    # above only covers the minority that can). The ordinary shape is instead:
    # complete the handshake, then immediately close. With this client library
    # `recv()` then raises nothing and returns `""`, indistinguishable from "no
    # reply yet" by content alone - `connection.connected` is the one signal
    # that tells them apart.
    rejected_after_accept = False
    try:
        if directive.body is not None:
            connection.send(resolve_secret_text(directive.body))
        connection.settimeout(reply_timeout_s)
        # Bound the frame BEFORE it is read, not after. See `_BoundedSocket`.
        # The margin over the capture limit leaves room for frame headers and
        # for a continuation the library stitches together, so an ordinary
        # reply is never cut by this - only a pathological one is refused.
        ws_budget = (directive.max_body_bytes or capture.body_sample_bytes)
        try:
            connection.sock = _BoundedSocket(connection.sock,
                                             ws_budget + _WS_FRAME_MARGIN)
        except Exception:
            pass
        try:
            frame = connection.recv()
            reply = frame if isinstance(frame, str) else decode_body(frame or b"")
            if not reply and not connection.connected:
                rejected_after_accept = True
        except ws_client.WebSocketTimeoutException:
            pass  # no reply within the window, connection still open - a
                  # real, common answer, not a rejection
        except ws_client.WebSocketConnectionClosedException:
            rejected_after_accept = True
        except Exception:
            rejected_after_accept = True  # dropped after a successful handshake
    finally:
        try:
            connection.close()
        except Exception:
            pass

    limit = directive.max_body_bytes or capture.body_sample_bytes
    body = redact_text(reply, limit)
    # 1006 ("abnormal closure") is websocket's own vocabulary for exactly this:
    # the connection ended with no proper close handshake the client could read a
    # reason from. Reporting it, rather than still reporting 101, lets a
    # consumer distinguish a genuine accept from an accept-then-reject without a
    # second field in every `_probe_ws` result.
    status = 1006 if rejected_after_accept else 101
    probe = ProbeResponse(
        url=url, status=status, ok=True, body_sample=body, body_length=len(reply),
        raw_request=raw_request,
        raw_response=redact_text(
            "HTTP/1.1 101 Switching Protocols\r\n\r\n" + reply if not
            rejected_after_accept else
            "HTTP/1.1 101 Switching Protocols\r\n\r\n(closed with no reply)",
            limit + 200),
        elapsed_ms=elapsed_ms())
    return Outcome(action_result=ActionResult(ok=True, detail={"status": status}),
                   probe=probe, capture_state=False)


def _page_raw_request(directive: Directive, auth_used: bool) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(directive.url or "")
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    note = ("page context used application-managed auth state"
            if auth_used else "page context had no recognized auth token")
    return (f"GET {target} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
            f"X-SekuScan-Note: {note}\r\n\r\n")


def _raw_request(directive: Directive, kwargs: dict[str, Any],
                 limit: int = 2000, url: Optional[str] = None) -> str:
    """The request as an analyst would paste it into a repeater.

    `url` is the request this reconstruction DESCRIBES, and callers that
    followed redirects must pass the hop they actually ended on. The method and
    body come from `kwargs`, which the redirect loop mutates (a POST becomes a
    GET and drops its body on a 303, or on a 301/302 that was not already a
    GET), so the target must match: evidence that describes a request nobody
    made is worse than no evidence.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url or directive.url or "")
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    lines = [f"{kwargs.get('method', 'GET')} {target} HTTP/1.1",
             f"Host: {parts.netloc}"]
    for name, value in _report_safe_headers(
            kwargs.get("headers") or {},
            keep_cookie=str(directive.cookie_name or "") or None).items():
        lines.append(f"{name}: {value}")
    if directive.anonymous:
        lines.append("X-SekuScan-Note: sent with no cookies and no auth header")
    body = kwargs.get("data")
    text = "\r\n".join(lines) + "\r\n\r\n" + (body if isinstance(body, str) else "")
    return redact_text(text, limit)


#: A body larger than this is not carried whole. Ordinary responses come nowhere
#: near it, and the ceiling exists so a
#: pathological download cannot turn one probe into a multi-megabyte POST.
MAX_CARRIED_BODY = 2_000_000


def compress_body(body: str) -> str:
    """The whole redacted body, zlib-compressed and base64-encoded.

    `_raw_response` keeps a 1800-byte PREFIX; this carries the rest.

    Redaction has already run on `body` before this is called; nothing
    unredacted leaves the agent.
    """
    if not body:
        return ""
    raw = body.encode("utf-8", "replace")
    if len(raw) > MAX_CARRIED_BODY:
        return ""
    return base64.b64encode(zlib.compress(raw, 6)).decode("ascii")


def _raw_response(status: Optional[int], headers: dict[str, str], body: str,
                  head_limit: int = 1200, body_limit: int = 1800) -> str:
    """Status line, headers and the start of the body.

    Kept as-is deliberately: everything that reads a stored exchange today
    expects this shape. The whole body travels beside it in
    `ProbeResponse.body_z` - see `compress_body`.
    """
    lines = [f"HTTP/1.1 {status if status is not None else '?'}"]
    for name, value in list(headers.items())[:20]:
        lines.append(f"{name}: {value}")
    head = "\r\n".join(lines)[:head_limit]
    return head + "\r\n\r\n" + (body or "")[:body_limit]


def probe_from_network(directive: Directive, events: list[Any],
                       preferred_url: Optional[str] = None
                       ) -> Optional[ProbeResponse]:
    """Turn a redacted browser submission event into reportable wire proof.

    ``fill_submit`` and ``upload_file`` are browser actions rather than direct
    ``probe_http`` directives, so Playwright has the authoritative request
    body. The event has already passed BrowserSession's header/body redaction.
    Only an in-scope non-GET request is eligible; no cookie or authorization
    header is reconstructed.
    """
    if directive.kind not in {"fill_submit", "upload_file"}:
        return None
    target = urlparse(directive.url or "")
    preferred = urlparse(preferred_url or directive.url or "")
    candidates: list[tuple[int, int, Any]] = []
    for event in events or []:
        method = str(getattr(event, "method", "") or "").upper()
        if method in {"HEAD", "OPTIONS"}:
            continue
        url = str(getattr(event, "url", "") or "")
        parsed = urlparse(url)
        if not url or (target.netloc and parsed.netloc != target.netloc):
            continue
        if method == "GET":
            # A GET form submission has no request body, but its response is
            # still the proof for the exact stateful form action. Restrict
            # this exception to fill_submit and the observed target path so a
            # page navigation or an unrelated same-origin asset cannot become
            # workflow evidence.
            if directive.kind != "fill_submit" \
                    or parsed.path != (preferred.path or target.path or "/"):
                continue
        body = getattr(event, "request_body_sample", None)
        if (method != "GET" and body is None
                and not getattr(event, "failure", None)):
            continue
        score = 0
        if preferred.netloc and parsed.netloc == preferred.netloc:
            score += 20
            if parsed.path == (preferred.path or "/"):
                score += 60
            if preferred.query and parsed.query == preferred.query:
                score += 10
        # A native form action ranks highest; otherwise the last event wins,
        # with a small preference for one carrying the submitted body.
        if getattr(event, "resource_type", None) == "document":
            score += 10
        if body is not None:
            score += 5
        candidates.append((score, len(candidates), event))
    if not candidates:
        return None
    _score, _order, event = max(candidates, key=lambda item: (item[0], item[1]))
    url = str(getattr(event, "url", "") or directive.url or "")
    # Defense in depth for callers constructing NetworkEvent themselves: the
    # browser capture already filters these, but a wire-proof helper must never
    # make cookies or authorization headers reportable by accident.
    safe_request_headers = {"content-type", "accept", "origin", "referer",
                            "x-requested-with", "user-agent",
                            "accept-language", "soapaction",
                            "graphql-operation-name", "prefer"}
    req_headers = {
        str(k): str(v) for k, v in
        (getattr(event, "request_headers", {}) or {}).items()
        if str(k).lower() in safe_request_headers
    }
    res_headers = dict(getattr(event, "response_headers", {}) or {})
    # `response_headers` is a collapsed dict, so this carries every
    # `Set-Cookie` the browser capture saw (`agent/browser.py`).
    res_set_cookie = list(getattr(event, "set_cookie", None) or [])
    body = str(getattr(event, "request_body_sample", None) or "")
    response_body = str(getattr(event, "response_body_sample", None) or "")
    status = getattr(event, "status", None)
    failure = getattr(event, "failure", None)
    # `ok` describes transport/capture success, not application semantics.
    # A 4xx/5xx response is still a captured response.
    ok = not failure and status is not None
    method = str(getattr(event, "method", "POST") or "POST")
    return ProbeResponse(
        url=url, status=status, ok=ok,
        headers=res_headers, set_cookie=res_set_cookie, body_sample=response_body,
        body_length=int(getattr(event, "response_length", None)
                        or len(response_body)),
        elapsed_ms=getattr(event, "elapsed_ms", None),
        error=str(failure)[:300] if failure else None,
        raw_request=_network_raw_request(
            method=method, url=url, headers=req_headers, body=body,
            truncated=bool(getattr(event, "request_body_truncated", False))),
        raw_response=_raw_response(status, res_headers, response_body),
        body_z=compress_body(response_body),
    )


def _network_raw_request(method: str, url: str, headers: dict[str, str],
                         body: str, truncated: bool = False) -> str:
    parts = urlparse(url)
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    lines = [f"{method.upper()} {target} HTTP/1.1",
             f"Host: {parts.netloc}"]
    for name, value in list(_report_safe_headers(headers).items())[:20]:
        lines.append(f"{name}: {value}")
    if truncated:
        lines.append("X-SekuScan-Note: request body sample truncated")
    return redact_text("\r\n".join(lines) + "\r\n\r\n" + body, 3000)


def _screenshot(session: BrowserSession, directive: Directive, out_dir: str,
                seq: int) -> Outcome:
    # The name comes from the engine: keep it a plain file name inside out_dir.
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", directive.name or "").lstrip(".")[:80] or f"{seq:04d}"
    path = os.path.join(out_dir, "screenshots", f"{name}.png")
    saved = session.screenshot(path)
    return Outcome(
        action_result=ActionResult(ok=bool(saved),
                                  error=None if saved else "screenshot failed",
                                  detail={"path": saved}),
        screenshots=[saved] if saved else [], capture_state=False)
