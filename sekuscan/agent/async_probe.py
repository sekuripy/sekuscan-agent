# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Concurrent dispatch for a batch of independent `probe_http` directives.

Playwright's sync API - what the rest of this agent (`browser.py`,
`execute.py`) is built on - is thread-pinned: calling a sync
`context.request.fetch()` from a worker thread fails every call with
`greenlet.error: cannot switch to a different thread`. Playwright's async
API, driven with `asyncio.gather()`, dispatches concurrently and correctly.

So this module never touches the sync `BrowserSession`'s own Playwright
objects, and the sync objects never touch this module's. It owns a
SEPARATE, lightweight async Playwright connection - a bare
`playwright.request` context (no browser, no page needed at all; the same
browser-less HTTP-client shape `BrowserSession.secondary_request_context()`/
`anonymous_request_context()` already use on the sync side, via
`self._pw.request.new_context(...)` rather than `self.browser.new_context()`)
- running on its own dedicated background thread with its own event loop,
started once per run and reused across every batch.

Division of labor, deliberately narrow: this module's ONLY job is the
network I/O (fetch, follow redirects one hop at a time, read the body) and
returning plain, primitive results. Turning those into `ProbeResponse`/
`ActionResult`/`Outcome` objects - redaction, the body-size guard, rate-limit
backoff, `raw_request`/`raw_response` reconstruction - stays on the main
thread in `execute.py`, reusing the same helper
functions as the sequential path. Nothing about how a probe's
result is INTERPRETED changes because of where the bytes came from.

Only ordinary `probe_http` directives are handed to this module. Directives
that need a different transport (`secondary`, `raw_query`, `browser_context`)
are never batched; each is executed by its own sequential path.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
from .bodies import is_streaming_body
from concurrent.futures import TimeoutError as FuturesTimeout
import logging
import threading
import time
from urllib.parse import urlparse

from . import pacing, transient
from typing import Any, Callable, Optional
from urllib.parse import urljoin

log = logging.getLogger("sekuscan.agent.async_probe")

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# How long to wait for the worker thread's event loop to come up before
# giving up and raising - startup is just spawning a Playwright driver
# process, not launching a browser, so this is generous rather than tight.
_STARTUP_TIMEOUT_S = 30.0
_SHUTDOWN_TIMEOUT_S = 10.0



_host_of = pacing.host_key


class AsyncProbeWorker:
    """One dedicated thread + event loop + async Playwright driver, for the
    lifetime of one agent run. `start()`/`stop()` mirror
    `BrowserSession.start()`/`stop()`'s own one-time-cost shape; unlike a
    `BrowserSession`, nothing here ever launches a browser process.
    """

    def __init__(self, ignore_https_errors: bool = True,
                 proxy: Optional[dict] = None,
                 user_agent: Optional[str] = None):
        self._ignore_https_errors = ignore_https_errors
        # The batch worker builds its OWN `playwright.request.new_context()`,
        # which inherits nothing from the browser context - so, exactly like
        # the anonymous/secondary request contexts in `browser.py`, it must be
        # handed the proxy explicitly or every batched probe goes out direct.
        # This is what routes concurrent probes through the local relay (SOCKS5
        # auth, or NTLM-to-target interception); `None` is the ordinary
        # no-proxy run and changes nothing.
        self._proxy = proxy
        # ...and, for the same reason, the browser's `user_agent`: a bare
        # request context defaults to Playwright's own User-Agent, so the
        # value is passed explicitly to match the sequential path.
        self._user_agent = user_agent
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._pw: Any = None
        self._ready = threading.Event()
        self._start_error: Optional[BaseException] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run_forever, daemon=True, name="sekuscan-async-probe")
        self._thread.start()
        if not self._ready.wait(timeout=_STARTUP_TIMEOUT_S):
            raise RuntimeError("async probe worker did not start in time")
        if self._start_error is not None:
            raise self._start_error

    def _run_forever(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._init_driver())
        except BaseException as exc:  # noqa: BLE001 - surfaced to start()
            self._start_error = exc
        finally:
            self._ready.set()
        loop.run_forever()

    async def _init_driver(self) -> None:
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()

    def stop(self) -> None:
        loop = self._loop
        if loop is None:
            return
        self._loop = None  # dispatch_batch must refuse once stop() is called,
                           # not race a stopped loop into a silent hang
        try:
            fut = asyncio.run_coroutine_threadsafe(self._shutdown(), loop)
            fut.result(timeout=_SHUTDOWN_TIMEOUT_S)
        except Exception:
            log.exception("async probe worker shutdown failed")
        loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=_SHUTDOWN_TIMEOUT_S)

    async def _shutdown(self) -> None:
        if self._pw is not None:
            await self._pw.stop()
            self._pw = None

    # -- dispatch ------------------------------------------------------

    def dispatch_batch(self, specs: list[dict[str, Any]],
                       cookies: list[dict[str, Any]],
                       scope_check: Callable[[str], tuple[bool, str]],
                       batch_timeout_s: float,
                       credential_check: Optional[Callable[[str], bool]] = None,
                       ) -> list[dict[str, Any]]:
        """Run every spec in `specs` concurrently; return one result dict
        per spec, in the SAME order as `specs`, so the call site can match
        each result back to its directive id.

        `scope_check(url) -> (allowed, reason)` is `ScopeGuard.check`'s pure
        decision, thread-safe since it touches no Playwright object - passed
        in rather than imported, so this module has no dependency on
        `agent/scope.py`'s own object shape.
        """
        loop = self._loop
        if loop is None:
            raise RuntimeError("async probe worker not started")
        fut = asyncio.run_coroutine_threadsafe(
            self._dispatch_batch_async(specs, cookies, scope_check,
                                       credential_check), loop)
        try:
            return fut.result(timeout=batch_timeout_s)
        except FuturesTimeout:
            # `fut.result(timeout=...)` only stops waiting: the coroutine and
            # its in-flight requests would otherwise carry on in the loop
            # thread, holding connections and spending the target's rate
            # budget. Abandoning a batch has to abandon the work.
            #
            # `cancel()` is best-effort: a coroutine already past its last
            # await point runs to completion; no new await resumes.
            fut.cancel()
            raise

    async def _dispatch_batch_async(
            self, specs: list[dict[str, Any]], cookies: list[dict[str, Any]],
            scope_check: Callable[[str], tuple[bool, str]],
            credential_check: Optional[Callable[[str], bool]] = None,
            ) -> list[dict[str, Any]]:
        # A bare `APIRequestContext` (no browser, no page) has no
        # `add_cookies()`, so cookies are seeded at creation time via
        # `storage_state`, in the dict shape `BrowserSession.cookies()`
        # already returns.
        new_context_kwargs: dict[str, Any] = {
            "ignore_https_errors": self._ignore_https_errors}
        if self._proxy:
            new_context_kwargs["proxy"] = self._proxy
        if self._user_agent:
            new_context_kwargs["user_agent"] = self._user_agent
        contexts: list[Any] = []

        async def fresh(seeded: bool) -> Any:
            kwargs = dict(new_context_kwargs)
            if seeded and cookies:
                kwargs["storage_state"] = {
                    "cookies": [_normalized_cookie(c) for c in cookies],
                    "origins": []}
            context = await self._pw.request.new_context(**kwargs)
            contexts.append(context)
            return context

        # An anonymous probe gets a context of its own, never the seeded one
        # and never a sibling's: a Set-Cookie one anonymous probe receives
        # must not reach the next (`BrowserSession.anonymous_request_context`
        # rebuilds its own context for the same reason).
        primary = (await fresh(True)
                   if any(not spec.get("anonymous") for spec in specs) else None)

        async def run(spec: dict[str, Any]) -> dict[str, Any]:
            context = await fresh(False) if spec.get("anonymous") else primary
            return await self._one(context, spec, scope_check, credential_check)

        try:
            results = await asyncio.gather(*(run(spec) for spec in specs),
                                           return_exceptions=True)
        finally:
            for context in contexts:
                await context.dispose()
        return [self._as_result(specs[i], r) for i, r in enumerate(results)]

    @staticmethod
    def _as_result(spec: dict[str, Any], outcome: Any) -> dict[str, Any]:
        if isinstance(outcome, BaseException):
            return {"directive_id": spec["directive_id"], "ok": False,
                    "error": f"{type(outcome).__name__}: {outcome}"[:300],
                    "elapsed_ms": 0, "final_method": spec["method"],
                    "final_data": spec.get("body")}
        return outcome

    async def _one(self, context: Any, spec: dict[str, Any],
                   scope_check: Callable[[str], tuple[bool, str]],
                   credential_check: Optional[Callable[[str], bool]] = None,
                   ) -> dict[str, Any]:
        """One directive's fetch, following redirects one hop at a time -
        the async mirror of `execute.py::_probe_http`'s own loop, kept as
        close to its structure as the sync/async split allows."""
        started = time.monotonic()
        url = spec["url"]
        method = spec["method"]
        headers = dict(spec.get("headers") or {})
        data = spec.get("body")
        wire_data = data
        if spec.get("body_encoding") == "base64" and data is not None:
            try:
                wire_data = base64.b64decode(data, validate=True)
            except (ValueError, binascii.Error):
                return {"directive_id": spec["directive_id"], "ok": False,
                        "error": "probe body refused: invalid base64 encoding",
                        "elapsed_ms": 0, "final_method": method,
                        "final_data": data, "url": url}
        timeout_ms = spec.get("timeout_ms") or 12000
        follow_cap = spec.get("max_redirects")
        if follow_cap is None:
            follow_cap = 20
        try:
            for hop in range(follow_cap + 1):
                # Same per-host ceiling the sync path honours, reached
                # through the same allocator - `pacing.claim` hands out a
                # future slot rather than sleeping, which is what lets one
                # implementation serve a blocking caller and this awaiting
                # one. Without it a batch of N would leave as a burst of N,
                # which is precisely what a rate ceiling exists to prevent.
                kwargs: dict[str, Any] = {
                    "method": method, "timeout": timeout_ms,
                    "fail_on_status_code": False, "max_redirects": 0,
                }
                if headers:
                    kwargs["headers"] = headers
                if wire_data is not None:
                    kwargs["data"] = wire_data
                # Same retry policy as the sync path - see `transient`.
                for attempt in range(len(transient.RETRY_DELAYS_S) + 1):
                    wait = pacing.claim(_host_of(url))
                    if wait:
                        await asyncio.sleep(wait)
                    tried = time.monotonic()
                    try:
                        response = await context.fetch(url, **kwargs)
                        break
                    except Exception as exc:
                        delay = transient.retry_delay(exc, method, attempt)
                        if delay is None:
                            raise
                        log.info("probe %s retried after %s", url[:200], exc)
                        await asyncio.sleep(delay)
                        started += time.monotonic() - tried
                if response.status not in _REDIRECT_STATUSES or hop == follow_cap:
                    break
                location = response.headers.get("location")
                if not location:
                    break
                next_url = urljoin(url, location)
                allowed, reason = scope_check(next_url)
                if not allowed:
                    log.warning("redirect to %s refused: %s", next_url[:200], reason)
                    break
                # In scope is not authorised for the operator's credential:
                # drop the session headers/Cookie before following onto an
                # origin outside `credential_origins` (see
                # `execute._strip_credentials`, the sync mirror).
                if credential_check is not None and not credential_check(next_url):
                    drop = {n.lower() for n in spec.get("credential_headers") or ()}
                    drop.add("cookie")
                    headers = {k: v for k, v in headers.items()
                               if k.lower() not in drop}
                if response.status == 303 or (
                        response.status in (301, 302) and method != "GET"):
                    method = "GET"
                    data = None
                    wire_data = None
                url = next_url
        except Exception as exc:
            return {"directive_id": spec["directive_id"], "ok": False,
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "final_method": method, "final_data": data,
                    "url": url}

        response_headers = dict(response.headers)
        declared_length = _content_length(response_headers)
        body: Optional[bytes] = None
        # `is_streaming_body` first: an unknown length is the ordinary case
        # for chunked transfer, but a stream never ends, so buffering it
        # would hang this worker instead of merely allocating.
        if is_streaming_body(response_headers):
            body = None
        elif declared_length is None or declared_length <= _MAX_BUFFERED_BODY_BYTES:
            try:
                body = await response.body()
            except Exception:
                body = None
        return {
            "directive_id": spec["directive_id"], "ok": True,
            "status": response.status, "headers": response_headers,
            "url": response.url, "body": body,
            "declared_length": declared_length,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "final_method": method, "final_data": data,
        }


def _normalized_cookie(cookie: dict[str, Any]) -> dict[str, Any]:
    """`storage_state`'s schema requires every one of these fields. A real
    `context.cookies()` call always includes them; this is a defensive
    default for a hand-built cookie dict."""
    out = dict(cookie)
    out.setdefault("expires", -1)
    out.setdefault("httpOnly", False)
    out.setdefault("secure", False)
    out.setdefault("sameSite", "Lax")
    return out


def _content_length(headers: dict[str, str]) -> Optional[int]:
    value = headers.get("content-length") or headers.get("Content-Length")
    return int(value) if value and str(value).isdigit() else None


# Kept identical to `execute.py`'s own constant rather than imported, so
# this module has no import-time dependency on `execute.py` (which imports
# `BrowserSession`, a sync-Playwright-bound object this module must never
# touch) - see the module docstring. Keep the two values equal.
_MAX_BUFFERED_BODY_BYTES = 25 * 1024 * 1024
