# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Adaptive page settle: measure when a page is actually done, per origin.

A fixed wait after every browser action (Playwright's `networkidle`, which has
a 500 ms floor, plus a blind sleep) is most of the cost of an action: the page
often loads and its DOM can be collected in tens of milliseconds, and the rest
is a timer.

## How it works, and how it stays correct

The fast path asks the page directly instead of waiting a fixed time:
`document.readyState === 'complete'`, no in-flight `fetch`/XHR for
`NET_QUIET_MS`, and no DOM mutation for `DOM_QUIET_MS`. On server-rendered
pages a short quiet window produces the same DOM as the full wait, several
times faster.

It cannot be assumed to be safe for every site. A single-page application may
render its content well after the network and the DOM have both gone quiet, so
no fixed window is correct everywhere. A scanner that silently collected part
of such a page would miss findings without saying so.

So the fast path is never assumed: for the first `CALIBRATION_SAMPLES`
navigations to an origin this settles both ways and compares a cheap DOM
fingerprint. Only an origin whose fast and slow fingerprints agree every time
gets the fast path, and even then one navigation in `REVALIDATE_EVERY`
re-checks the same way, because a site can be server-rendered in places and
script-heavy in others. Any disagreement pins that origin to the slow path for
the rest of the run.

The cost of being wrong is asymmetric (a missed page is invisible; a slower
scan is not), so every failure mode resolves to the slow path: an evaluate
that throws, an execution context destroyed mid-navigation, an origin that
cannot be parsed, an unknown state.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional
from urllib.parse import urlparse

log = logging.getLogger("sekuscan.agent.settle")

# The settle poll after an interaction uses `wait_for_function`, which takes a
# real `timeout=`, survives the execution context being torn down mid-
# navigation by re-evaluating in the new one, and raises instead of hanging.
# A bare `page.evaluate()` loop has no per-call timeout and can block
# indefinitely when a navigation never stabilises. Imported at module level,
# guarded, so this file stays importable with no browser installed (the pure-
# logic helpers such as `reset` need no Playwright).
try:
    from playwright.sync_api import TimeoutError as _PlaywrightTimeoutError
    _INTERACTION_TIMEOUT_EXCS: tuple = (_PlaywrightTimeoutError,)
except Exception:  # pragma: no cover - playwright absent
    _INTERACTION_TIMEOUT_EXCS = ()

# No in-flight fetch/XHR for this long, and no DOM mutation for this long,
# and readyState complete -> the page is done. The window alone does not decide
# correctness for script-rendered pages; calibration does.
NET_QUIET_MS = 60
DOM_QUIET_MS = 60
# A one-shot timer scheduled before we looked, due within this long, is
# pending work: it has not run yet and it is going to. For example, a page can
# ship a placeholder and a script that replaces it with a form and a link some
# hundreds of milliseconds later; settling before that would see no forms or
# links.
#
# Only setTimeout, never setInterval: an interval is a page that is
# permanently busy (polling, a clock, an animation loop) and waiting for one
# is waiting forever. Only short delays, because a timer due in thirty
# seconds is not this page finishing loading. And capped in total, so a chain
# of timers that each schedule the next cannot hold a navigation open.
#
# Both limits can be overridden by environment variable, with the default
# unchanged, because the boundary is a judgement and not a fact. A deferred
# request a few seconds after load (analytics, a lazy widget, a consent banner
# writing back) is a real pattern, but waiting that long on every navigation
# that happens to hold a timer is not a good default.
#
# The wait only happens when a timer is actually pending, so a page without
# one costs nothing either way, and `LATE_TIMER_BUDGET_MS` still caps the
# total however high the per-timer ceiling goes.
def _tunable(name: str, default: int) -> int:
    """An operator's tuning setting must never stop the agent from starting.

    These are read at import time, so a malformed value must not raise: the
    agent would fail to start with a traceback from a module the operator has
    never heard of. A bad value falls back to the default and says so in a
    warning, so an operator is never left tuning against a number that is not
    in effect.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        log.warning("%s=%r is not a number - using the default %d",
                    name, raw, default)
        return default


LATE_TIMER_MAX_MS = _tunable("SEKUSCAN_LATE_TIMER_MAX_MS", 1500)
LATE_TIMER_BUDGET_MS = _tunable("SEKUSCAN_LATE_TIMER_BUDGET_MS", 1200)
# Never wait longer than the slow path would have, so the fast path can
# never be the slower one: networkidle's own timeout (3000) plus its floor.
# Overridable for the same reason as the two timer ceilings, and it has to
# move with them: it is the hard clamp on the whole fast wait, so raising
# `LATE_TIMER_MAX_MS` while this stays lower would count the timer but still
# cut the wait off before it fires.
FAST_MAX_MS = _tunable("SEKUSCAN_FAST_MAX_MS", 3000)

# How many navigations to an origin are settled both ways before trusting
# the fast path, and how often to re-check afterward. The calibration cost is
# paid once per origin, while a scan makes many navigations to the same
# origin, so calibration is negligible and the re-check is a small overhead.
CALIBRATION_SAMPLES = 2
REVALIDATE_EVERY = 25

# Origin -> state. Process-global: one agent process is one run.
_FAST: dict[str, bool] = {}          # origin -> fast path proven safe
_AGREEMENTS: dict[str, int] = {}     # origin -> consecutive agreeing samples
_SEEN: dict[str, int] = {}           # origin -> navigations settled

# Counts in-flight fetch/XHR so the page can answer "is the network quiet"
# itself, rather than us waiting Playwright's fixed 500ms to infer it.
# Installed via `context.add_init_script`, so it runs before any page script
# on every navigation (see `browser.py`). Deliberately additive and
# defensive: a page that replaces `fetch` itself still works, it just stops
# being counted, and the DOM-quiescence half still applies.
INFLIGHT_SCRIPT = """
(() => {
  if (window.__sksInflight !== undefined) return;
  window.__sksInflight = 0;
  // Pending one-shot timers, for the same reason as in-flight requests: the
  // page has told us it is not finished. `setInterval` is deliberately left
  // alone - see LATE_TIMER_MAX_MS.
  window.__sksTimers = 0;
  window.__sksCounted = {};
  // Kept in step with `LATE_TIMER_MAX_MS` rather than repeating the number:
  // the in-page counter and the waiter have to agree on which timers
  // count.
  window.__sksTimerMax = __SKS_TIMER_MAX__;
  const ot = window.setTimeout;
  if (ot) {
    window.setTimeout = function (fn, delay) {
      const ms = Number(delay) || 0;
      if (typeof fn !== 'function' || ms > window.__sksTimerMax) {
        return ot.apply(this, arguments);
      }
      window.__sksTimers++;
      const args = Array.prototype.slice.call(arguments, 2);
      const wrapped = function () {
        window.__sksTimers = Math.max(0, window.__sksTimers - 1);
        return fn.apply(this, args);
      };
      const id = ot.call(this, wrapped, ms);
      window.__sksCounted[id] = 1;
      return id;
    };
  }
  /* `clearTimeout` is wrapped too. A cancelled timer never runs its wrapper,
     so without this its count would never be decremented and the page would
     look permanently busy. Debounce and throttle patterns cancel far more
     timers than they fire.

     `__sksCounted` remembers which ids this wrapper incremented for, so
     clearing a timer we did not count, or clearing one twice, cannot drive
     the counter negative. */
  const oc = window.clearTimeout;
  if (oc) {
    window.clearTimeout = function (id) {
      if (window.__sksCounted && window.__sksCounted[id]) {
        delete window.__sksCounted[id];
        window.__sksTimers = Math.max(0, window.__sksTimers - 1);
      }
      return oc.apply(this, arguments);
    };
  }
  const of = window.fetch;
  if (of) {
    window.fetch = function () {
      window.__sksInflight++;
      let p;
      try { p = of.apply(this, arguments); }
      catch (e) { window.__sksInflight--; throw e; }
      return p.finally(() => { window.__sksInflight--; });
    };
  }
  const X = window.XMLHttpRequest;
  if (X && X.prototype && X.prototype.send) {
    const send = X.prototype.send;
    X.prototype.send = function () {
      window.__sksInflight++;
      let done = false;
      const drop = () => { if (!done) { done = true; window.__sksInflight--; } };
      this.addEventListener('loadend', drop);
      try { return send.apply(this, arguments); }
      catch (e) { drop(); throw e; }
    };
  }
})();
"""

INFLIGHT_SCRIPT = INFLIGHT_SCRIPT.replace(
    "__SKS_TIMER_MAX__", str(LATE_TIMER_MAX_MS))


# Resolves as soon as the page is genuinely done, or at `max` - whichever
# comes first. Returns how long it waited, for the debug log.
_SETTLE_SCRIPT = """
(cfg) => new Promise(resolve => {
  const start = Date.now();
  let lastMutation = Date.now();
  let lastBusy = Date.now();
  const timerDeadline = start + (cfg.timerBudget || 0);
  let observer = null;
  try {
    observer = new MutationObserver(() => { lastMutation = Date.now(); });
    observer.observe(document, {childList: true, subtree: true,
                                attributes: true, characterData: true});
  } catch (e) { /* no document yet: the timeouts below still bound us */ }
  const stop = (ms) => {
    if (observer) { try { observer.disconnect(); } catch (e) {} }
    resolve(ms);
  };
  const tick = () => {
    const now = Date.now();
    if ((window.__sksInflight || 0) > 0) lastBusy = now;
    // A pending one-shot timer keeps the page busy, but only while the
    // separate timer budget lasts - a chain of them must not hold the
    // navigation open, and the quiescence rules still have to be met after.
    if ((window.__sksTimers || 0) > 0 && now < timerDeadline) lastBusy = now;
    if (document.readyState === 'complete'
        && now - lastBusy >= cfg.net
        && now - lastMutation >= cfg.dom) { stop(now - start); return; }
    if (now - start >= cfg.max) { stop(now - start); return; }
    setTimeout(tick, 15);
  };
  tick();
})
"""

# Cheap structural fingerprint: the shape of the page that the crawler would
# consume. Deliberately not the full html: this runs on every calibration
# navigation and must stay a few milliseconds.
_FINGERPRINT_SCRIPT = """
() => {
  const n = (sel) => document.querySelectorAll(sel).length;
  return [n('a[href]'), n('form'), n('input'), n('button'),
          n('select'), n('textarea'), n('[onclick]'),
          (document.body ? document.body.innerText.length : 0)].join(':');
}
"""


def origin_of(url: Optional[str]) -> str:
    # Anything that is not a real url string (a page mid-navigation, a
    # duck-typed page in a test, `None`) has no origin to key learned state
    # on, and `mode_for("")` routes it to the slow path. Checked rather than
    # assumed: `urlparse` raises `TypeError` on a non-string, and a settle
    # helper must never be the thing that ends a run.
    if not isinstance(url, str) or not url:
        return ""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}".lower()
    except (ValueError, TypeError):
        return ""


def reset() -> None:
    """Drop everything learned: for tests, and any caller that reuses one
    process for more than one run."""
    _FAST.clear()
    _AGREEMENTS.clear()
    _SEEN.clear()


def mode_for(origin: str) -> str:
    """`fast`, `slow`, or `calibrate` - what this origin has earned."""
    if not origin:
        return "slow"
    if _FAST.get(origin) is False:
        return "slow"
    if _FAST.get(origin) is True:
        # Even a proven origin is re-checked periodically: a site whose
        # first pages are server-rendered and whose later sections are
        # script-rendered is an ordinary shape.
        seen = _SEEN.get(origin, 0)
        if REVALIDATE_EVERY > 0 and seen % REVALIDATE_EVERY == 0:
            return "calibrate"
        return "fast"
    return "calibrate"


def note_navigation(origin: str) -> None:
    if origin:
        _SEEN[origin] = _SEEN.get(origin, 0) + 1


def record(origin: str, agreed: bool) -> None:
    """One calibration result. Disagreement is permanent for the run;
    agreement has to happen `CALIBRATION_SAMPLES` times in a row."""
    if not origin:
        return
    if not agreed:
        if _FAST.get(origin) is not False:
            log.info("settle: %s needs the full wait (fast settle would have "
                     "collected a different DOM)", origin)
        _FAST[origin] = False
        _AGREEMENTS[origin] = 0
        return
    _AGREEMENTS[origin] = _AGREEMENTS.get(origin, 0) + 1
    if _AGREEMENTS[origin] >= CALIBRATION_SAMPLES and _FAST.get(origin) is None:
        log.info("settle: %s settles fast (%d/%d samples agreed)", origin,
                 _AGREEMENTS[origin], CALIBRATION_SAMPLES)
        _FAST[origin] = True


#: How long "do timers run in this document?" may take to answer. A live page
#: answers within one task; a dead one never does.
TIMER_PROBE_MS = 300
_TIMER_ARM = """() => {
  if (window.__sksTimersOk !== true) {
    setTimeout(() => { window.__sksTimersOk = true; }, 0);
  }
  return window.__sksTimersOk === true;
}"""
_TIMER_FIRED = "() => window.__sksTimersOk === true"


def timers_run(page: Any) -> bool:
    """Whether `setTimeout` callbacks fire in the current document.

    In a document served with a CSP `sandbox` lacking `allow-scripts`,
    Chromium never runs a timer or animation-frame callback, not even one
    scheduled by code we inject. Every awaited script that resolves from a
    timer (`_SETTLE_SCRIPT`, `_script_load`) would then never resolve, and the
    sync `page.evaluate` has no timeout, so the navigation would only end at
    the browser watchdog.

    Asked through `wait_for_function`, whose timeout Playwright enforces
    itself rather than via a timer in the page. Anything else that stops the
    question being asked (a page mid-navigation) answers True, so the
    caller's own fallbacks behave as usual.
    """
    try:
        if page.evaluate(_TIMER_ARM):
            return True
        page.wait_for_function(_TIMER_FIRED, timeout=TIMER_PROBE_MS,
                               polling=10)
        return True
    except _INTERACTION_TIMEOUT_EXCS:
        return False
    except Exception as exc:
        log.debug("settle: timer probe unavailable (%s)", type(exc).__name__)
        return True


def fast_settle(page: Any) -> Optional[float]:
    """Wait for the page's own definition of done. `None` means it could not
    be asked (a destroyed execution context, a page mid-navigation, an
    evaluate that threw) - the caller must fall back to the slow path."""
    try:
        started = time.monotonic()
        page.evaluate(_SETTLE_SCRIPT,
                      {"net": NET_QUIET_MS, "dom": DOM_QUIET_MS,
                       "max": FAST_MAX_MS,
                       "timerBudget": LATE_TIMER_BUDGET_MS})
        return (time.monotonic() - started) * 1000.0
    except Exception as exc:
        log.debug("settle: fast path unavailable (%s), using the full wait",
                  type(exc).__name__)
        return None


# -- the interaction case --------------------------------------------------
#
# A form submission or a click is where a settle must not measure "quiet" too
# early. The reason is a race rather than a slow page: the browser has not
# necessarily started the work when the click returns, so the old document is
# still there, complete and idle, and asking it whether it is done truthfully
# says yes about the wrong document.
#
# So the submission is observed before waiting for it to finish. One round
# trip answers all three ways it can show up (the document was replaced, the
# document is loading, or a fetch/XHR is in flight), and a token planted
# before the click distinguishes "a new document" from "the same one, still
# idle".
#
# Bounded at every end. `SUBMIT_MAX_MS` is the upper bound on the wait, equal to the
# flat sleep used otherwise. `INTERACTION_START_GRACE_MS` is how long a
# submission gets to appear at all; past that, nothing observable happened
# and there is nothing to wait for. And it only runs on an origin that has
# already earned `fast` through navigation calibration. An origin that needs
# the full wait for navigation keeps the flat sleep here too.
# The cap is supplied by each call site and is that site's own flat-sleep
# cost, so the adaptive wait is never slower.
SUBMIT_MAX_MS = 550
INTERACTION_START_GRACE_MS = 250
_INTERACTION_POLL_MS = 20

_INTERACTION_MARK_SCRIPT = "(t) => { window.__sksInteractionDoc = t; }"

# Every way a submission announces itself, in one round trip, as a predicate
# (`wait_for_function` polls it itself and does not want a value read back):
# true once any of the three has fired.
_INTERACTION_OBSERVE_PREDICATE = """
(token) => (
  window.__sksInteractionDoc !== token
  || document.readyState !== 'complete'
  || (window.__sksInflight || 0) > 0
)
"""


def mark_before_interaction(page: Any) -> Optional[str]:
    """Plant a token identifying the CURRENT document. `None` if it could not
    be planted, which means the caller must keep the fixed wait - without the
    token a replaced document is indistinguishable from an idle one."""
    token = "sks-%d" % time.monotonic_ns()
    try:
        page.evaluate(_INTERACTION_MARK_SCRIPT, token)
        return token
    except Exception as exc:
        log.debug("settle: could not mark the document before the "
                  "interaction (%s)",
                  type(exc).__name__)
        return None


def settle_after_interaction(page: Any, token: str,
                             cap_ms: int = SUBMIT_MAX_MS) -> Optional[float]:
    """Wait for an interaction to be observed and then to finish.

    `None` means this could not be measured and the caller must fall back to
    the fixed wait. Returning early having seen nothing is NOT reported as a
    failure: a submission that produced no navigation, no request and no
    re-render has nothing left to wait for.
    """
    started = time.monotonic()
    deadline = started + cap_ms / 1000.0
    # A click's whole budget is smaller than the default grace, so the grace
    # can never outlast the cap it is bounded by.
    grace_ms = min(INTERACTION_START_GRACE_MS, cap_ms)
    observed = False
    try:
        # Bounded even if the page is stuck mid-navigation: this is a real
        # CDP timer, not a Python-side one, so it fires regardless of what the
        # greenlet is blocked on.
        page.wait_for_function(_INTERACTION_OBSERVE_PREDICATE, arg=token,
                               timeout=max(1, grace_ms),
                               polling=_INTERACTION_POLL_MS)
        observed = True
    except _INTERACTION_TIMEOUT_EXCS:
        # Nothing observable happened within the grace window.
        observed = False
    except Exception:
        # The execution context went away underneath us (or the page never
        # had one to evaluate against), which IS the observation: the
        # document is being replaced.
        observed = True

    remaining_ms = (deadline - time.monotonic()) * 1000.0
    if remaining_ms <= 0:
        return (time.monotonic() - started) * 1000.0
    stuck = False
    if observed:
        # A replaced document has to reach domcontentloaded before its own
        # quiet means anything. Returns immediately when nothing is pending.
        try:
            page.wait_for_load_state("domcontentloaded",
                                     timeout=max(1.0, remaining_ms))
        except Exception:
            # The page never reached a stable load state: the interaction
            # started a navigation the server has not answered (for example a
            # form POST to an endpoint that hangs). The document is stuck
            # "loading", so the `page.evaluate` below would block forever
            # waiting for an execution context that never arrives; evaluate
            # has no timeout in Playwright's Python API. `wait_for_load_state`
            # above is bounded and tells us the page is stuck, so do not
            # evaluate it. The next directive's bounded `goto` recovers the
            # page.
            stuck = True
        remaining_ms = (deadline - time.monotonic()) * 1000.0
    if not stuck and remaining_ms > 0:
        try:
            page.evaluate(_SETTLE_SCRIPT,
                          {"net": NET_QUIET_MS, "dom": DOM_QUIET_MS,
                           "max": max(1.0, remaining_ms),
                           # the interaction settle is already capped by its
                           # own call site; do not add a second budget on top
                           "timerBudget": 0})
        except Exception as exc:
            log.debug("settle: interaction quiet wait unavailable (%s)",
                      type(exc).__name__)
            return None
    return (time.monotonic() - started) * 1000.0


#: How long a click may wait for requests IT STARTED to finish.
#:
#: A click's settle is a flat DOM window with `wait_network_idle=False`: a
#: live single-page application has no useful network-idle point, so waiting
#: for one would turn a bounded exploration into a very long one.
#:
#: That leaves a correctness gap. A click that starts a `fetch()` produces a
#: real request, and if the step's capture drains before the response arrives,
#: the request is absent from the traffic record.
#:
#: So this waits, and only for what the click itself started. It returns
#: immediately when nothing is in flight, which is the great majority of
#: clicks, so the speed argument above is preserved.
CLICK_INFLIGHT_MAX_MS = 900

_INFLIGHT_ONLY_SCRIPT = """
() => ((window.__sksInflight || 0) > 0)
"""


def drain_click_requests(page: Any,
                         cap_ms: int = CLICK_INFLIGHT_MAX_MS) -> float:
    """Wait for requests the click started, and for nothing else.

    Returns the milliseconds spent, which is 0 when the page reports nothing
    in flight. Never raises: a page that replaced `fetch` itself stops being
    counted and this returns immediately, which is the same
    already-documented degradation `INFLIGHT_SCRIPT` accepts.

    Deliberately not a general network-idle wait. It asks one question, "is
    something the page started still outstanding", so a WebSocket, an
    analytics stream or a long-poll cannot hold it: those are not counted by
    `INFLIGHT_SCRIPT` as one-shot in-flight requests any longer than their
    own turnaround.
    """
    started = time.monotonic()
    deadline = started + max(0, cap_ms) / 1000.0
    while True:
        try:
            busy = bool(page.evaluate(_INFLIGHT_ONLY_SCRIPT))
        except Exception:
            break
        if not busy:
            break
        if time.monotonic() >= deadline:
            log.debug("settle: click still had requests in flight after %dms",
                      cap_ms)
            break
        time.sleep(_INTERACTION_POLL_MS / 1000.0)
    return (time.monotonic() - started) * 1000.0


def fingerprint(page: Any) -> Optional[str]:
    try:
        return str(page.evaluate(_FINGERPRINT_SCRIPT))
    except Exception:
        return None
