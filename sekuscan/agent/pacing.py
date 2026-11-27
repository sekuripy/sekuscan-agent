# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""A proactive per-host request ceiling for the scan's own traffic.

`execute.py` already backs off after a host answers 429/503. This module is
the proactive half: an engagement's rules typically say "do not exceed N
requests per second against this host", agreed before the scan starts and
honoured whether or not the target ever complains. Many production targets
never answer 429; they just slow down or drop connections, so a limiter that
only reacts to a status code cannot honour an agreed number.

Deliberately per HOST, not per run: a scan spanning an app origin and its
API origin is two servers, and a global cap would throttle both to the rate
agreed for one.

Off by default (`max_rps=0`): a run that sets no ceiling pays nothing - no
sleep, no lock contention, no clock read.

The allocator hands out FUTURE SLOTS rather than sleeping itself: a caller
asks what time it may go, and does its own waiting. That is what lets one
implementation serve both transports - `execute.py` blocks on
`time.sleep()`, `async_probe.py` yields on `await asyncio.sleep()` - without
either needing to know about the other.
"""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_max_rps: float = 0.0
#: host -> the monotonic time the next request to it may start.
_next_slot: dict[str, float] = {}


def configure(max_rps: float) -> None:
    """Set the ceiling. 0 (or less) disables pacing entirely."""
    global _max_rps
    with _lock:
        _max_rps = max(0.0, float(max_rps or 0.0))
        _next_slot.clear()


def enabled() -> bool:
    return _max_rps > 0.0


def host_key(url: str) -> str:
    """`host:port` for `url`, the unit the ceiling counts in: userinfo
    dropped, lower case, the scheme's default port filled in. Never raises."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        port = parsed.port or {"http": 80, "https": 443, "ws": 80,
                               "wss": 443}.get(parsed.scheme.lower())
    except ValueError:
        return ""
    if not host:
        return ""
    return "%s:%s" % (host, port) if port else host


def claim(host: str) -> float:
    """Reserve this host's next slot; return the seconds to wait for it.

    Atomic under the lock, so two threads never reserve the same instant -
    the sync probe path and the async batch worker are genuinely concurrent,
    and a check-then-sleep would let a whole batch through at once, which is
    exactly the burst a ceiling exists to prevent.
    """
    if _max_rps <= 0.0:
        return 0.0
    interval = 1.0 / _max_rps
    now = time.monotonic()
    with _lock:
        # Re-read inside the lock: `configure` may have raced us.
        if _max_rps <= 0.0:
            return 0.0
        earliest = _next_slot.get(host, 0.0)
        start = now if earliest < now else earliest
        _next_slot[host] = start + interval
    return max(0.0, start - now)
