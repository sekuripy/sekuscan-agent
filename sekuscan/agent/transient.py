# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Which probe transport failures are worth one more try, and when.

A reset keep-alive socket or a host that refuses one connection mid-restart
would otherwise cost a probe its answer outright. A bounded retry recovers it.

The split is by what the target may have SEEN, read from the Node error text
Playwright surfaces:

* never delivered - the connection or TLS handshake itself failed. Safe to
  repeat for any method, a POST included, because no request reached the app.
* maybe delivered - the socket died after the request was written. Repeated
  only for idempotent methods: a reset POST may already have run, and sending
  it again would double its effect.

Not retried at all: a timeout (the 12 s default would become 36 s against a
dead host, and a directive's own deadline would be exceeded) and a name
that does not resolve (permanent, not transient).

Pure functions, no state, shared by both probe transports (`execute.py` and
`async_probe.py`).
"""

from __future__ import annotations

from typing import Optional

#: Seconds to wait before retry 1, 2, ... - also the retry count.
RETRY_DELAYS_S = (0.5, 1.5)

_NEVER_DELIVERED = ("ECONNREFUSED", "EAI_AGAIN", "connect ETIMEDOUT",
                    "EHOSTUNREACH", "ENETUNREACH",
                    "before secure TLS connection was established")
_MAYBE_DELIVERED = ("ECONNRESET", "socket hang up", "EPIPE")
_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})


def retry_delay(exc: BaseException, method: str, attempt: int) -> Optional[float]:
    """Seconds to wait before retrying after failed `attempt` (0-based), or
    None when this failure must stand."""
    if attempt >= len(RETRY_DELAYS_S) or "Timeout" in type(exc).__name__:
        return None
    text = str(exc)
    if any(marker in text for marker in _NEVER_DELIVERED):
        return RETRY_DELAYS_S[attempt]
    if (str(method or "GET").upper() in _IDEMPOTENT
            and any(marker in text for marker in _MAYBE_DELIVERED)):
        return RETRY_DELAYS_S[attempt]
    return None
