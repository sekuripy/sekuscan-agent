# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Turning response bytes into text, correctly for old sites as well as new.

Split out of `execute.py` so `browser.py` can use it too: `execute` imports
`browser`, so the dependency has to point this way or it is a cycle.
"""

from __future__ import annotations

import re
from typing import Optional

# A charset name we are willing to hand to `bytes.decode`. Deliberately narrow:
# this string comes from the target, and an unbounded one would be passed
# straight into the codec registry.
_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9._-]{1,40})", re.I)


def _charset_of(headers: dict[str, str]) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == "content-type":
            found = _CHARSET_RE.search(str(value or ""))
            return found.group(1).lower() if found else ""
    return ""


def decode_body(raw: bytes, headers: Optional[dict[str, str]] = None) -> str:
    """Decode a response body using the charset the server declared.

    Decoding everything as UTF-8 with `errors="replace"` is wrong for pages
    served as `windows-1252`, `ISO-8859-1`, `Shift_JIS`, `GBK` or
    `windows-1251`: every non-ASCII byte becomes U+FFFD, which changes the
    text and its length.

    Falls back to UTF-8 on anything unusable: an unknown codec name, a bogus
    one, or a declared charset the bytes do not actually honour. A target
    declaring `charset=nonsense` must not be able to make this raise.
    """
    if not raw:
        return ""
    declared = _charset_of(headers or {})
    if declared and declared not in ("utf-8", "utf8"):
        try:
            return raw.decode(declared, "replace")
        except (LookupError, UnicodeError, TypeError, ValueError):
            pass                       # unusable label: fall through to UTF-8
    return raw.decode("utf-8", "replace")


#: Content types that do not END. A response with one of these is a stream,
#: not a document: `text/event-stream` stays open by design, and
#: `multipart/x-mixed-replace` is the old push idiom that does the same.
#:
#: The size ceiling is checked against a DECLARED `Content-Length`, so a
#: chunked or unknown-length response skips it and `response.body()` would
#: buffer until EOF - which a stream never reaches. Skipping these bodies
#: removes the case that hangs rather than merely allocates. Unknown-length
#: responses in general are not bounded, because Playwright's buffered API
#: cannot stop a read already in progress.
STREAMING_CONTENT_TYPES = ("text/event-stream", "multipart/x-mixed-replace")


def is_streaming_body(headers: dict) -> bool:
    """True when this response is a stream that will not end on its own."""
    value = ""
    for name, raw in (headers or {}).items():
        if str(name).lower() == "content-type":
            value = str(raw).lower()
            break
    return any(kind in value for kind in STREAMING_CONTENT_TYPES)
