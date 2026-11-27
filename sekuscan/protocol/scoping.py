# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""The canonical scope decision, shared by engine and agent.

Both sides call this one implementation. Two implementations of a safety
control can disagree: the engine could plan a request the agent then refused
(costing coverage), or the agent could allow something the engine believed was
out of scope (costing containment). Disagreements to guard against:

  * **Path boundary.** A plain `path.startswith(origin_path)` would let an
    origin of `https://host/app` match `/apple`, `/app-admin` and
    `/application`. A boundary has to fall on a path segment.
  * **Scheme.** An `https://` scope must not accept `http://`, which is
    precisely the downgrade a scope restriction is supposed to prevent.

It lives in `protocol/` rather than in either side because scope is part of the
contract between them, not a policy either one owns.

The rule, in order:

    1. the scheme must be http, https, ws or wss (ws/wss judged as their
       http/https equivalent - see `WS_SCHEME_EQUIV`), and must match the
       origin's when the origin declared one;
    2. no deny substring may appear anywhere in the url;
    3. the host must equal the origin's host, or be a subdomain of it when
       subdomains are allowed;
    4. the port must match, defaults resolved (80/443) on both sides;
    5. the origin's path must be a segment-boundary prefix of the url's path;
    6. when a depth is declared, the url may not exceed that many path segments
       below the origin.

Anything not explicitly allowed is denied.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, NamedTuple, Optional
from urllib.parse import unquote, urlparse, urlunparse

WEB_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}
# A websocket connection is opened over the same origin, the same cookie jar
# and the same trust boundary as the page that requested it: `ws`/`wss` are
# `http`/`https` upgraded in place, on the same default ports. Treating them
# as their http(s) equivalent means every other rule in this file (path
# boundary, host, port, depth and no silent scheme downgrade) covers a
# websocket request without a separate copy.
WS_SCHEME_EQUIV = {"ws": "http", "wss": "https"}


class Origin(NamedTuple):
    scheme: Optional[str]   # None when the operator wrote a bare host
    host: str
    port: Optional[int]     # None when the origin named no port
    path: str               # normalised, no trailing slash, "" for root


@dataclass
class Decision:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


# The operator's origins do not change during a run, so parsing them once and
# caching the result avoids repeating the work on every scope decision.
@lru_cache(maxsize=1024)
def parse_origin(origin: str) -> Optional[Origin]:
    """`example.test`, `https://example.test:8443/app/` -> an Origin.

    A bare host keeps `scheme=None`, which means "either scheme is acceptable":
    the operator did not express a preference, so inventing one would silently
    narrow their scope.
    """
    if not origin or not str(origin).strip():
        return None
    raw = str(origin).strip()
    declared = "//" in raw
    parsed = urlparse(raw if declared else "//" + raw, scheme="")
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    scheme = (parsed.scheme or "").lower() or None
    # An operator may paste a `wss://...` url from browser developer tools.
    # Judge it as its http(s) equivalent rather than rejecting a spelling that
    # `decide()` already treats as interchangeable on the URL side.
    if scheme:
        scheme = WS_SCHEME_EQUIV.get(scheme, scheme)
    if scheme and scheme not in WEB_SCHEMES:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None and scheme:
        port = DEFAULT_PORTS[scheme]
    # A bare host names neither scheme nor port, so it keeps both open and
    # means "this host on its default port, either scheme". Defaulting to 80
    # here would wrongly refuse every https url under a bare-host scope.
    return Origin(scheme, host, port, _norm_path(parsed.path))


_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._~"
)
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")


def _decode_unreserved(value: str) -> str:
    """Decode only percent-escapes of RFC 3986 unreserved characters.

    `%2F` must stay `%2F`: decoding it into a literal `/` would change how
    many path segments the url has, which is exactly the boundary this
    function exists to protect. Only an escape that decodes to a character a
    url could have spelled literally anyway (a letter, digit, `-._~`) is
    folded. That includes `%2e` -> `.`, which lets an encoded `..` reach
    `_resolve_dot_segments` below: the scope check must resolve the path the
    way the real request will.
    """
    def repl(m: "re.Match[str]") -> str:
        char = chr(int(m.group(1), 16))
        return char if char in _UNRESERVED else m.group(0).upper()
    return _PERCENT_ESCAPE.sub(repl, value)


def _resolve_dot_segments(path: str) -> str:
    """RFC 3986 5.2.4, applied to an absolute path."""
    parts: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return "/" + "/".join(parts)


def _norm_path(path: Optional[str]) -> str:
    """`/app/` -> `/app`, `/` and `` -> `` (meaning: no path restriction).

    A literal string operation (collapse repeated `/`, strip a trailing `/`)
    is not enough: `https://host/app/../admin` and
    `https://host/app/%2e%2e/admin` would both compare as "still under /app"
    even though the transport that sends the request resolves either one to
    `/admin`. So percent-escapes of unreserved characters are decoded and
    dot-segments are resolved first.
    """
    value = _resolve_dot_segments(_decode_unreserved((path or "").strip()))
    while "//" in value:
        value = value.replace("//", "/")
    value = value.rstrip("/")
    return value if value not in ("", "/") else ""


_ENCODED_SEP = re.compile(r"%(?:2F|5C)", re.IGNORECASE)


def _norm_paths(path: Optional[str]) -> tuple[str, ...]:
    """Every path a real backend could resolve this one to, normalised.

    `_decode_unreserved` leaves `%2F` encoded because decoding it would change
    the segment count. But an encoded separator also keeps a `..` inside one
    segment, where `_resolve_dot_segments` cannot see it, so under a `/app`
    scope:

        /app/%2e%2e/admin       denied     (the dots are their own segment)
        /app/%2e%2e%2Fadmin     ALLOWED    (the dots hide in one segment)

    Some servers (for example Tomcat with `ALLOW_ENCODED_SLASH`, Apache with
    `AllowEncodedSlashes`) and anything behind a proxy that normalises before
    forwarding route the second one as `/app/../admin` -> `/admin`. `%5C` is
    the same on servers that take a backslash as a separator.

    The backend is unknown, so both readings are considered and scope has to
    be satisfied by both before a request is approved. A path with no encoded
    separator yields exactly one form and costs nothing extra.
    """
    raw = (path or "").strip()
    forms = [_norm_path(raw)]
    if _ENCODED_SEP.search(raw):
        decoded = _norm_path(_ENCODED_SEP.sub("/", raw))
        if decoded not in forms:
            forms.append(decoded)
    return tuple(forms)


def _host_matches(host: str, origin: Origin, allow_subdomains: bool) -> bool:
    if host == origin.host:
        return True
    # `evil-example.test` must not match `example.test`: the boundary is the
    # dot, not the suffix
    return allow_subdomains and host.endswith("." + origin.host)


def _path_within(path: str, origin_path: str) -> bool:
    """Segment-boundary containment, which `startswith` is not.

    `/app` contains `/app` and `/app/x`. It does not contain `/apple`.
    """
    if not origin_path:
        return True
    return all(
        target == origin_path or target.startswith(origin_path + "/")
        for target in _norm_paths(path)
    )


def _relative_depth(path: str, origin_path: str) -> int:
    """Number of path segments below an already-matched origin path.

    The deepest reading wins, for the same reason `_path_within` needs every
    reading to hold: a backend that decodes `%2F` sees more segments than one
    that does not, and a depth limit that trusts the shallower count is not a
    limit on that backend.
    """
    return max(_depth_of(target, origin_path) for target in _norm_paths(path))


def _depth_of(target: str, origin_path: str) -> int:
    if origin_path and target.startswith(origin_path):
        remainder = target[len(origin_path):].strip("/")
    else:
        remainder = target.strip("/")
    return len([part for part in remainder.split("/") if part])


def decide(url: Optional[str], origins: Iterable[str],
           deny_substrings: Iterable[str] = (),
           allow_subdomains: bool = False,
           max_depth: Optional[int] = None) -> Decision:
    """The one scope decision. Both sides call this and nothing else.

    Memoised: the same URL is typically asked about many times in a run, and
    the answer cannot change while the scope is fixed.

    The verdict is cached, not the `Decision`: that is a plain mutable
    dataclass, and handing the same instance to every caller would let one
    caller's mutation affect every other.

    The cache key carries the scope, so two runs with different scopes do not
    share an answer.
    """
    return Decision(*_decide_verdict(
        url or "", tuple(origins or ()), tuple(deny_substrings or ()),
        bool(allow_subdomains),
        None if max_depth is None else int(max_depth)))


@lru_cache(maxsize=16384)
def _decide_verdict(url: str, origins: tuple, deny_substrings: tuple,
                    allow_subdomains: bool,
                    max_depth: Optional[int]) -> tuple:
    decision = _decide_uncached(url, origins, deny_substrings,
                                allow_subdomains, max_depth)
    return (decision.allowed, decision.reason)


def _decide_uncached(url: Optional[str], origins: Iterable[str],
                     deny_substrings: Iterable[str] = (),
                     allow_subdomains: bool = False,
                     max_depth: Optional[int] = None) -> Decision:
    if not url:
        return Decision(False, "empty url")
    try:
        parsed = urlparse(url)
    except ValueError:
        return Decision(False, "unparseable url")
    scheme = (parsed.scheme or "").lower()
    effective_scheme = WS_SCHEME_EQUIV.get(scheme, scheme)
    if effective_scheme not in WEB_SCHEMES:
        return Decision(False, "scheme not allowed: %s" % (scheme or "?"))
    # Parser differential: WHATWG (Chromium) treats a raw backslash as '/'
    # in http(s) URLs and silently drops tab/CR/LF, urlparse does neither.
    # "http://attacker.example\\@example.test/x" has host example.test here but the
    # browser connects to attacker.example; "/app/..\\admin" resolves to /admin
    # there but stays under /app here. Real URLs carry these percent-encoded,
    # so refuse the raw form rather than guess which parser is right.
    if any(c in url for c in "\\\t\r\n"):
        return Decision(False, "backslash/control char in url")

    # Checked against the raw url AND against it percent-decoded (once and
    # twice, to catch double-encoding): a deny rule for "logout" must not be
    # dodgeable by spelling it "%6cogout" in the url the checker sees while
    # the literal request still reads "logout" on the wire.
    #
    # Both short-circuits below are exact, not approximations. `unquote` can
    # only change a string that contains a percent sign, so for an ordinary
    # URL the decoded views are the original and building them is wasted
    # work; and with no deny rules configured the views are never consulted.
    if deny_substrings:
        low = url.lower()
        deny_views = ({low, unquote(low), unquote(unquote(low))}
                      if "%" in low else (low,))
        for deny in deny_substrings:
            needle = str(deny).lower() if deny else ""
            if needle and any(needle in view for view in deny_views):
                return Decision(False, "deny pattern matched: %s" % deny)

    try:
        host = (parsed.hostname or "").lower()
        port = parsed.port or DEFAULT_PORTS[effective_scheme]
    except ValueError:
        return Decision(False, "malformed authority")
    if not host:
        return Decision(False, "no host")

    for raw in origins or ():
        origin = parse_origin(raw)
        if origin is None:
            continue
        # `origin.scheme` is always plain http/https or None (`parse_origin`
        # rejects anything else). Compare against the effective scheme, not
        # the literal one, so a `wss://` request is judged against an
        # `https://`-scoped origin exactly as a plain `https://` request
        # would be, and a `ws://` request never slips through on an
        # `https://`-only scope.
        if origin.scheme and origin.scheme != effective_scheme:
            continue
        if not _host_matches(host, origin, allow_subdomains):
            continue
        if origin.port is None:
            # no port declared: the url must be on the default port for its
            # own scheme, so an explicit `:8443` still needs naming
            if port != DEFAULT_PORTS[effective_scheme]:
                continue
        elif port != origin.port:
            continue
        if not _path_within(parsed.path, origin.path):
            continue
        if max_depth is not None and _relative_depth(parsed.path, origin.path) > max(0, int(max_depth)):
            continue
        return Decision(True)
    return Decision(False, "outside scope: %s" % _describe(scheme, host, port,
                                                           parsed.path))


def _describe(scheme: str, host: str, port: int, path: str) -> str:
    default_port = DEFAULT_PORTS.get(WS_SCHEME_EQUIV.get(scheme, scheme))
    netloc = host if port == default_port else "%s:%d" % (host, port)
    return urlunparse((scheme, netloc, path or "/", "", "", ""))


def origin_reachable(host: str, port: int, scheme: str,
                     origins: Iterable[str],
                     allow_subdomains: bool = False) -> bool:
    """Host/port/scheme reachability: a decision with no path or depth to
    judge, for a caller that has neither.

    A CONNECT tunnel names only `host:port`; the scheme and path travel inside
    it, usually in TLS the relay does not terminate. This
    reuses `parse_origin`/`_host_matches` and the port-default rule of
    `decide()`, and deliberately stops there: `_path_within` and
    `_relative_depth` are skipped because there is no path for either to judge.
    `agent.scope.ScopeGuard.check(url)` still enforces both on every URL the
    agent actually sees once the tunnel is open; this is host-level containment
    for the one hop that precedes it, not a replacement for it.

    Do NOT call `decide("/", ...)` for this. `decide()` normalises a missing
    path to the origin's own root, so under a path-scoped origin
    (`https://host/app`) a bare `/` reads as out of scope and every CONNECT to
    that host would be wrongly refused.
    """
    scheme = (scheme or "").lower()
    effective_scheme = WS_SCHEME_EQUIV.get(scheme, scheme)
    if effective_scheme not in WEB_SCHEMES:
        return False
    host = (host or "").lower()
    if not host:
        return False
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    for raw in origins or ():
        origin = parse_origin(raw)
        if origin is None:
            continue
        if origin.scheme and origin.scheme != effective_scheme:
            continue
        if not _host_matches(host, origin, allow_subdomains):
            continue
        if origin.port is None:
            if port != DEFAULT_PORTS[effective_scheme]:
                continue
        elif port != origin.port:
            continue
        return True
    return False
