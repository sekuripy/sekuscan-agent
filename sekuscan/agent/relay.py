# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""agent/relay - a loopback-only HTTP CONNECT relay.

Chromium's own `--proxy-server` speaks plain http(s)+Basic CONNECT chaining
and unauthenticated SOCKS5 natively. It cannot do SOCKS5 WITH credentials at
all - there is no proxy-authentication step in the SOCKS5 handshake browsers
implement. An enterprise SOCKS5 proxy that requires a login is therefore a
proxy Chromium is simply unable to dial, no matter what `--proxy-server`
value it is handed.

This module is what stands in for it: a tiny local relay, bound to
`127.0.0.1:0`, that Chromium is told is a plain HTTP proxy (which it CAN
speak) and which itself does the SOCKS5-with-auth handshake to the real
upstream. Chromium authenticates to nothing - the relay lives on loopback and
accepts any CONNECT that is in scope - and the credentials never leave this
process or cross into a directive, the same rule that applies to
`--client-cert`/secondary-identity credentials.

Threading: background daemon threads, bounded recv timeouts and an ephemeral
port, not asyncio - one relay serves one run, and the traffic it carries is
already serialised through a single browser tab.

Tunnel-only for the ordinary case: the relay splices the tunnel it opens
without looking inside it. There are two deliberate exceptions: NTLM-to-TARGET
TLS-intercepts, because the browser has no NTLM client to hand the target
itself; and authenticating to a PARENT proxy that challenges with
Digest/NTLM/Negotiate (`_http_connect_chain`) reads that proxy's own 407
before the tunnel exists - it never looks inside the tunnel proper, only at
the CONNECT handshake that precedes it. Per-host routing is out of scope.
The handler only speaks CONNECT, so a plain http:// page navigation routed
at this relay (which Chromium sends as an absolute-form GET) gets a 405.
`APIRequestContext`-driven probes (anonymous/secondary identities,
`_probe_raw_query`) are unaffected: Playwright's request API CONNECT-tunnels
even a plain-http target, so they reach this relay the same way an https
navigation does.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.client
import ipaddress
import logging
import os
import re
import socket
import socketserver
import ssl
import tempfile
import threading
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import spnego
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ..protocol import scoping
from ..protocol.models import ScopeRules

log = logging.getLogger("sekuscan.agent.relay")

RECV_BUFFER = 65536
#: Per-direction inactivity timeout on a spliced tunnel. Generous on purpose
#: - `_splice`'s job is to notice a truly dead peer, not to bound a slow one.
IDLE_TIMEOUT_S = 300.0
#: How long dialing the upstream (direct, HTTP-CONNECT chain, or SOCKS5) may
#: take before this relay gives up and answers the client with a failure.
CONNECT_TIMEOUT_S = 15.0
#: Ceiling on a CONNECT request/response head, client or upstream side alike
#: - both are a handful of header lines in the honest case, and a peer that
#: never sends a blank line must not grow this buffer without bound.
MAX_HEAD_BYTES = 65536


#: `--proxy-auth-scheme` values this relay can answer a parent proxy's own
#: 407 challenge with. "basic" is sent proactively and never waits for a 407 - see `_http_connect_chain`.
PROXY_AUTH_SCHEMES = ("basic", "digest", "ntlm", "negotiate")


@dataclass(frozen=True)
class UpstreamSpec:
    """Where `_dial_upstream` should end up, and how to get there."""

    scheme: str                       # "direct", "http", "https", "socks5"
    host: str = ""
    port: int = 0
    username: Optional[str] = None
    password: Optional[str] = None
    #: How to answer the parent proxy's OWN 407. Only meaningful
    #: for scheme in ("http", "https") - SOCKS5's authentication is the RFC
    #: 1929 sub-negotiation `socks5_connect` already does, an entirely
    #: different wire protocol this field has no bearing on.
    auth_scheme: str = "basic"


def parse_upstream(proxy_server: Optional[str], username: Optional[str] = None,
                   password: Optional[str] = None) -> UpstreamSpec:
    """`--proxy-server` (+ optional `--proxy-username`/`--proxy-password`) ->
    an `UpstreamSpec`.

    Credentials may travel embedded in the url (`socks5://user:pass@host:port`
    - what an operator pastes straight from a proxy provider) or via the
    separate flags; an embedded one wins when both are given, since it is the
    more specific spelling of the two.

    `--proxy-auth-scheme` travels the same way, but riding the URL's SCHEME
    rather than its authority: `agent/cli.py` (the only writer of this shape)
    turns `--proxy-server http://host:port --proxy-auth-scheme digest` into
    the literal string `http+digest://host:port` before handing it to
    `agent/browser.py`, which forwards `proxy_server` to this function as an
    opaque string.
    A compound scheme is ordinary RFC 3986 (`+` is a valid scheme character,
    same trick `postgresql+psycopg2://` uses), so `urlparse` needs no help
    splitting it back apart.
    """
    if not proxy_server:
        return UpstreamSpec(scheme="direct")
    parsed = urlparse(proxy_server)
    raw_scheme = (parsed.scheme or "http").lower()
    scheme, plus, auth_scheme = raw_scheme.partition("+")
    if not plus or auth_scheme not in PROXY_AUTH_SCHEMES:
        auth_scheme = "basic"
    # 1080 is SOCKS5's IANA-registered default (what curl and every other
    # SOCKS5 client assume too) - http(s) has no equivalent single default,
    # so those are left at 0 (meaning "the operator must have said one") for
    # `_dial_upstream` to fail loudly on rather than guess.
    default_port = 1080 if scheme in ("socks5", "socks5h") else 0
    return UpstreamSpec(
        scheme=scheme, host=parsed.hostname or "",
        port=parsed.port or default_port,
        username=parsed.username or username,
        password=parsed.password or password,
        auth_scheme=auth_scheme)


def needs_relay(spec: UpstreamSpec) -> bool:
    """True when Chromium cannot dial this upstream on its own.

    Two shapes: SOCKS5 carrying credentials, and an http(s) parent proxy
    whose auth scheme is anything but Basic - Chromium's own `--proxy-server` speaks CONNECT + preemptive Basic
    and nothing past that; Digest/NTLM/Negotiate to a PARENT proxy have no
    native support to fall back on, the same gap `--target-auth` fills for
    the target itself. Plain http/https (with or without Basic) and
    unauthenticated SOCKS5 are things Chromium's own `--proxy-server`
    already does - see the module docstring - and routing those through a
    relay hop anyway would cost a round trip for nothing.
    """
    if spec.scheme in ("socks5", "socks5h"):
        return bool(spec.username)
    if spec.scheme in ("http", "https"):
        return spec.auth_scheme != "basic" and bool(spec.username)
    return False


# --------------------------------------------------------------------------
# wire helpers shared by both the relay's server side and its raw-lane client
# --------------------------------------------------------------------------

def _read_head(sock: socket.socket, max_bytes: int = MAX_HEAD_BYTES) -> bytes:
    """Read one HTTP request/response head, stopping exactly at the blank
    line that ends it.

    Byte-at-a-time on purpose: whatever comes immediately after that blank
    line is the tunnel's own payload, already sitting on the same socket with
    no framing to hand an over-read back. A buffered read (e.g.
    `makefile().readline()`) would swallow the first bytes of the tunnel
    along with the head and there would be no way to give them back to
    `_splice`.
    """
    data = bytearray()
    while len(data) < max_bytes:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\r\n\r\n"):
            break
    return bytes(data)


def _status_ok(head: bytes) -> bool:
    line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split()
    return len(parts) >= 2 and parts[1] == "200"


def _recvn(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed mid-handshake")
        data += chunk
    return bytes(data)


def _encode_addr(host: str) -> tuple[bytes, bytes]:
    """SOCKS5 ATYP + address body for a CONNECT request.

    An IP literal is sent as ATYP 1/4 (IPv4/IPv6) rather than as a domain
    name - some SOCKS5 servers refuse to resolve a domain-shaped IP string,
    and the address type exists precisely so a client never has to guess.
    """
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna") if not host.isascii() else host.encode("ascii")
        return b"\x03", bytes([len(encoded)]) + encoded
    return (b"\x01", parsed.packed) if parsed.version == 4 else (b"\x04", parsed.packed)


def socks5_connect(sock: socket.socket, host: str, port: int,
                   username: Optional[str] = None,
                   password: Optional[str] = None) -> None:
    """RFC 1928 handshake (+ RFC 1929 sub-negotiation when `username` is
    given) followed by a CONNECT request, all on an already-connected
    `sock`. Raises `ConnectionError` on any non-zero status at any stage;
    returns normally with the socket positioned exactly at the start of the
    tunnelled stream.
    """
    methods = bytes([0x00, 0x02]) if username else bytes([0x00])
    sock.sendall(bytes([0x05, len(methods)]) + methods)
    greeting = _recvn(sock, 2)
    if greeting[0:1] != b"\x05":
        raise ConnectionError("socks5: bad version in method reply")
    method = greeting[1]
    if method == 0x02:
        if not username:
            raise ConnectionError("socks5: server requires auth, none configured")
        user_b, pass_b = username.encode(), (password or "").encode()
        sock.sendall(bytes([0x01, len(user_b)]) + user_b
                    + bytes([len(pass_b)]) + pass_b)
        auth_reply = _recvn(sock, 2)
        if auth_reply[1] != 0x00:
            raise ConnectionError("socks5: authentication failed")
    elif method == 0xff:
        raise ConnectionError("socks5: no acceptable auth method")
    elif method != 0x00:
        raise ConnectionError("socks5: unexpected method 0x%02x" % method)

    atyp, addr_body = _encode_addr(host)
    sock.sendall(bytes([0x05, 0x01, 0x00]) + atyp + addr_body
                + port.to_bytes(2, "big"))
    reply = _recvn(sock, 4)
    if reply[0:1] != b"\x05":
        raise ConnectionError("socks5: bad version in connect reply")
    if reply[1] != 0x00:
        raise ConnectionError("socks5: connect failed, rep=0x%02x" % reply[1])
    # BND.ADDR/BND.PORT still has to be drained off the wire before the
    # tunnel is clean, whatever its shape - the reply's own ATYP says how
    # long it is.
    bound_atyp = reply[3]
    if bound_atyp == 0x01:
        _recvn(sock, 4 + 2)
    elif bound_atyp == 0x03:
        _recvn(sock, _recvn(sock, 1)[0] + 2)
    elif bound_atyp == 0x04:
        _recvn(sock, 16 + 2)
    else:
        raise ConnectionError("socks5: unknown address type 0x%02x in reply"
                              % bound_atyp)


def _status_code(head: bytes) -> int:
    line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split()
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0


def _head_header_values(head: bytes, name: str) -> list[str]:
    """Every header line named `name` (case-insensitive) in a raw response
    head, in order. A 407 commonly carries one `Proxy-Authenticate` line
    PER scheme on offer (`Digest realm=..., nonce=...`, then a separate
    `NTLM` line, then a separate `Negotiate` line) - returned as separate
    strings rather than joined, since a scheme's own challenge parameters
    (Digest's especially) contain commas that would corrupt a naive
    single-line comma-split across schemes.
    """
    lname = name.lower()
    values = []
    for line in head.split(b"\r\n")[1:]:
        header_name, sep, value = line.partition(b":")
        if sep and header_name.decode("latin-1", "replace").strip().lower() == lname:
            values.append(value.decode("latin-1", "replace").strip())
    return values


def _select_challenge(head: bytes, scheme_name: str) -> Optional[str]:
    """The `Proxy-Authenticate` line offering `scheme_name` (case-
    insensitive), with the scheme token itself stripped - the remainder is
    either empty (the proxy is only announcing it supports this scheme, no
    token yet) or the scheme's own challenge (an NTLM/Negotiate base64 blob,
    or Digest's `realm=...` parameter list). `None` when that scheme was not
    offered at all.
    """
    lname = scheme_name.lower()
    for value in _head_header_values(head, "Proxy-Authenticate"):
        candidate_scheme, _, rest = value.partition(" ")
        if candidate_scheme.lower() == lname:
            return rest.strip()
    return None


#: A Digest challenge/credential parameter: `key=value` or `key="value"`.
_DIGEST_PARAM_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^\s,]+))')


def _parse_digest_challenge(value: str) -> dict:
    params = {}
    for m in _DIGEST_PARAM_RE.finditer(value):
        params[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    return params


def digest_proxy_authorization(challenge: str, username: str, password: str,
                               method: str, uri: str,
                               cnonce: Optional[str] = None) -> str:
    """RFC 7616 (RFC 2617-compatible) `Proxy-Authorization: Digest ...`
    value, computed from a `Proxy-Authenticate: Digest ...` challenge (with
    the leading `Digest ` scheme token already stripped by the caller) plus
    the credentials and the request's own method/URI.

    Pure and side-effect free (past drawing `cnonce`). `cnonce` is exposed so a caller can fix it;
    real callers let it default to a fresh `os.urandom` value.

    `qop=auth-int` (which digests the request body) is deliberately not
    distinguished from `qop=auth` here - `_http_connect_chain` only ever
    calls this for a bodyless CONNECT, so the two qop kinds would compute
    an identical result (the body hash is that of the empty string either
    way) and the extra branch would buy nothing. `algorithm=...-sess` is
    not implemented: it falls back to the plain (non-sess) formula, which
    is wrong for servers that require -sess.
    """
    params = _parse_digest_challenge(challenge)
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    opaque = params.get("opaque")
    algorithm = (params.get("algorithm") or "MD5").upper()
    digestmod = hashlib.sha256 if algorithm.startswith("SHA-256") else hashlib.md5
    qop_offered = [q.strip() for q in (params.get("qop") or "").split(",") if q.strip()]
    qop = "auth" if "auth" in qop_offered else (qop_offered[0] if qop_offered else None)

    def h(s: str) -> str:
        return digestmod(s.encode()).hexdigest()

    ha1 = h("%s:%s:%s" % (username, realm, password))
    ha2 = h("%s:%s" % (method, uri))
    cnonce = cnonce or os.urandom(8).hex()
    nc = "00000001"
    if qop:
        response = h("%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2))
    else:
        response = h("%s:%s:%s" % (ha1, nonce, ha2))

    parts = ['username="%s"' % username, 'realm="%s"' % realm,
             'nonce="%s"' % nonce, 'uri="%s"' % uri,
             'response="%s"' % response]
    if qop:
        parts += ["qop=%s" % qop, "nc=%s" % nc, 'cnonce="%s"' % cnonce]
    if opaque is not None:
        parts.append('opaque="%s"' % opaque)
    if "algorithm" in params:
        parts.append("algorithm=%s" % params["algorithm"])
    return "Digest " + ", ".join(parts)


def _http_connect_chain(sock: socket.socket, host: str, port: int,
                        spec: UpstreamSpec) -> None:
    """Dial an upstream HTTP(S) proxy's own CONNECT, authenticating to the
    PROXY itself (not the target beyond it) with whatever `spec.auth_scheme`
    names - the chained-proxy branch, for an upstream that is itself an
    http(s) proxy rather than the final origin or a SOCKS5 hop.

    Basic (the default): sent PROACTIVELY on the one
    and only CONNECT - no round trip spent finding out the proxy wants it.

    Digest/NTLM/Negotiate cannot be sent proactively - Digest
    needs the server's own nonce, NTLM/Negotiate need a real handshake - so
    the first CONNECT deliberately carries no `Proxy-Authorization` at all.
    If the proxy answers 200 anyway (it turned out not to require auth),
    that is used as-is. Otherwise its 407's `Proxy-Authenticate` challenge
    for the configured scheme drives one (Digest) or two (NTLM/Negotiate,
    Type1 then Type3) further CONNECTs on this SAME socket - NTLM/Negotiate
    are connection-scoped exactly like NTLM-to-target (see the NTLM
    sections below), so every leg of the handshake must share one TCP
    connection with the final, now-authenticated CONNECT; a fresh dial per
    leg would each start its own, unrelated challenge.
    """
    def send(extra_header: Optional[str] = None) -> bytes:
        lines = ["CONNECT %s:%d HTTP/1.1" % (host, port),
                 "Host: %s:%d" % (host, port)]
        if extra_header:
            lines.append(extra_header)
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        return _read_head(sock)

    def fail(head: bytes) -> None:
        raise ConnectionError(
            "upstream CONNECT failed: %s"
            % (head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
               if head else "no response from upstream proxy"))

    username, password = spec.username, spec.password
    if spec.auth_scheme == "basic":
        header = None
        if username:
            token = base64.b64encode(
                ("%s:%s" % (username, password or "")).encode()).decode()
            header = "Proxy-Authorization: Basic %s" % token
        head = send(header)
        if not head or not _status_ok(head):
            fail(head)
        return

    head = send(None)
    if _status_ok(head):
        return
    if not head or _status_code(head) != 407:
        fail(head)

    authority = "%s:%d" % (host, port)
    if spec.auth_scheme == "digest":
        challenge = _select_challenge(head, "Digest")
        if challenge is None:
            raise ConnectionError(
                "upstream proxy did not offer a Digest challenge")
        auth_value = digest_proxy_authorization(
            challenge, username or "", password or "", "CONNECT", authority)
        head = send("Proxy-Authorization: %s" % auth_value)
    elif spec.auth_scheme in ("ntlm", "negotiate"):
        scheme_name = "Negotiate" if spec.auth_scheme == "negotiate" else "NTLM"
        client = NtlmClient(username or "", password or "", hostname=spec.host,
                            protocol=spec.auth_scheme)
        type1 = client.step(None)
        head = send("Proxy-Authorization: %s %s"
                    % (scheme_name, base64.b64encode(type1).decode()))
        if _status_ok(head):
            return
        if not head or _status_code(head) != 407:
            fail(head)
        token_b64 = _select_challenge(head, scheme_name)
        if not token_b64:
            raise ConnectionError(
                "upstream proxy did not return a %s challenge" % scheme_name)
        type3 = client.step(base64.b64decode(token_b64))
        head = send("Proxy-Authorization: %s %s"
                    % (scheme_name, base64.b64encode(type3).decode()))
    else:
        raise ValueError("unsupported proxy auth scheme: %s" % spec.auth_scheme)

    if not head or not _status_ok(head):
        fail(head)


def _dial_upstream(spec: UpstreamSpec, host: str, port: int) -> socket.socket:
    """The one seam every CONNECT goes through: direct, chained through
    another HTTP(S) proxy, or through a SOCKS5 upstream. Returns a socket
    already positioned at the start of the tunnelled stream, or raises.
    """
    if spec.scheme == "direct":
        return socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S)
    if spec.scheme in ("http", "https"):
        sock = socket.create_connection((spec.host, spec.port),
                                        timeout=CONNECT_TIMEOUT_S)
        try:
            _http_connect_chain(sock, host, port, spec)
        except Exception:
            sock.close()
            raise
        return sock
    if spec.scheme in ("socks5", "socks5h"):
        sock = socket.create_connection((spec.host, spec.port),
                                        timeout=CONNECT_TIMEOUT_S)
        try:
            socks5_connect(sock, host, port, spec.username, spec.password)
        except Exception:
            sock.close()
            raise
        return sock
    raise ValueError("unsupported upstream scheme: %s" % spec.scheme)


def connect_through_relay(relay_host: str, relay_port: int, target_host: str,
                          target_port: int, timeout: float = CONNECT_TIMEOUT_S
                          ) -> socket.socket:
    """The client side of one CONNECT to OUR OWN relay.

    What a raw-socket probe transport (`execute.py::_probe_raw_query`) dials
    instead of the target directly, so the one lane that owns its socket
    outright - and therefore never passes through Chromium's proxy config at
    all - still goes out via whatever upstream (SOCKS5-with-credentials) the
    relay exists to reach.
    """
    sock = socket.create_connection((relay_host, relay_port), timeout=timeout)
    try:
        sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                     % (target_host, target_port, target_host, target_port))
                    .encode("ascii"))
        head = _read_head(sock)
        if not head or not _status_ok(head):
            raise ConnectionError(
                "relay CONNECT failed: %s"
                % head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip())
    except Exception:
        sock.close()
        raise
    return sock


# --------------------------------------------------------------------------
# splice
# --------------------------------------------------------------------------

def _pump(src: socket.socket, dst: socket.socket, idle_timeout: float) -> None:
    src.settimeout(idle_timeout)
    try:
        while True:
            try:
                chunk = src.recv(RECV_BUFFER)
            except socket.timeout:
                break
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        # Half-close: forward the FIN this direction just saw without
        # touching the socket's other, possibly still-live direction. A
        # streamed request body that keeps sending after the response
        # headers are already back (or the reverse) needs the pump that
        # finished to stop WITHOUT killing the pump still carrying the other
        # direction's bytes.
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _splice(a: socket.socket, b: socket.socket,
           idle_timeout: float = IDLE_TIMEOUT_S) -> None:
    """Pump both directions of an already-established tunnel until each
    side has seen the other's FIN (or gone idle), then close both.

    Two threads, one per direction, each doing its own half-close on EOF.
    Both sockets are only ever closed here, after BOTH pump threads have
    joined - closing one while the other thread might still call `recv`/
    `sendall` on it is exactly the race a shared teardown avoids.
    """
    t1 = threading.Thread(target=_pump, args=(a, b, idle_timeout), daemon=True)
    t2 = threading.Thread(target=_pump, args=(b, a, idle_timeout), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for sock in (a, b):
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# the relay itself
# --------------------------------------------------------------------------

class _RelayHandler(socketserver.BaseRequestHandler):

    def handle(self) -> None:
        relay: "Relay" = self.server.relay        # type: ignore[attr-defined]
        try:
            head = _read_head(self.request)
        except OSError:
            return
        if not head:
            return
        request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = request_line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            self._reject(405, "only CONNECT is supported")
            return
        host, _, port_s = parts[1].rpartition(":")
        if not host or not port_s.isdigit():
            self._reject(400, "malformed CONNECT target")
            return
        port = int(port_s)
        if not relay.origin_allowed(host, port):
            self._reject(403, "target is outside the run's scope")
            return
        if relay.target_auth_configured:
            self._intercept_ntlm(relay, host, port)
            return
        try:
            upstream = _dial_upstream(relay.upstream, host, port)
        except Exception as exc:
            self._reject(502, str(exc)[:200])
            return
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            upstream.close()
            return
        _splice(self.request, upstream, relay.idle_timeout)

    def _intercept_ntlm(self, relay: "Relay", host: str, port: int) -> None:
        """NTLM-to-target: terminate the browser's TLS here, complete the NTLM
        handshake on the relay's OWN connection to the real target, and
        forward every request/response pair over both legs for the life of
        this one browser tunnel. See the TLS-interception section below for
        why this cannot be a splice.
        """
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            return
        try:
            tls_context = relay.tls_context_for(host)
            tls_sock = tls_context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            log.debug("TLS handshake with the browser failed for %s: %s",
                      host, exc)
            return
        rfile = tls_sock.makefile("rb")
        upstream: Optional[_NtlmUpstream] = None
        try:
            upstream = _NtlmUpstream(host, port, relay.target_auth_username,
                                     relay.target_auth_password)
            while True:
                request = _read_http_request(rfile)
                if request is None:
                    break
                method, path, headers, body = request
                close_after = _header(headers, "Connection").lower() == "close"
                try:
                    status, reason, resp_headers, resp_body = upstream.send(
                        method, path, headers, body)
                except Exception as exc:
                    log.warning("upstream NTLM request failed for %s%s: %s",
                                host, path, exc)
                    break
                try:
                    _write_http_response(tls_sock, status, reason,
                                         resp_headers, resp_body)
                except OSError:
                    break
                if close_after:
                    break
        finally:
            if upstream is not None:
                upstream.close()
            try:
                rfile.close()
            except OSError:
                pass
            try:
                tls_sock.close()
            except OSError:
                pass

    def _reject(self, status: int, reason: str) -> None:
        try:
            self.request.sendall(
                ("HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n"
                % (status, reason)).encode("latin-1", "replace"))
        except OSError:
            pass


class _RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    relay: "Relay"


class Relay:
    """Owns the upstream spec and the run's scope; hands Chromium (and the
    raw-query lane) a plain loopback CONNECT proxy they can both actually
    talk to.
    """

    def __init__(self, upstream: UpstreamSpec, scope: Optional[ScopeRules] = None,
                idle_timeout: float = IDLE_TIMEOUT_S,
                target_auth_username: Optional[str] = None,
                target_auth_password: Optional[str] = None):
        self.upstream = upstream
        self.scope = scope
        self.idle_timeout = idle_timeout
        # NTLM-to-target. Set, this turns EVERY in-scope
        # CONNECT into a TLS-interception (see `_RelayHandler._intercept_ntlm`)
        # rather than a tunnel-splice - there is one target identity per run,
        # not a per-host list, matching `--client-cert-origin`'s shape.
        self.target_auth_username = target_auth_username
        self.target_auth_password = target_auth_password
        self._tls_contexts: dict[str, ssl.SSLContext] = {}
        self._tls_lock = threading.Lock()
        self._cert_dir: Optional[tempfile.TemporaryDirectory] = None
        self._server: Optional[_RelayServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def target_auth_configured(self) -> bool:
        return bool(self.target_auth_username and self.target_auth_password)

    def tls_context_for(self, host: str) -> ssl.SSLContext:
        """A cached, minted-on-demand self-signed server context for `host`.

        Cached rather than known in advance: the CONNECT line already names
        the exact hostname the browser wants, so no SNI callback is needed
        to pick it - the dispatch already happened at parse time, in
        `_RelayHandler.handle()`, before TLS is even involved.
        """
        with self._tls_lock:
            context = self._tls_contexts.get(host)
            if context is not None:
                return context
            if self._cert_dir is None:
                self._cert_dir = tempfile.TemporaryDirectory(
                    prefix="sekuscan-relay-tls-")
            context = _mint_leaf_context(host, self._cert_dir.name)
            self._tls_contexts[host] = context
            return context

    def origin_allowed(self, host: str, port: int) -> bool:
        """Host/port containment. `scope=None` means "no restriction"; both
        callers in this package (`browser.py` and `cli.py`) pass a real
        `ScopeRules`, so the relay is scope-limited in practice.

        A CONNECT target's scheme is exactly what the tunnel hides, so this
        tries both http and https readings of the operator's scope rather
        than guessing one - a scope declared as a bare `https://` origin
        must not refuse the very host it names just because the low-level
        hint said "http".
        """
        if self.scope is None:
            return True
        origins = list(self.scope.origins or ())
        if not origins:
            return False
        allow_sub = bool(self.scope.allow_subdomains)
        return (scoping.origin_reachable(host, port, "https", origins, allow_sub)
                or scoping.origin_reachable(host, port, "http", origins, allow_sub))

    def start(self) -> tuple[str, int]:
        self._server = _RelayServer(("127.0.0.1", 0), _RelayHandler)
        self._server.relay = self
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return "127.0.0.1", self._server.server_address[1]

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None
        self._thread = None
        if self._cert_dir is not None:
            try:
                self._cert_dir.cleanup()
            except Exception:
                pass
            self._cert_dir = None


# --------------------------------------------------------------------------
# NTLM-to-target - the pyspnego client.
#
# `_RelayHandler._intercept_ntlm` drives this over its own upstream HTTP(S)
# connection to the real target once TLS interception terminates the
# browser's CONNECT. This class builds a client context, steps it through an
# NTLMv2 exchange, and turns a token into/out of the wire header shape.
# --------------------------------------------------------------------------

class NtlmClient:
    """Client side of one NTLMv2 (or Negotiate/SPNEGO) handshake, wrapping a
    pyspnego context.

    `protocol="ntlm"` (the default, and the only value NTLM-to-target uses)
    forces `options=use_ntlm` so this runs the same NTLM code path on every
    install rather than whatever a system GSSAPI/SSPI backend happens to
    pick. `protocol="negotiate"` (parent-proxy `--proxy-auth-scheme negotiate`)
    leaves the options at pyspnego's default, so it picks Kerberos when a
    real ticket is available and falls back to NTLM under the same SPNEGO
    wrapper otherwise - a parent proxy offering "Negotiate" is offering
    exactly that choice, not mandating Kerberos. `username` is the
    `DOMAIN\\user` form, not a UPN.
    """

    def __init__(self, username: str, password: str, hostname: str,
                protocol: str = "ntlm"):
        options = (spnego.NegotiateOptions.use_ntlm if protocol == "ntlm"
                  else spnego.NegotiateOptions.none)
        self._context = spnego.client(
            username, password, hostname=hostname, service="HTTP",
            protocol=protocol, options=options)

    def step(self, in_token: Optional[bytes] = None) -> Optional[bytes]:
        """`None` in -> Type1 out. Type2 in -> Type3 out."""
        return self._context.step(in_token)

    @property
    def complete(self) -> bool:
        """True once this side has built its last message (Type3) - NOT
        proof the server accepted it. Set on the step that produces Type3;
        only the server's own acceptance (its `.complete`, and no exception
        from its final `step`) means the handshake actually succeeded.
        """
        return self._context.complete


def ntlm_auth_header(token: bytes) -> str:
    """A token -> the `Authorization`/`Proxy-Authorization` value that
    carries it: `"NTLM <b64>"`."""
    return "NTLM " + base64.b64encode(token).decode("ascii")


def parse_ntlm_challenge(value: Optional[str]) -> Optional[bytes]:
    """A `WWW-Authenticate` header VALUE -> its NTLM token, or `None`.

    Handles a server offering several schemes on one line
    (`"Negotiate, NTLM <b64>"`) and matches the scheme name
    case-insensitively. A bare `"NTLM"` challenge (no token yet - the
    server's way of asking for a Type1) also reads as `None`: either way,
    there is no token to step with yet.
    """
    if not value:
        return None
    for part in value.split(","):
        scheme, _, token = part.strip().partition(" ")
        if scheme.lower() != "ntlm" or not token.strip():
            continue
        try:
            return base64.b64decode(token.strip())
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------
# NTLM-to-target - TLS interception on the relay's CONNECT handler, and the
# upstream side of the handshake.
#
# `_RelayHandler` normally splices a CONNECT tunnel byte-for-byte and never
# looks inside it (see the module docstring). NTLM cannot be done that way:
# the handshake has to happen on THIS process's own HTTP connection to the
# target, since the browser has no NTLM client of its own and Chromium's
# `--proxy-server` cannot inject one. So when target-auth is configured,
# `_RelayHandler` answers the CONNECT itself, TLS-terminates the browser's
# side with a leaf certificate minted on demand (no CA needed - Chromium
# runs with `ignore_https_errors=True`, see `browser.py`), and opens its OWN
# TLS connection to the real target for every request that arrives on the
# browser's tunnel. `http.client.HTTPSConnection` carries that connection:
# it parses HTTP/1.1 framing (status line, headers, Content-Length/chunked
# body) for free, and keep-alive falls out of reusing the same
# `HTTPConnection` object across every request the browser sends down one
# tunnel - which is also exactly what NTLM's connection-scoping needs:
# authenticate once per TCP connection, never once per request.
#
# Scope: HTTPS/CONNECT targets only (see the module docstring's note on a
# plain-http absolute-GET target). Interception does not chain through
# `relay.upstream` (a SOCKS5/HTTP parent proxy) - it dials the target
# directly, so an upstream proxy cannot be combined with NTLM-to-target in
# the same run.
# --------------------------------------------------------------------------

#: Headers stripped between the browser and the intercepted upstream
#: connection, in EITHER direction - proxy/connection plumbing that belongs
#: to one hop and must never survive to the other.
_HOP_BY_HOP_HEADERS = {
    "connection", "proxy-connection", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding",
    "upgrade", "keep-alive",
}


def _header(headers: dict, name: str, default: str = "") -> str:
    """Case-insensitive lookup - HTTP header names are, and a hand-parsed
    dict here (unlike Playwright's own header objects) does not normalise
    case for you."""
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value
    return default


def _forwardable_request_headers(headers: dict) -> dict:
    """Browser -> upstream. Also drops any inbound `Authorization` - the
    upstream connection's own NTLM handshake owns that header from here on;
    forwarding whatever the page itself sent would either clobber it or
    leak a header the page had no way to construct correctly anyway.
    """
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_BY_HOP_HEADERS
            and k.lower() != "authorization"}


def _forwardable_response_items(items) -> list:
    """Upstream -> browser. `Content-Length` is dropped too - the body is
    already fully read by the time this runs, and `_write_http_response`
    sets it from the real length rather than trust whatever the origin sent
    for a body it may have chunked."""
    return [(name, value) for name, value in items
            if name.lower() not in _HOP_BY_HOP_HEADERS
            and name.lower() != "content-length"]


def _read_http_request(rfile) -> Optional[tuple[str, str, dict, bytes]]:
    """One HTTP/1.1 request off an already-TLS-framed byte stream:
    `(method, path, headers, body)`. `None` at a clean EOF between requests
    - the ordinary end of a keep-alive tunnel the browser closed politely.

    Content-Length only - a browser talking to an intercepted origin over
    ordinary page loads and form submissions does not chunk its OWN request
    bodies; a streamed upload is out of scope.
    """
    request_line = rfile.readline(MAX_HEAD_BYTES)
    if not request_line:
        return None
    try:
        method, path, _version = request_line.decode("latin-1").strip().split(" ", 2)
    except ValueError:
        return None
    headers: dict[str, str] = {}
    while True:
        line = rfile.readline(MAX_HEAD_BYTES)
        if not line or line in (b"\r\n", b"\n"):
            break
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep:
            continue
        headers[name.strip()] = value.strip()
    length = 0
    try:
        length = int(_header(headers, "Content-Length", "0") or "0")
    except ValueError:
        length = 0
    body = rfile.read(length) if length else b""
    return method, path, headers, body


def _write_http_response(sock, status: int, reason: str, header_items,
                         body: bytes) -> None:
    lines = ["HTTP/1.1 %d %s" % (status, reason or "")]
    for name, value in _forwardable_response_items(header_items):
        lines.append("%s: %s" % (name, value))
    lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: keep-alive")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
                + body)


def _mint_leaf_context(host: str, cert_dir: str) -> ssl.SSLContext:
    """A fresh, self-signed server `SSLContext` for exactly one hostname.

    The SAN type follows the host: an IP literal
    gets `x509.IPAddress`, anything else `x509.DNSName` - a browser's TLS
    stack checks the SAN against whichever form the CONNECT target actually
    named. No CA is involved anywhere; Chromium is launched with
    `ignore_https_errors=True` (see `browser.py`) specifically so a bare
    self-signed leaf is accepted without one.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    try:
        san = x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address(host))])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256()))
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", host) or "host"
    key_path = os.path.join(cert_dir, "%s.key.pem" % safe)
    cert_path = os.path.join(cert_dir, "%s.cert.pem" % safe)
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


class _NtlmUpstream:
    """One authenticated HTTP/1.1 connection to the real target, opened once
    per intercepted browser tunnel and reused for every request that arrives
    on it. NTLM is connection-scoped - re-handshaking
    per request would be both wrong (a fresh NTLM context has no relationship
    to whatever the server already accepted) and needlessly expensive.

    Self-healing: if the browser-facing tunnel sits idle, a server's
    keep-alive timeout can close the *upstream* leg while `self._authed`
    still says the connection is authenticated. `http.client` then either
    raises (`RemoteDisconnected` et al.) or - because
    `HTTPConnection.request()` transparently reconnects whenever
    `self.sock is None` - silently opens a new, unauthenticated socket and
    completes the request on it, which comes back as an ordinary 401. Both
    cases are detected and the handshake is redone once, rather than every
    later request failing with 401.
    """

    def __init__(self, host: str, port: int, username: str, password: str):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._host = host
        self._username = username
        self._password = password
        self._conn = http.client.HTTPSConnection(
            host, port, context=ctx, timeout=CONNECT_TIMEOUT_S)
        self._authed = False

    def send(self, method: str, path: str, headers: dict, body: bytes):
        headers = _forwardable_request_headers(headers)
        # At most one self-heal retry: attempt 0 uses the current state
        # (handshaking first if not authenticated); attempt 1 happens only if
        # attempt 0 rode a connection that was recycled, and always
        # re-handshakes, so a genuine credential or target failure surfaces
        # after two tries rather than looping.
        for attempt in (0, 1):
            reused_auth = self._authed
            try:
                if not self._authed:
                    self._handshake(method, path, headers)
                self._conn.request(method, path, body=(body or None), headers=headers)
                resp = self._conn.getresponse()
                resp_body = resp.read()
            except (http.client.HTTPException, OSError):
                if attempt == 1:
                    raise
                self._authed = False
                try:
                    self._conn.close()  # force the next .request() to reconnect
                except Exception:
                    pass
                continue
            if resp.status == 401 and reused_auth and attempt == 0:
                # We believed this connection was authenticated and skipped
                # the handshake; a 401 here means the physical socket was
                # silently swapped (recycled) underneath that belief, not
                # that the credentials are wrong. Re-handshake and retry once.
                self._authed = False
                continue
            return resp.status, resp.reason, resp.getheaders(), resp_body

    def _handshake(self, method: str, path: str, headers: dict) -> None:
        """Type1 -> the server's Type2 challenge -> Type3, on THIS
        connection, before the caller's real request goes out on it.

        The Type1 leg reuses the caller's method/path (some servers gate the
        challenge on the resource, not just the connection) but never its
        body - fully draining the 401 that comes back is what keeps the
        keep-alive socket usable for the real request right after, and
        resending a non-idempotent body twice would be
        its own bug.
        """
        client = NtlmClient(self._username, self._password, hostname=self._host)
        type1 = client.step(None)
        leg_headers = {k: v for k, v in headers.items()
                       if k.lower() not in ("content-length", "transfer-encoding")}
        leg_headers["Authorization"] = ntlm_auth_header(type1)
        self._conn.request(method, path, body=None, headers=leg_headers)
        resp = self._conn.getresponse()
        resp.read()  # drain fully - see the docstring above
        challenge = parse_ntlm_challenge(resp.getheader("WWW-Authenticate"))
        if resp.status != 401 or challenge is None:
            raise ConnectionError(
                "upstream did not offer an NTLM challenge for the Type1 "
                "leg (status %d)" % resp.status)
        type3 = client.step(challenge)
        headers["Authorization"] = ntlm_auth_header(type3)
        # `complete` here means "built Type3", never "the server accepted
        # it" (see `NtlmClient`'s own docstring) - a wrong password still
        # reaches this line, and is caught by the caller reading whatever
        # status the real request (sent next, on this same connection)
        # comes back with.
        self._authed = True

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
