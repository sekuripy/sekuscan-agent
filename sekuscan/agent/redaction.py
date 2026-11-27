# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Local redaction of secrets before anything leaves the agent.

The agent is the only component that sees raw traffic, so redaction happens
here, mechanically and locally, before data is sent to the engine.

What is redacted:
  * request-side credentials: Authorization, Cookie, API-key and CSRF-token
    headers, and the values of a request Cookie header (names are kept);
  * well-known key formats (cloud, source-host and payment-provider keys,
    private keys, a JWT's signature) and credential-named URL parameters;
  * populated password fields and anti-CSRF form values, which are replaced by
    a handle (`PRESERVE_DOM_VALUE`) that the agent resolves locally.

What is deliberately NOT redacted: values the target itself discloses in a
response (a Set-Cookie value, a token or password echoed in a body, a Referer),
and values this scanner generated. These are the evidence a report exists to
show; the target already holds them.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from typing import Any, Optional
from urllib.parse import quote, quote_plus

from ..protocol.models import PRESERVE_DOM_VALUE

REDACTED = "<redacted>"

#: Extra length scanned beyond the caller's limit before truncating, so a long
#: match that straddles the limit is still replaced whole. See `redact_text`.
_REDACT_MARGIN = 16384

SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
    "x-xsrf-token", "api-key", "authentication", "x-amz-security-token",
}

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # A JWT with only its signature dropped. The signature is the secret; the
    # header and claims are base64 of public metadata (see `jwt_preview`).
    # Keeping them preserves what a reader needs to assess the token (`alg`,
    # `exp`, role claims).
    (re.compile(r"\b(eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,})\.[A-Za-z0-9_-]{4,}"),
     r"\1.<redacted-signature>"),
    # A bearer token in a response body is left alone: it is a value the
    # target disclosed. In a request header it is the operator's credential
    # and `redact_headers` handles it.
    # Cloud and service keys.
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{12,}\b"), "<redacted:aws-key>"),
    # Stripe secret/restricted keys only ("sk_"/"rk_"). "pk_" publishable keys
    # are documented as public, client-side identifiers, not secrets.
    (re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
     "<redacted:stripe-key>"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "<redacted:google-api-key>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "<redacted:github-token>"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "<redacted:api-key>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<redacted:slack-token>"),
    # Further token formats. These are redacted before leaving the agent; the
    # placeholder still tells the engine what kind of secret was found.
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "<redacted:github-token>"),
    (re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36}\b"), "<redacted:github-token>"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "<redacted:npm-token>"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{40,45}\b"),
     "<redacted:sendgrid-key>"),
    (re.compile(r'"type"\s*:\s*"service_account"'),
     "<redacted:gcp-service-account>"),
    # The whole key, through its END line (or to the end of a truncated
    # sample). Matching only the header and the next 64 characters left the
    # rest of the key body in place.
    (re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?(?:-----END \1PRIVATE KEY-----|$)"),
     "<redacted:private-key>"),
    # A credential-NAMED JSON field in a response body is NOT redacted: it is
    # a value the target disclosed. `redact_headers` keeps Authorization and
    # Cookie request-header values off the wire.
    #
    # A credential-NAMED query parameter. The value charset excludes the
    # punctuation `<>()\'";|` and backtick, so a value containing markup is
    # not redacted. Values this scanner generated itself (`SekuScan-...`,
    # `sekuscan@...`, `sks...`) are also left alone: they are not anyone's
    # credential.
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|"
                r"access[_-]?token|client[_-]?secret|otp|pin|cvv)"
                r"=(?!SekuScan-|sekuscan@|sks[a-z0-9]{4,}(?=$|[&\s]))"
                r"([^&\s#<>()'\";|`]{4,})(?=$|[&\s#])"),
     r"\1=<redacted>"),
]

#: Shapes that mean "this one value is opaque key material".
#:
#: These are not applied to response bodies. Bodies are transmitted largely in
#: full, so mangling a long hex or base64 substring inside one is not
#: protection, and it would corrupt legitimate content such as base64-encoded
#: file contents that a probe asked the target to return.
#:
#: They are right for a single FORM FIELD VALUE, which is what
#: `redact_value_sample` judges: a hidden input of 40 hex characters is an
#: anti-CSRF token, and becomes `PRESERVE_DOM_VALUE`, a handle the agent
#: resolves locally, rather than a description of itself.
_OPAQUE_VALUE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Fa-f0-9]{40,}\b"), "<redacted:hex>"),
    (re.compile(r"\b[A-Za-z0-9+/]{48,}={0,2}\b"), "<redacted:blob>"),
]


#: Literals every match of a `_PATTERNS` entry must contain. A pattern whose
#: literals are all absent cannot match, and `in` is a C substring search, so
#: the regex is skipped. This keeps redaction cheap on large volumes of
#: responses. A pattern with no entry here (the case-insensitive parameter
#: rule) always runs.
_NEEDLES: dict[re.Pattern[str], tuple[str, ...]] = {
    pattern: needles for (pattern, _), needles in zip(_PATTERNS, (
        ("eyJ",), ("AKIA", "ASIA"), ("k_live_", "k_test_"), ("AIza",),
        ("ghp_",), ("sk-",), ("xox",), ("github_pat_",),
        ("gho_", "ghu_", "ghs_", "ghr_"), ("npm_",), ("SG.",),
        ("service_account",), ("-----BEGIN",)))}


def redact_text(text: Optional[str], limit: Optional[int] = None,
                opaque_shapes: bool = False) -> str:
    """Redact a BODY: known credential formats only, by default.

    `opaque_shapes` additionally applies `_OPAQUE_VALUE_PATTERNS`; only
    `redact_value_sample` passes it (see that constant for why).
    """
    if not text:
        return ""
    out = text
    # Cut before scanning so a very large response is not run through every
    # pattern only to keep its first few KB.
    #
    # The cut is at `limit + _REDACT_MARGIN` rather than at `limit` so that a
    # long match (a multi-line key, say) that straddles the limit is still
    # matched whole and replaced; otherwise its tail could be cut off, the
    # pattern would stop matching, and its head would remain in the output.
    if limit is not None and len(out) > limit + _REDACT_MARGIN:
        out = out[:limit + _REDACT_MARGIN]
    patterns = (_PATTERNS + _OPAQUE_VALUE_PATTERNS) if opaque_shapes else _PATTERNS
    for pattern, repl in patterns:
        needles = _NEEDLES.get(pattern)
        if needles and not any(needle in out for needle in needles):
            continue
        out = pattern.sub(repl, out)
    out = scrub_text(out)
    if limit is not None and len(out) > limit:
        out = scrub_text(out[:limit])
    return out


#: Header names the operator supplied (`--header`). Their values are the
#: operator's own credentials or tenant identifiers, whatever they are called,
#: so they are redacted like `Authorization` wherever a header set is reported.
_OPERATOR_HEADERS: set[str] = set()


#: Every credential value the operator supplied (passwords, codes, tokens,
#: cookie and header values). `scrub_secrets` removes them from everything
#: sent to the engine, whatever path carried them there.
_SECRET_VALUES: set[str] = set()
#: Shorter values are not scrubbed: they would match unrelated text.
MIN_SECRET_LENGTH = 4
#: Values that appear on every login page; scrubbing them would erase the
#: page, not protect a secret. A credential this weak is not one.
UBIQUITOUS_VALUES = frozenset({"password", "admin", "administrator", "user", "guest",
                               "test", "root", "demo", "login"})
#: Protocol fields describing a page's structure (a field's type or name):
#: never scrubbed, they are what the target wrote, not what was typed.
_STRUCTURAL_KEYS = frozenset({"type", "name", "id", "autocomplete", "input_type", "tag",
                              "kind", "role"})
SECRET_REDACTED = "<redacted:secret>"
#: The shortest cut-off piece of a secret still scrubbed at a string's edge.
_PARTIAL_MIN = 5
_FORMS: list[str] = []


def register_secret_values(values) -> None:
    """The operator-supplied values `scrub_secrets` removes (replaces any
    earlier set, so one run's secrets never outlive it in a process)."""
    _SECRET_VALUES.clear()
    for value in values or ():
        value = str(value or "")
        if len(value) >= MIN_SECRET_LENGTH and value.lower() not in UBIQUITOUS_VALUES:
            _SECRET_VALUES.add(value)
    forms = set()
    for value in _SECRET_VALUES:
        forms.update((value, quote(value, safe=""), quote_plus(value),
                      # a browser's form encoding: `*` kept, `~` escaped
                      quote_plus(value, safe="*").replace("~", "%7E"),
                      quote(value, safe="").replace("~", "%7E"),
                      json.dumps(value)[1:-1], html.escape(value),
                      # an application that echoes it transformed
                      value.upper(), value.lower(),
                      base64.b64encode(value.encode()).decode().rstrip("=")))
    _FORMS[:] = sorted((f for f in forms if len(f) >= MIN_SECRET_LENGTH),
                       key=len, reverse=True)


def scrub_text(text: str) -> str:
    """`text` with every registered secret replaced, including a secret cut
    off at either end of it (a truncated sample)."""
    if not _FORMS or not text:
        return text
    for form in _FORMS:
        if form in text:
            text = text.replace(form, SECRET_REDACTED)
        for k in range(len(form) - 1, _PARTIAL_MIN - 1, -1):
            if text.endswith(form[:k]):
                text = text[:-k] + SECRET_REDACTED
                break
        for k in range(len(form) - 1, _PARTIAL_MIN - 1, -1):
            if text.startswith(form[-k:]):
                text = SECRET_REDACTED + text[k:]
                break
    return text


def _scrub_compressed(value: str) -> str:
    """A `body_z` (zlib + base64) with its content scrubbed."""
    import zlib

    try:
        text = zlib.decompress(base64.b64decode(value)).decode("utf-8")
    except Exception:
        return ""  # unreadable here means unscrubbable: not sent
    return base64.b64encode(zlib.compress(scrub_text(text).encode("utf-8"), 6)).decode("ascii")


def scrub_secrets(document: Any) -> Any:
    """`document` with every registered secret value replaced in every string
    (keys included, and inside `body_z`), in the plain, percent-encoded,
    form-encoded, JSON-escaped and HTML-escaped forms. Structural fields and
    non-string values are untouched."""
    if not _FORMS:
        return document

    def walk(value: Any, key: Optional[str] = None) -> Any:
        if isinstance(value, str):
            if key in _STRUCTURAL_KEYS:
                return value
            if key == "body_z":
                return _scrub_compressed(value) if value else value
            return scrub_text(value)
        if isinstance(value, dict):
            return {walk(k): walk(v, k) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [walk(v) for v in value]
        return value

    return walk(document)


def register_operator_headers(names) -> None:
    """Redact the values of these operator-supplied headers from now on."""
    for name in names or ():
        if name:
            _OPERATOR_HEADERS.add(str(name).strip().lower())


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        low = name.lower()
        if low == "set-cookie":
            # Kept, value and all: a response `Set-Cookie` is a value the
            # target issued. A request `Cookie:` is redacted.
            out[name] = redact_text(value, 400)
        elif low == "referer":
            # Kept whole (capped at 400 characters). A `Referer` is not a
            # credential this agent carries; it is a URL the browser already
            # sent to a third party.
            out[name] = value[:400] if value else ""
        elif low == "authorization" and value.lower().startswith("bearer "):
            token = value.split(" ", 1)[1]
            preview = jwt_preview(token)
            out[name] = f"Bearer {preview}" if preview else f"{REDACTED}:{len(value)}"
        elif low in SENSITIVE_HEADERS or low in _OPERATOR_HEADERS:
            out[name] = f"{REDACTED}:{len(value or '')}"
        else:
            out[name] = redact_text(value, 400)
    return out


def redact_cookie_header(value: str, keep: Optional[str] = None) -> str:
    """Redact a REQUEST `Cookie:` header per pair, not as one opaque string.

    Every value is blanked and every NAME survives. The pair named by `keep`
    (the value this request deliberately set) is left intact.

    A value the application issued reaches the engine through `Set-Cookie`,
    which is kept whole; a request `Cookie:` is only that value being replayed,
    or an operator-supplied session, which must not leave the agent.
    """
    out = []
    for part in (value or "").split(";"):
        pair = part.strip()
        if not pair:
            continue
        if "=" not in pair:
            out.append(f"{REDACTED}:{len(pair)}")
            continue
        name, raw = pair.split("=", 1)
        if keep is not None and name == keep:
            out.append(f"{name}={raw}")
        else:
            out.append(f"{name}={REDACTED}:{len(raw)}")
    return "; ".join(out)


_JWT_RE = re.compile(r"\A(eyJ[A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]*)\Z")


def jwt_preview(value: str) -> Optional[str]:
    """Keep a JWT's header and claims, drop the signature.

    The signature is the secret; the header and payload are base64 of public
    metadata. Preserving them lets the engine judge `alg`, `exp` and role
    claims without ever handling key material.
    """
    match = _JWT_RE.match((value or "").strip())
    if not match:
        return None
    return f"{match.group(1)}.{match.group(2)}.<redacted-signature>"


def value_fingerprint(value: str) -> Optional[str]:
    """A one-way fingerprint of a secret-ish value, safe to report.

    The identifier itself is a credential that must stay off the wire. A
    truncated hash allows two values to be compared without carrying a value
    an observer could replay.
    """
    if not value:
        return None
    return hashlib.sha256(value.encode("utf8")).hexdigest()[:24]


def value_shape(value: str) -> str:
    """Coarse shape of a secret-ish value, safe to report."""
    if not value:
        return "empty"
    if re.fullmatch(r"[0-9]+", value):
        return "numeric"
    if re.fullmatch(r"[A-Fa-f0-9]+", value):
        return "hex"
    if value.count(".") == 2 and value.startswith("eyJ"):
        return "jwt"
    if re.fullmatch(r"[A-Za-z0-9+/=_\-]+", value):
        return "opaque-token"
    return "mixed"


#: A hidden field whose NAME says it carries request state the application
#: will re-check. Shape alone is not enough: a shape rule catches a long hex
#: token but misses short or differently encoded nonces. Replaying a stale
#: value makes the application reject the submission.
#:
#: Every name here is a common framework default:
#:   csrfmiddlewaretoken          Django
#:   authenticity_token           Rails
#:   __RequestVerificationToken   ASP.NET / ASP.NET Core
#:   _csrf, _csrf_token           Spring Security, Symfony
#:   _token                       Laravel
#:   __VIEWSTATE, __EVENTVALIDATION  ASP.NET WebForms
#:   nonce, _wpnonce              WordPress and the wider PHP world
#:
#: Matched on the NAME only, and only for a hidden input, so a visible field a
#: user actually fills is never turned into a handle.
_TOKEN_FIELD_RE = re.compile(
    r"(?i)(?:^|[_\-\[.])?(?:csrf|xsrf|authenticity[_\-]?token|"
    r"request[_\-]?verification[_\-]?token|verification[_\-]?token|"
    r"viewstate|eventvalidation|nonce|wpnonce|"
    r"anti[_\-]?csrf|_token|form[_\-]?key|synchronizer[_\-]?token)")


def looks_like_a_token_field(name: Optional[str]) -> bool:
    """Does this field NAME say the application will re-check its value?"""
    return bool(name) and bool(_TOKEN_FIELD_RE.search(str(name)))


def redact_value_sample(value: Optional[str], keep: int = 240,
                        name: Optional[str] = None,
                        hidden: bool = False,
                        input_type: Optional[str] = None) -> Optional[str]:
    """Form field values are echoed back to the engine, so keep them short and clean.

    A value that redaction would destroy is replaced by a handle rather than by
    a description of itself. `<redacted:hex>` is not a value: if sent back in a
    fill directive it would be typed into the anti-CSRF field and the
    application would reject the submission.

    `PRESERVE_DOM_VALUE` means "leave what the browser already has there",
    which is both the correct submission and the strongest redaction: the
    token never leaves the agent.
    """
    if value is None:
        return None
    if input_type == "password" and value:
        # A populated password field (for example a login form re-rendered
        # after a failed submit) is a credential, and a short one passes every
        # shape heuristic below. Empty stays empty: a handle would claim a DOM
        # value that is not there.
        return PRESERVE_DOM_VALUE
    if hidden and looks_like_a_token_field(name):
        # The NAME already settled it, so the shape does not get a vote. A
        # short framework nonce is still a nonce, and replaying a stale one is
        # what this handle prevents.
        return PRESERVE_DOM_VALUE
    # `opaque_shapes=True`: for a single field value the shape is the signal,
    # unlike for a body.
    cleaned = redact_text(value, keep, opaque_shapes=True)
    if cleaned != value[:keep]:
        # Redaction changed it, so what is left is a description rather than
        # a value; hand back the handle instead.
        return PRESERVE_DOM_VALUE
    return cleaned
