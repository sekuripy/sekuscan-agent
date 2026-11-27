# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""SekuScan wire protocol (agent <-> engine).

The engine sends `Directive` objects describing mechanical browser or HTTP
operations; the agent executes them and sends back `Observation` objects
describing what it saw. The agent applies its own scope, risk and redaction
rules to every directive and observation (see `agent/scope.py` and
`agent/redaction.py`).
"""

from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "0.1"
AGENT_VERSION = "0.2.7"
ENGINE_VERSION = "0.1.0"

DirectiveKind = Literal[
    "navigate",
    "click",
    "fill_submit",
    "probe_http",
    "probe_ws",
    "script_load",
    "upload_file",
    "upload_cleanup",
    "set_cookie",
    "screenshot",
    "wait",
    "stop",
]


# --------------------------------------------------------------------------
# run lifecycle
# --------------------------------------------------------------------------


def effective_risk(risk: int, allow_destructive: bool, allow_upload_cleanup: bool,
                   allow_authz_non_get: bool) -> int:
    """The risk level that actually governs a run, older surgical flags folded in.

    Used both when a run is created and by the agent's own local policy, so the
    agent derives its authorization from the operator's local flags instead of
    trusting a risk level reported by the engine.

    Only the three explicit operator flags (--allow-destructive,
    --allow-upload-cleanup, --allow-authz-non-get) are folded in, not a
    free-form `profile` string: a profile label is not an explicit capability
    grant the way a named CLI flag is.
    """
    legacy_risk = 3 if allow_upload_cleanup else 2 if (
        allow_destructive or allow_authz_non_get) else 1
    return max(int(risk), legacy_risk)


class ScopeRules(BaseModel):
    """Scope contract. The engine sends it; the agent also enforces it locally.

    Response-direction: see `RunCreateResponse` for why this gets
    `extra="forbid"`.
    """

    model_config = ConfigDict(extra="forbid")

    origins: list[str] = Field(default_factory=list)
    allow_subdomains: bool = False
    deny_substrings: list[str] = Field(default_factory=list)
    # None means the operator did not impose a path-depth limit; no default
    # depth is imposed by the protocol.
    max_depth: Optional[int] = None


class CaptureRules(BaseModel):
    """Response-direction (`RunCreateResponse.capture`): see
    `RunCreateResponse` for why this gets `extra="forbid"`."""

    model_config = ConfigDict(extra="forbid")

    html_sample_bytes: int = 24000
    text_sample_bytes: int = 8000
    body_sample_bytes: int = 8000
    max_links: Optional[int] = None
    max_forms: Optional[int] = None
    # None means enumerate every discovered control. This is observation
    # metadata, not a run budget.
    max_actions: Optional[int] = Field(default=None, ge=1)
    max_network_events: int = 200
    max_console_events: int = 60
    screenshots: bool = True


class AgentCapabilities(BaseModel):
    playwright: bool = True
    browser: str = "chromium"
    headless: bool = True
    can_probe_http: bool = True
    can_screenshot: bool = True
    secondary_session: bool = False


# A directive value equal to this is not a value: it is an instruction to the
# agent to substitute a secret it holds locally and the engine never sees.
# Anything the engine never receives cannot leak from its storage, logs or
# reports, which is a stronger guarantee than redaction on the way out.
SECRET_PREFIX = "\x00sekuscan-secret:"
SECRET_PASSWORD = SECRET_PREFIX + "password\x00"
# A static second-factor value (a backup code, or a code copied from an
# authenticator app for the run's duration) is a credential like the password.
# It travels as a handle too: the agent holds the real value and substitutes
# it at fill time; the engine never receives, stores or renders the code.
SECRET_MFA_CODE = SECRET_PREFIX + "mfa_code\x00"


# "Leave whatever the DOM already has in this field." A hidden anti-CSRF token
# is both a secret the engine should not see and a value the form will not
# submit without; a redacted placeholder typed into the field would make the
# application reject the submission.
PRESERVE_DOM_VALUE = "\x00sekuscan-preserve\x00"


def is_preserve(value: Any) -> bool:
    return value == PRESERVE_DOM_VALUE


# A value the agent read from a page (see `CaptureFrom` below) and
# substituted into the same directive's own body/header values; never a
# literal the engine sent.
CAPTURE_PLACEHOLDER = "\x00sekuscan-captured\x00"
#: A cookie NAME the agent will put on the wire (RFC 6265 token). The engine
#: declines a probe outside it up front; the agent refuses it at send time.
COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")


def secret_handle(name: str) -> str:
    return "%s%s\x00" % (SECRET_PREFIX, name)


def secret_name(value: str) -> Optional[str]:
    """The secret this value stands for, or None if it is a literal."""
    if isinstance(value, str) and value.startswith(SECRET_PREFIX) \
            and value.endswith("\x00"):
        return value[len(SECRET_PREFIX):-1]
    return None


class Credentials(BaseModel):
    """Login material for the run, minus the secret itself.

    `password` carries a handle (`SECRET_PASSWORD`), never the password. The
    agent keeps the real value in its own process and substitutes it when it
    fills the form.
    """

    username: str
    password: str = SECRET_PASSWORD
    login_url: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    extra: dict[str, str] = Field(default_factory=dict)
    # A static operator-supplied second-factor value (a backup code, or a
    # code copied from an authenticator app for the run's duration). Never a
    # TOTP secret: the value is submitted as given, no codes are generated.
    mfa_code: Optional[str] = None


class OperatorDatum(BaseModel):
    """One value the operator authorises the scan to use, named exactly.

    The scanner never guesses a business value (a coupon code, a voucher). When
    the application does not volunteer one, the operator may supply it here:
    where it applies (`path`), which field carries it, the value, and the most
    times it may be submitted. It appears in the report.
    """
    path: str = Field(min_length=1, max_length=300, pattern=r"^/")
    field: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=200)
    replays: int = Field(default=2, ge=1, le=5)


class RunCreateRequest(BaseModel):
    target: str
    scope: list[str] = Field(default_factory=list)
    # Optional operator constraint. Absent by default: no path-depth ceiling
    # is imposed.
    max_depth: Optional[int] = Field(default=None, ge=0)
    profile: str = "default"
    # One operator-facing risk dial. Level 1 is read-only, level 2 permits
    # exact application-owned writes and non-GET authorization comparisons,
    # and level 3 additionally enables the bounded upload and command-proof
    # capabilities. The older individual flags remain available and can only
    # raise the effective level.
    risk: int = Field(default=1, ge=1, le=3)
    # Optional cap on the number of actions in a run; normally None. An
    # explicit 0 or negative value is rejected rather than reinterpreted as
    # unlimited, so a `--max-actions 0` typo cannot expand a run's scope.
    max_actions: Optional[int] = Field(default=None, ge=1)
    # Wall-clock allowance for the whole run, in seconds. Absent by default;
    # when it passes, the run ends as an operator stop does and the report
    # says why.
    max_seconds: Optional[int] = Field(default=None, ge=1)
    # Optional observer bound. Omitted means every discovered control on a
    # page is reported; this is not a scan budget.
    capture_max_actions: Optional[int] = Field(default=None, ge=1)
    allow_destructive: bool = False
    # Upload cleanup is a separate permission and requires an exact URL; a
    # delete endpoint is never guessed from an upload response.
    allow_upload_cleanup: bool = False
    upload_cleanup_url: Optional[str] = None
    # Safe GET replay is still an active request. It requires a separate
    # operator opt-in and an exact URL allowlist; idempotence is never inferred
    # from the HTTP verb or a path name.
    allow_safe_get_replay: bool = False
    # Exact in-scope GET URLs observed in traffic for an explicit replay. They
    # are never expanded into other paths or mutated.
    safe_get_urls: list[str] = Field(default_factory=list)
    # Some APIs use POST for a read-only authorization operation. This narrow
    # permission covers only exact observed non-GET authorization comparisons;
    # it does not authorize workflow mutation, uploads, or arbitrary requests.
    allow_authz_non_get: bool = False
    # operator-supplied "do not touch": substrings that put a url out of scope
    deny: list[str] = Field(default_factory=list)
    # Off by default: a `target` or `scope` naming a loopback, link-local,
    # RFC1918 private, or reserved address is refused unless explicitly
    # acknowledged here, so a shared or cloud-adjacent deployment does not
    # fetch its own hosting infrastructure by accident. An operator who means
    # to scan an internal or staging application says so.
    allow_internal_targets: bool = False
    # Operator-supplied test data (see `OperatorDatum`): at most a handful.
    test_data: list[OperatorDatum] = Field(default_factory=list, max_length=16)
    credentials: Optional[Credentials] = None
    # The agent may hold a second, operator-supplied session locally for
    # read-only access-control comparisons. Only this boolean is sent to the
    # engine; the cookies and headers never enter the protocol.
    secondary_session: bool = False
    # The agent already holds a primary session the operator supplied (a
    # `--cookie`, `--bearer`, `--header`, or a JSON `--login-body` that
    # succeeded). Only this boolean crosses the protocol, as with
    # `secondary_session`: the cookie or token stays in the agent's process.
    # It lets the engine know the run is authenticated even though it did not
    # direct the login.
    preset_session: bool = False
    # An operator-supplied login the agent will attempt rather than one it
    # already holds (for example a JSON `--login-body`, which can fail).
    # Kept separate from `preset_session` so that a session the agent does not
    # have is never claimed as established.
    pending_session: bool = False
    agent_version: str = AGENT_VERSION
    protocol_version: str = PROTOCOL_VERSION
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    labels: dict[str, str] = Field(default_factory=dict)


class RunCreateResponse(BaseModel):
    """Engine -> agent. This, `StepResponse`, `CompleteResponse` and
    `StopResponse` (plus what they nest: `ScopeRules`, `CaptureRules`,
    `Directive`, `CaptureFrom`, `RunProgress`) are the response-direction half
    of the wire protocol: built by the engine from its own field names, never
    parsed from an external dict. `extra="forbid"` on this half makes a field
    the model does not declare an error instead of being silently dropped.

    The agent parses these, so an agent running this code against a newer
    engine that adds another field would raise on the extra key. That is an
    accepted cost of an evolving response schema in a single-vendor protocol.

    The other half (`RunCreateRequest`, `Observation`, `CompleteRequest`,
    `StopRequest` and everything they nest) is agent-constructed and
    engine-parsed. It deliberately does NOT get `extra="forbid"`: the agent
    runs on the customer's network and may lag the engine, so a newer agent
    sending one more field than an older engine knows about must degrade to
    "the engine ignores it", never "the engine rejects the whole step".
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str
    run_token: str
    token_expires_in: int
    engine_version: str = ENGINE_VERSION
    protocol_version: str = PROTOCOL_VERSION
    scope: ScopeRules
    capture: CaptureRules
    # None means unlimited; a value is present only when the operator supplied
    # an explicit action limit.
    safety_ceiling: Optional[int] = None
    profile: str
    risk: int = 1
    features: dict[str, bool] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# observations (agent -> engine)
# --------------------------------------------------------------------------


class InputSpec(BaseModel):
    name: Optional[str] = None
    dom_id: Optional[str] = None
    type: str = "text"
    value_sample: Optional[str] = None
    placeholder: Optional[str] = None
    required: bool = False
    accept: Optional[str] = None
    hidden: bool = False
    readonly: bool = False
    maxlength: Optional[int] = None
    options: list[str] = Field(default_factory=list)


class SubresourceSpec(BaseModel):
    """One `<script src>` or `<link rel=stylesheet>` as the DOM declares it.

    `script_srcs` carries the URLs. Whether the tag pins a hash (`integrity`)
    is an attribute of the tag, so it is reported separately; this is
    mechanical observation.
    """
    tag: str = "script"
    url: str = ""
    integrity: Optional[str] = None
    crossorigin: Optional[str] = None


class FormSpec(BaseModel):
    ref: str
    action: Optional[str] = None
    method: str = "get"
    # Did the author write `method=`, or is "get" above merely the HTML
    # default? A `<form>` with no method is typically submitted by JavaScript,
    # so nothing is placed in a query string, while a form that declares
    # `method="get"` would put its fields there.
    #
    # Defaults True so that a producer which does not set it keeps the more
    # conservative behaviour.
    method_declared: bool = True
    enctype: Optional[str] = None
    name: Optional[str] = None
    dom_id: Optional[str] = None
    inputs: list[InputSpec] = Field(default_factory=list)
    submit_selector: Optional[str] = None
    # True when there is no `<form>`: loose inputs grouped with the control
    # that acts on them. It has no action or method of its own (the request is
    # whatever the application's script sends), so it is driven by filling the
    # fields and pressing the control, never by submitting a form.
    synthetic: bool = False


class ActionSpec(BaseModel):
    ref: str
    kind: str = "link"  # link | button | submit | input | control
    text: str = ""
    href: Optional[str] = None
    disabled: bool = False
    # A control in a pane that is not open. It is in the document and has a
    # handler, but cannot be pressed. Cleared when an observation finds it
    # visible.
    hidden: bool = False


class AnchorSpec(BaseModel):
    """A rendered link whose navigation attributes affect browser safety."""
    href: str = ""
    target: Optional[str] = None
    rel: Optional[str] = None
    text: Optional[str] = None


class CookieSpec(BaseModel):
    name: str
    domain: Optional[str] = None
    path: Optional[str] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    expires: Optional[float] = None
    value_len: int = 0
    value_shape: Optional[str] = None
    value_preview: Optional[str] = None  # JWT header.claims only, never a secret
    # A truncated one-way hash of the value, so two values can be compared
    # without sending the value itself. Not reversible; not the credential.
    value_fingerprint: Optional[str] = None
    # This scanner's own `sks...` tokens found in this cookie's value, and
    # nothing else. Cookie values are redacted; these tokens are generated by
    # this scanner, contain no application data, and are already printed in
    # reports.
    carries_markers: list[str] = Field(default_factory=list)


class NetworkEvent(BaseModel):
    method: str = "GET"
    url: str = ""
    status: Optional[int] = None
    resource_type: Optional[str] = None
    mime: Optional[str] = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    # Added alongside `response_headers`, never replacing it. A response with
    # two `Set-Cookie` headers collapses to the last one in a name-keyed map,
    # because the underlying header maps combine repeated names. Empty on an
    # older agent; a reader should fall back to
    # `response_headers['set-cookie']` when this is empty.
    set_cookie: list[str] = Field(default_factory=list)
    request_body_sample: Optional[str] = None
    # Binary request bodies are carried as base64 across the JSON wire. Text
    # bodies keep the historical None value.
    request_body_encoding: Optional[str] = None
    request_body_length: Optional[int] = None
    request_body_truncated: bool = False
    response_body_sample: Optional[str] = None
    response_length: Optional[int] = None
    elapsed_ms: Optional[int] = None
    failure: Optional[str] = None
    is_document: bool = False
    # Set only on the agent's synthetic event for an explicitly supplied
    # login that returned a fresh session cookie. It is set by the agent from
    # what it observed, never from a page label.
    authenticated: bool = False


class ConsoleEvent(BaseModel):
    type: str = "log"
    text: str = ""
    location: Optional[str] = None


class StateSnapshot(BaseModel):
    requested_url: Optional[str] = None
    url: str = ""
    http_status: Optional[int] = None
    title: Optional[str] = None
    dom_signature: Optional[str] = None
    text_hash: Optional[str] = None
    text_sample: str = ""
    text_length: int = 0
    html_sample: str = ""
    html_length: int = 0
    visible_text_length: int = 0
    links: list[str] = Field(default_factory=list)
    anchors: list[AnchorSpec] = Field(default_factory=list)
    forms: list[FormSpec] = Field(default_factory=list)
    actions: list[ActionSpec] = Field(default_factory=list)
    cookies: list[CookieSpec] = Field(default_factory=list)
    script_srcs: list[str] = Field(default_factory=list)
    subresources: list[SubresourceSpec] = Field(default_factory=list)
    # How many the page had, against however many the arrays above carry.
    # Same contract as `text_length` beside `text_sample`: the sample is
    # bounded, and the size it was drawn from is reported.
    dom_nodes_total: int = 0
    anchors_total: int = 0
    script_srcs_total: int = 0
    subresources_total: int = 0
    inline_script_sample: str = ""
    meta: dict[str, str] = Field(default_factory=dict)
    load_error: Optional[str] = None
    blank: bool = False


class ProbeResponse(BaseModel):
    url: str = ""
    status: Optional[int] = None
    # the exchange as text, redacted
    raw_request: str = ""
    raw_response: str = ""
    ok: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    # Added alongside `headers`. Wire contract: never change its type; an
    # older engine reading a newer agent must keep working.
    #
    # `headers` is `dict[str, str]`, so a response setting more than one
    # `Set-Cookie` collapses to the last one. `Set-Cookie` is the one header
    # that repeats in practice, so it alone gets a list field.
    #
    # Empty on an older agent, or when a response set at most one cookie; a
    # reader must not treat "empty" as "no cookie was set" and should fall
    # back to `headers['set-cookie']`.
    set_cookie: list[str] = Field(default_factory=list)
    body_sample: str = ""
    body_length: int = 0
    # The whole redacted body, zlib-compressed and base64-encoded.
    #
    # `raw_response` above is capped at a few KB of body. For pages over a
    # couple of KB this compressed form is smaller on the wire than that
    # truncated prefix. Redaction happens on the agent before this is built;
    # nothing unredacted crosses to the engine.
    body_z: str = ""
    # A float, not an int, so sub-millisecond durations are kept.
    elapsed_ms: Optional[float] = None
    error: Optional[str] = None
    redirect_location: Optional[str] = None


class ActionResult(BaseModel):
    directive_id: Optional[str] = None
    kind: Optional[str] = None
    ok: bool = True
    error: Optional[str] = None
    elapsed_ms: Optional[int] = None
    refused_reason: Optional[str] = None
    detail: dict[str, Any] = Field(default_factory=dict)


class BatchedResult(BaseModel):
    """One directive's outcome inside a batch response. `action_result`
    carries `directive_id`, which is the only correlation a batch needs."""
    action_result: ActionResult
    probe: Optional[ProbeResponse] = None


class Observation(BaseModel):
    seq: int = 0
    phase_hint: str = "step"
    state: Optional[StateSnapshot] = None
    probe: Optional[ProbeResponse] = None
    action_result: Optional[ActionResult] = None
    # A batch dispatch (see `StepResponse.directives`) posts every member's
    # result here instead of one call per directive. `probe`/`action_result`
    # above stay populated with the first result, so an older engine that only
    # reads the singular fields still sees a coherent observation.
    batch: list[BatchedResult] = Field(default_factory=list)
    network: list[NetworkEvent] = Field(default_factory=list)
    console: list[ConsoleEvent] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    agent_notes: list[str] = Field(default_factory=list)
    # Set by the agent only for a state it captured before its own
    # (agent-held) login ran. Never derived from anything the target returned:
    # only the agent can know an observation predates its own authentication,
    # and an older agent never sets it. Everything else observed while holding
    # a session is treated as authenticated.
    pre_auth: bool = False
    # The agent can hold one batch ahead (`StepResponse.ahead`) and run it
    # while this observation is absorbed. An older agent never sets it and is
    # never sent `ahead`.
    pipeline: bool = False


# --------------------------------------------------------------------------
# directives (engine -> agent)
# --------------------------------------------------------------------------


class CaptureFrom(BaseModel):
    """A value the AGENT reads from a page and replays into this same
    directive's own body/headers, without the engine ever seeing it.

    This does for a hand-built raw request what `PRESERVE_DOM_VALUE` does for a
    live form field (for example a hidden anti-CSRF token the engine must not
    see and the application will not accept back if redacted): `url` is
    fetched with a plain GET (through the same request context and cookies the
    main directive uses, so an anonymous session stays anonymous and a primary
    one stays authenticated), `pattern` is applied to that page's body, and
    group `group` of the first match replaces every occurrence of
    `CAPTURE_PLACEHOLDER` (defined above) in this directive's own `body` and
    header VALUES before the main request goes out. When `cookie_name` is set,
    the agent reads that named cookie from its local browser storage state
    instead of fetching `url`; this is the safe path for a redacted session
    cookie. The captured value and the capture page's own response are never
    reported back to the engine, only the main request's result.

    Response-direction (nested in `Directive`): see `RunCreateResponse` for
    why this gets `extra="forbid"`.
    """

    model_config = ConfigDict(extra="forbid")

    url: str
    pattern: str
    group: int = 1
    cookie_name: Optional[str] = None


class Directive(BaseModel):
    """Engine -> agent. Response-direction: see `RunCreateResponse` for why
    this gets `extra="forbid"`."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: DirectiveKind
    reason: str = ""
    # navigate / probe_http
    url: Optional[str] = None
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    # "base64" means the body is decoded to bytes by the agent immediately
    # before transmission.
    body_encoding: Optional[str] = None
    max_redirects: Optional[int] = None
    # click / fill_submit
    selector: Optional[str] = None
    values: dict[str, str] = Field(default_factory=dict)
    # May add one bounded, operator-authorized field that the observed form
    # did not advertise. Ordinary form directives leave this empty.
    extra_values: dict[str, str] = Field(default_factory=dict)
    submit_selector: Optional[str] = None
    # Overrides the live form's method only when explicitly permitted.
    # Ordinary fill_submit directives leave this unset and use the document's
    # own method.
    form_method: Optional[str] = None
    # misc
    name: Optional[str] = None
    wait_ms: int = 0
    screenshot: bool = False
    capture_state: bool = True
    score: Optional[int] = None
    probe_id: Optional[str] = None
    # carries credentials: the agent may use it, nobody may log it
    sensitive: bool = False
    # send without the session (fresh context, no cookies, no auth header)
    anonymous: bool = False
    # `primary` is the normal authenticated browser session. `secondary` is an
    # optional operator-supplied session used only for bounded GET comparison.
    auth_profile: str = "primary"
    # Automatic narrow transport for a literal-query parser boundary probe.
    raw_query: bool = False
    # safe GET in the live page context, so application-managed auth state can
    # participate without exposing the token to the engine
    browser_context: bool = False
    # A `navigate` with the page's CSP not enforced, for this one navigation
    # only; it is switched back afterwards.
    bypass_csp: bool = False
    # some documents are only useful whole: specs, sitemaps, js bundles
    max_body_bytes: Optional[int] = None
    # A per-directive transport deadline, for a request that is expected to
    # take longer than the default timeout.
    timeout_ms: Optional[int] = None
    # upload_file - only the fixed benign probe file generated for the run
    file_index: int = 0
    file_name: Optional[str] = None
    file_content: Optional[str] = None
    file_mime: str = "text/plain"
    # A transport upload: the engine names a fixture and the agent builds it.
    #
    # The `upload_file` path sends `file_content` and has the agent compare it
    # byte for byte, because the engine is not a trust boundary. Naming the
    # fixture instead means the bytes never cross the wire. The fixtures are
    # defined only in the agent (`agent/execute.UPLOAD_FIXTURES`).
    #
    # It also covers upload endpoints that no rendered form reaches, where
    # the browser-driven path has no form to drive.
    upload_fixture: Optional[str] = None
    upload_field: str = "file"
    #: The run's own `sks` token, the only part of a fixture that varies.
    upload_marker: Optional[str] = None
    #: Sent as the multipart filename, from a closed set the agent re-checks.
    upload_filename: Optional[str] = None
    #: Pad the named fixture to this size. The agent generates the filler
    #: and caps it; see `agent/execute.MAX_UPLOAD_FILL_BYTES`.
    upload_fill_bytes: Optional[int] = None
    # set_cookie - same-origin, browser-only
    cookie_name: Optional[str] = None
    cookie_value: Optional[str] = None
    cookie_path: str = "/"
    #: Put this cookie back to the value it had before this run first
    #: overrode it: a value only the agent knows, so it is never on the
    #: wire. `cookie_value` is the fallback when the agent has no snapshot.
    cookie_restore: bool = False
    # An exclusive directive is not dispatched concurrently with another
    # exclusive one. Carried on the wire so a batching agent can enforce it;
    # a non-batching agent ignores it safely, since it already dispatches one
    # directive at a time.
    exclusive: bool = False
    # What the directive declares it does: "read" changes no server state
    # whatever the HTTP method carries it (a GraphQL query, a REST batch, a
    # JSON search body). The agent's local risk gate honors a declared read
    # instead of refusing every non-GET method outright.
    effect: str = "read"
    # See `CaptureFrom`: a value the agent reads from a page and substitutes
    # into this directive's own body/headers, never surfaced to the engine.
    capture_from: Optional[CaptureFrom] = None
    # A named exemption from the operator's deny substrings, for this
    # directive alone. Origin, scheme and depth are unaffected.
    deny_exemption: Optional[str] = None


class RunProgress(BaseModel):
    """Engine -> agent. Response-direction: see `RunCreateResponse` for why
    this gets `extra="forbid"`."""

    model_config = ConfigDict(extra="forbid")

    phase: str = "explore"
    auth_state: Optional[str] = None
    actions_used: int = 0
    safety_ceiling: Optional[int] = None
    states: int = 0
    surfaces: int = 0
    findings: int = 0
    pending_probes: int = 0


#: `Directive.reason` of a pipeline hold: the engine absorbed the observation
#: and has nothing new to send; the agent runs what it holds and reports that.
PIPE_HOLD = "pipeline-hold"


class StepResponse(BaseModel):
    """Engine -> agent. Response-direction: see `RunCreateResponse` for why
    this gets `extra="forbid"`."""

    model_config = ConfigDict(extra="forbid")

    # `directive` is always `directives[0]`, kept as its own required field
    # so code that only reads the singular directive keeps working.
    # `directives` is the authoritative list: length 1 in the ordinary case,
    # length N for a batch of independent probe_http directives that are safe
    # to run concurrently. A non-batching agent can ignore `directives` and
    # only ever see `directive`.
    directive: Directive
    directives: list[Directive] = Field(default_factory=list)
    # Pipelining (`Observation.pipeline`): a second batch the agent runs
    # right after `directives`, posting their observation meanwhile. Omitted
    # from the wire when empty, so an older agent never sees it.
    ahead: list[Directive] = Field(default_factory=list)
    progress: RunProgress
    notes: list[str] = Field(default_factory=list)


class CompleteRequest(BaseModel):
    """Agent -> engine. Deliberately NOT `extra="forbid"`: see
    `RunCreateResponse` for why the agent-sent half of the wire protocol stays
    permissive."""

    reason: str = "agent-finished"
    artifacts: list[str] = Field(default_factory=list)


class CompleteResponse(BaseModel):
    """Engine -> agent. Response-direction: see `RunCreateResponse` for why
    this gets `extra="forbid"`.

    A run that completes with unfinished work must be distinguishable from a
    clean one, so the coverage fields (`coverage_complete`, `termination`,
    `pending_probes`) are declared here; `extra="forbid"` turns an undeclared
    field into an error instead of silent data loss.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str
    # "completed" or "partial": a run that was cut off is not a clean run,
    # and the difference has to survive the API, not just the HTML report
    status: str
    # Raw signal counts, before consolidation into one issue per weakness.
    # Retained for compatibility: an existing consumer reading
    # `findings`/`candidates` sees what it always has. A consumer that wants
    # the number of distinct weaknesses should read `vulnerabilities` and its
    # siblings below instead.
    findings: int
    candidates: int
    report_json_url: str
    report_html_url: str
    # Same concepts `StopResponse` carries below, under the same names: a scan
    # that explored everything and one cut off mid-budget must not both read
    # as "0 findings" with no further signal.
    coverage_complete: bool = True
    termination: str = "finished"
    pending_probes: int = 0
    # Consolidated issue counts, as listed in the report's buckets.
    vulnerabilities: int = 0
    needs_validation: int = 0
    observations: int = 0
    diagnostics: int = 0
    # `findings + candidates`, so a caller need not add the two compatibility
    # fields itself to get the raw signal total.
    raw_signals: int = 0


class StopRequest(BaseModel):
    """Agent (or any caller with the run's token/API key) -> engine.
    Deliberately NOT `extra="forbid"`: see `RunCreateResponse` for why the
    agent-sent half of the wire protocol stays permissive."""

    reason: str = ""


class StopResponse(BaseModel):
    """Engine -> agent. Response-direction: see `RunCreateResponse` for why
    this gets `extra="forbid"`."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    # "stopping" (a running scan was flagged; it stops on its next step) or
    # the run's existing terminal status - asking twice, or asking after
    # the scan finished on its own, is not an error.
    status: str
    coverage_complete: bool = True
    termination: str = "finished"
    pending_probes: int = 0
