# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Pipeline-facing behaviour: credential sources, gating, baselines.

This module holds the parts a CI job needs:

  * credentials from env vars or a file, never only from argv (argv is visible
    in `ps` on a shared runner);
  * a session handoff path - cookie, bearer token or arbitrary header - for
    pipelines that already authenticated and just want the scan;
  * an exit code that means something, gated on severity;
  * a baseline, so a build fails on *new* findings rather than on the backlog
    it inherited.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

ENV_USERNAME = "SEKUSCAN_USERNAME"
ENV_PASSWORD = "SEKUSCAN_PASSWORD"
# Every credential, including the login URL they are posted to, can come from
# the environment, so nothing sensitive has to go on the command line.
ENV_LOGIN_URL = "SEKUSCAN_LOGIN_URL"
ENV_ADDITIONAL_LOGIN_URLS = "SEKUSCAN_ADDITIONAL_LOGIN_URLS"
ENV_MFA_CODE = "SEKUSCAN_MFA_CODE"
ENV_USERNAME2 = "SEKUSCAN_USERNAME2"
ENV_PASSWORD2 = "SEKUSCAN_PASSWORD2"
ENV_LOGIN_URL2 = "SEKUSCAN_LOGIN_URL2"
ENV_ADDITIONAL_LOGIN_URLS2 = "SEKUSCAN_ADDITIONAL_LOGIN_URLS2"
ENV_API_KEY = "SEKUSCAN_API_KEY"
ENV_COOKIE = "SEKUSCAN_COOKIE"
ENV_BEARER = "SEKUSCAN_BEARER"
# The third session-handoff form (an arbitrary header). `;;` separates several,
# as with ENV_COOKIE.
ENV_HEADER = "SEKUSCAN_HEADER"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


@dataclass
class AuthInput:
    """Everything the operator can hand us to get inside."""

    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None
    cookies: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    bearer: Optional[str] = None
    mfa_code: Optional[str] = None
    #: A JSON credential document to POST, instead of filling a form.
    #: Single-page applications log in this way and frequently render no
    #: form for the agent to find.
    login_body: Optional[str] = None
    #: URL-encoded form fields to POST to an API login endpoint. Unlike
    #: `login_body`, this is a JSON object describing form fields and is
    #: encoded by the agent's request client.
    login_fields: Optional[str] = None
    #: Additional API login endpoints for applications that expose one
    #: session cookie per module or tenant. They reuse the same explicit
    #: field template and credentials, and are attempted only after the
    #: primary login succeeds.
    additional_login_urls: list[str] = field(default_factory=list)
    #: Additional primary login profiles for applications whose endpoints
    #: use different request shapes or identities. Each item is a small
    #: operator-supplied object with `url`, `username`, `password`, and one of
    #: `body` or `fields`; secrets are consumed by the agent only.
    additional_logins: list[dict[str, str]] = field(default_factory=list)

    @property
    def has_form_login(self) -> bool:
        return bool(self.username and self.password and not self.login_body
                    and not self.login_fields)

    @property
    def has_json_login(self) -> bool:
        return bool(self.login_url and self.login_body)

    @property
    def has_form_fields_login(self) -> bool:
        return bool(self.login_url and self.login_fields)

    @property
    def has_session(self) -> bool:
        return bool(self.cookies or self.headers or self.bearer)

    def describe(self) -> str:
        parts = []
        if self.has_form_login:
            parts.append(f"form login as `{self.username}`")
        if self.mfa_code:
            parts.append("second-factor code supplied")
        if self.cookies:
            parts.append(f"{len(self.cookies)} cookie(s)")
        if self.bearer:
            parts.append("bearer token")
        if self.headers:
            parts.append(f"{len(self.headers)} header(s)")
        return ", ".join(parts) or "anonymous"



#: Prefix marking a credential that must be FETCHED rather than read.
SECRET_COMMAND_PREFIX = "cmd:"

#: A vault CLI that hangs must not wedge the scan behind it.
SECRET_COMMAND_TIMEOUT_S = 30


class SecretResolutionError(RuntimeError):
    """A `cmd:` credential could not be fetched.

    Deliberately fatal rather than falling back to "no credential". A scan
    that silently proceeds unauthenticated would report a clean result for
    everything behind the login, so a vault that is down stops the run
    instead.
    """


#: A credential is short. Anything past this from a `cmd:` command is a
#: misconfiguration printing at us, not a secret - see `_run_bounded`.
SECRET_MAX_BYTES = 64 * 1024


class _Completed:
    """The two fields `resolve_secret` reads off `subprocess.run`."""

    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _run_bounded(argv: list[str], timeout_s: float) -> "_Completed":
    """`subprocess.run(capture_output=True)` with a ceiling on the OUTPUT.

    The stock call bounds only TIME. This bounds bytes as well, and kills the
    child when it exceeds them rather than reading on to the timeout.
    """
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    return _Completed(proc.returncode,
                      (out or "")[:SECRET_MAX_BYTES],
                      (err or "")[:SECRET_MAX_BYTES])


def resolve_secret(value: Optional[str]) -> Optional[str]:
    """Resolve one credential, fetching it from a vault if it says to.

    A value of `cmd:<argv>` means "run this and use its stdout". That IS the
    external-secrets integration, and it is deliberately not a vendor SDK:
    every secret manager worth naming already ships a CLI that prints one
    secret to stdout, so one indirection covers all of them and adds no
    dependency -

        cmd:vault kv get -field=password secret/scan
        cmd:op read op://vault/scan-user/password
        cmd:aws secretsmanager get-secret-value --secret-id scan \
            --query SecretString --output text
        cmd:gcloud secrets versions access latest --secret=scan

    - and it composes with the existing precedence untouched, so the command
    can arrive by flag, by `--auth-file`, or by environment variable.

    Parsed with `shlex.split` and executed WITHOUT a shell: an operator
    supplies this string, but a vault path interpolated into it by a
    pipeline is data, and `shell=True` would make that data executable. A
    command genuinely needing a pipeline can point at a wrapper script.

    `stdout` is stripped of ONE trailing newline only (`rstrip("\n")`, not
    `.strip()`): a password may legitimately begin or end with a space, and
    silently trimming it turns a working credential into a login failure
    that looks like wrong credentials.
    """
    if not value or not value.startswith(SECRET_COMMAND_PREFIX):
        return value
    argv_text = value[len(SECRET_COMMAND_PREFIX):].strip()
    if not argv_text:
        raise SecretResolutionError("empty %s credential command"
                                    % SECRET_COMMAND_PREFIX)
    try:
        argv = shlex.split(argv_text)
    except ValueError as exc:
        raise SecretResolutionError("unparseable credential command: %s" % exc)
    if not argv:
        raise SecretResolutionError("empty %s credential command"
                                    % SECRET_COMMAND_PREFIX)
    try:
        # `capture_output=True` would buffer all output in memory, and the
        # timeout bounds only how long a command runs, not how much it
        # emits. The output is read with a ceiling instead: a secret needs no
        # more than `SECRET_MAX_BYTES`, and anything past that is a
        # misconfigured command, not a credential.
        done = _run_bounded(argv, SECRET_COMMAND_TIMEOUT_S)
    except FileNotFoundError:
        raise SecretResolutionError("credential command not found: %s" % argv[0])
    except subprocess.TimeoutExpired:
        raise SecretResolutionError(
            "credential command timed out after %ds: %s"
            % (SECRET_COMMAND_TIMEOUT_S, argv[0]))
    if done.returncode != 0:
        # stderr, never stdout: on failure stdout may still hold a partial
        # secret, and this string reaches logs.
        raise SecretResolutionError(
            "credential command failed (exit %d): %s: %s"
            % (done.returncode, argv[0], (done.stderr or "").strip()[:200]))
    secret = (done.stdout or "").rstrip("\n")
    if not secret:
        raise SecretResolutionError(
            "credential command produced nothing: %s" % argv[0])
    return secret


def resolve_auth(username: Optional[str], password: Optional[str],
                 login_url: Optional[str], auth_file: Optional[str],
                 cookies: Optional[list[str]] = None,
                 headers: Optional[list[str]] = None,
                 bearer: Optional[str] = None,
                 mfa_code: Optional[str] = None,
                 login_body: Optional[str] = None,
                 login_fields: Optional[str] = None,
                 additional_login_urls: Optional[list[str]] = None,
                 additional_logins: Optional[str] = None) -> AuthInput:
    """Flags win, then the auth file, then environment variables."""
    data: dict[str, Any] = {}
    if auth_file:
        # A missing, unreadable or malformed `--auth-file` is reported as an
        # operator error naming the file, not as a traceback. It is raised as
        # `SecretResolutionError`, which the CLI already renders that way.
        try:
            with open(auth_file, encoding="utf-8") as fh:
                data = json.load(fh) or {}
        except OSError as exc:
            raise SecretResolutionError(
                "could not read --auth-file %s: %s" % (auth_file, exc))
        except ValueError as exc:
            raise SecretResolutionError(
                "--auth-file %s is not valid JSON: %s" % (auth_file, exc))
        if not isinstance(data, dict):
            raise SecretResolutionError(
                "--auth-file %s must contain a JSON object" % auth_file)

    def pick(flag: Optional[str], key: str, env: Optional[str]) -> Optional[str]:
        # `resolve_secret` wraps the whole precedence, so a `cmd:` reference
        # works identically whether it arrived by flag, by --auth-file or from
        # the environment.
        if flag:
            return resolve_secret(flag)
        if data.get(key):
            return resolve_secret(str(data[key]))
        return resolve_secret(os.environ.get(env)) if env else None

    raw_logins = additional_logins or data.get("additional_logins")
    parsed_logins: list[dict[str, str]] = []
    if raw_logins:
        try:
            documents = json.loads(raw_logins) if isinstance(raw_logins, str) \
                else raw_logins
        except (TypeError, ValueError):
            documents = []
        if isinstance(documents, list):
            for document in documents:
                if not isinstance(document, dict) or not document.get("url"):
                    continue
                parsed = {}
                for key in ("url", "username", "password", "body", "fields"):
                    if document.get(key) is not None:
                        parsed[key] = resolve_secret(str(document[key]))
                if ("body" in parsed) != ("fields" in parsed):
                    parsed_logins.append(parsed)

    out = AuthInput(
        username=pick(username, "username", ENV_USERNAME),
        password=pick(password, "password", ENV_PASSWORD),
        login_url=pick(login_url, "login_url", ENV_LOGIN_URL),
        bearer=pick(bearer, "bearer", ENV_BEARER),
        cookies=_resolve_pairs(
            list(cookies or []) or _as_list(data.get("cookies")) or
            _as_list(os.environ.get(ENV_COOKIE))),
        headers=_resolve_pairs(
            list(headers or []) or _as_list(data.get("headers")) or
            _as_list(os.environ.get(ENV_HEADER))),
        mfa_code=pick(mfa_code, "mfa_code", ENV_MFA_CODE),
        login_body=pick(login_body, "login_body", None),
        login_fields=pick(login_fields, "login_fields", None),
        additional_login_urls=(list(additional_login_urls or []) or
                               _as_list(data.get("additional_login_urls")) or
                               _as_list(os.environ.get(ENV_ADDITIONAL_LOGIN_URLS))),
        additional_logins=parsed_logins,
    )
    return out


def resolve_secondary_auth(username: Optional[str], password: Optional[str],
                           login_url: Optional[str],
                           login_fields: Optional[str] = None,
                           additional_login_urls: Optional[list[str]] = None
                           ) -> AuthInput:
    """Resolve the opt-in second identity without inheriting primary auth."""
    # The second identity resolves vault references too, so that it does not
    # silently fail to authenticate.
    return AuthInput(
        username=resolve_secret(username or os.environ.get(ENV_USERNAME2)),
        password=resolve_secret(password or os.environ.get(ENV_PASSWORD2)),
        login_url=resolve_secret(login_url or os.environ.get(ENV_LOGIN_URL2)),
        login_fields=resolve_secret(login_fields),
        additional_login_urls=[resolve_secret(url) or "" for url in
                               (list(additional_login_urls or []) or
                                _as_list(os.environ.get(
                                    ENV_ADDITIONAL_LOGIN_URLS2))) if url],
    )


def _as_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(";;") if v.strip()]
    if isinstance(value, dict):
        return [f"{k}={v}" for k, v in value.items()]
    return [str(v) for v in value]


def _resolve_pairs(items: list[str]) -> list[str]:
    """Resolve a vault reference on the VALUE half of `name=value` entries.

    A bearer token or session cookie is exactly the kind of credential a
    vault holds, and these arrive as joined pairs rather than bare values,
    so the split has to happen before the lookup. The name half is never
    treated as a reference: `cmd:` in a cookie NAME is a cookie called
    `cmd:`, not an instruction.
    """
    out = []
    for item in items:
        name, sep, value = item.partition("=")
        if sep:
            out.append(name + sep + (resolve_secret(value) or ""))
        else:
            out.append(resolve_secret(item) or "")
    return out


def parse_pairs(items: list[str], separator: str = "=") -> dict[str, str]:
    """`name=value` / `Header: value` strings into a dict."""
    out: dict[str, str] = {}
    for item in items or []:
        if separator in item:
            name, _, value = item.partition(separator)
        elif ":" in item:
            name, _, value = item.partition(":")
        else:
            continue
        name, value = name.strip(), value.strip()
        if name:
            out[name] = value
    return out


# --------------------------------------------------------------------------
# gating
# --------------------------------------------------------------------------


log = logging.getLogger(__name__)


def _read_report(path: str) -> Optional[dict[str, Any]]:
    """A previous report, or None when it cannot be read.

    A truncated or hand-edited baseline (for instance from a killed CI job)
    must not turn a completed scan into a traceback. An unreadable baseline
    degrades to "no baseline", as a missing file does, and says so; silently
    gating against an empty baseline would report every existing finding as
    new.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        log.warning("baseline %s could not be read (%s) - continuing without "
                    "it; every finding will be treated as new", path, exc)
        return None
    if not isinstance(data, dict):
        log.warning("baseline %s is not a report object - continuing without "
                    "it", path)
        return None
    return data


def load_baseline(path: Optional[str]) -> set[str]:
    """Issue identities from a previous report, so CI only fails on new ones."""
    if not path or not os.path.isfile(path):
        return set()
    data = _read_report(path)
    if data is None:
        return set()
    known: set[str] = set()
    for item in (data.get("issues") or data.get("all_findings") or []):
        known.add(identity(item))
    return known


def identity(finding: dict[str, Any]) -> str:
    """Stable across runs: ignores per-run parameter values.

    Uses the report's `issue_id` when present; otherwise it keys on check,
    title and target with the query-string values removed.
    """
    import re

    if finding.get("issue_id"):
        return str(finding["issue_id"])
    target = re.sub(r"[?&][^=]+=[^&]*", "", str(finding.get("target") or ""))
    return "|".join([str(finding.get("check_id") or
                         ",".join(finding.get("checks") or [])),
                     str(finding.get("title") or ""), target])


# --------------------------------------------------------------------------
# diff-against-last-scan
# --------------------------------------------------------------------------


def _diff_summary(finding: dict[str, Any]) -> dict[str, Any]:
    return {"issue_id": identity(finding), "title": finding.get("title"),
            "severity": finding.get("severity"), "kind": finding.get("kind"),
            "vuln_class": finding.get("vuln_class"), "target": finding.get("target"),
            "param": finding.get("param") or ""}


#: Reach metrics from `report.summary.explored`: how much the run looked at,
#: as opposed to what it found. A scan that reached fewer of these tested
#: less, so a "fixed" issue may merely be unreached.
_COVERAGE_METRICS = ("unique_paths", "surfaces", "surfaces_exercised",
                     "probe_groups", "probes_sent", "network_requests")


def _coverage_of(report: dict[str, Any]) -> dict[str, int]:
    explored = ((report.get("summary") or {}).get("explored")) or {}
    return {metric: int(explored.get(metric) or 0) for metric in _COVERAGE_METRICS}


def _coverage_diff(prior: dict[str, Any],
                   current: dict[str, Any]) -> dict[str, Any]:
    """Per-metric baseline/current/delta, plus whether this run reached LESS.

    `fixed` means "in the baseline, absent now", which conflates a real fix
    with a surface this run never reached again. When the run tested less,
    that `fixed` list is suspect, and this says so in the data.
    """
    base, cur = _coverage_of(prior), _coverage_of(current)
    metrics = {m: {"baseline": base[m], "current": cur[m],
                   "delta": cur[m] - base[m]} for m in _COVERAGE_METRICS}
    reach_regressed = any(
        metrics[m]["delta"] < 0
        for m in ("surfaces_exercised", "unique_paths", "probes_sent"))
    return {"metrics": metrics, "reach_regressed": reach_regressed}


def _by_severity_then_title(row: dict[str, Any]) -> tuple[int, str]:
    return (-SEVERITY_RANK.get(str(row.get("severity")), -1), str(row.get("title") or ""))


def diff_against(report: dict[str, Any], baseline_path: Optional[str]) -> Optional[dict[str, Any]]:
    """New / fixed / persisted issues against a previous report.json.

    `gate()` only needs baseline identities; a diff a human reads needs the
    baseline issues' own content too, so this loads the full prior report.
    Returns `None` when there is no baseline to diff against, so a caller can
    tell "nothing changed" apart from "nothing to compare".
    """
    if not baseline_path or not os.path.isfile(baseline_path):
        return None
    prior = _read_report(baseline_path)
    if prior is None:
        return None
    prior_issues = prior.get("issues") or prior.get("all_findings") or []
    current_issues = report.get("issues") or report.get("all_findings") or []
    prior_by_id = {identity(f): f for f in prior_issues}
    current_by_id = {identity(f): f for f in current_issues}

    new_ids = set(current_by_id) - set(prior_by_id)
    fixed_ids = set(prior_by_id) - set(current_by_id)
    persisted_ids = set(current_by_id) & set(prior_by_id)

    new = sorted((_diff_summary(current_by_id[i]) for i in new_ids),
                key=_by_severity_then_title)
    fixed = sorted((_diff_summary(prior_by_id[i]) for i in fixed_ids),
                  key=_by_severity_then_title)
    persisted = sorted((_diff_summary(current_by_id[i]) for i in persisted_ids),
                       key=_by_severity_then_title)
    return {
        "baseline_run": (prior.get("run") or {}).get("id"),
        "current_run": (report.get("run") or {}).get("id"),
        "counts": {"new": len(new), "fixed": len(fixed), "persisted": len(persisted)},
        "new": new,
        # "fixed" means "present in the baseline, absent from this run" - not
        # "confirmed remediated". A surface the crawl never reached this time
        # (auth expired, a page moved, a narrower --scope) disappears the
        # same way a real fix would.
        "fixed": fixed,
        "fixed_caveat": ("absent from the current run's issues - this "
                         "includes a real fix, but also a surface this run "
                         "never reached again; it is not independently "
                         "confirmed remediated"),
        "persisted": persisted,
        # Coverage delta: did this run look at as much as the baseline? When it
        # reached less, the `fixed` list above is contaminated by unreached
        # surfaces, not only real remediations.
        "coverage": _coverage_diff(prior, report),
    }


def render_diff(diff: Optional[dict[str, Any]]) -> str:
    """A triage-ready summary, for stdout - the JSON is for tooling."""
    if diff is None:
        return "no baseline to diff against"
    counts = diff["counts"]
    lines = ["diff vs baseline: %d new, %d fixed, %d persisted"
             % (counts["new"], counts["fixed"], counts["persisted"])]
    coverage = diff.get("coverage") or {}
    if coverage.get("reach_regressed") and counts["fixed"]:
        drops = ", ".join(
            "%s %+d" % (metric, cell["delta"])
            for metric, cell in (coverage.get("metrics") or {}).items()
            if cell["delta"] < 0)
        lines.append("  ! this run reached LESS than the baseline (%s) - some "
                     "\"fixed\" may be unreached, not remediated" % drops)
    for row in diff["new"][:10]:
        lines.append("  + %-8s %s" % (row["severity"], row["title"]))
    if len(diff["new"]) > 10:
        lines.append("  ... and %d more new" % (len(diff["new"]) - 10))
    for row in diff["fixed"][:5]:
        lines.append("  - %-8s %s (no longer observed)" % (row["severity"], row["title"]))
    if len(diff["fixed"]) > 5:
        lines.append("  ... and %d more fixed" % (len(diff["fixed"]) - 5))
    return "\n".join(lines)


def _gateable(issue: dict[str, Any], include_candidates: bool) -> bool:
    """Is this issue allowed to fail a build?

    `kind` says whether a signal was proven; `bucket` is the report's own
    verdict on the issue, and the two can differ - an inventory or posture
    observation can be a proven fact about a response while being nothing a
    build should stop for.

    Gate on the report's bucket when it has one: only `vulnerability`, plus
    `validate` when the operator explicitly asked for candidates. An archived
    report, or the `all_findings` fallback above, carries no bucket - fall
    back to `kind` there rather than gating on nothing.
    """
    bucket = issue.get("bucket")
    if bucket:
        allowed = ("vulnerability", "validate") if include_candidates else ("vulnerability",)
        return bucket in allowed
    return include_candidates or issue.get("kind") == "finding"


def gate(report: dict[str, Any], fail_on: str, baseline: set[str],
         include_candidates: bool = False) -> tuple[int, list[dict[str, Any]], str]:
    """Decide the exit code.  Returns (code, offending issues, explanation).

    Gates on consolidated issues where the report has them: five signals about
    one injectable parameter is one thing to fix, and a build should not be
    five times as red for it.
    """
    if fail_on in ("", "none"):
        return EXIT_OK, [], "gating disabled"
    threshold = SEVERITY_RANK.get(fail_on.lower())
    if threshold is None:
        return EXIT_USAGE, [], f"unknown severity `{fail_on}`"

    offenders = []
    for finding in (report.get("issues") or report.get("all_findings") or []):
        if not _gateable(finding, include_candidates):
            continue
        if SEVERITY_RANK.get(str(finding.get("severity")), -1) < threshold:
            continue
        if identity(finding) in baseline:
            continue
        offenders.append(finding)

    if not offenders:
        note = f"nothing new at or above `{fail_on}`"
        if baseline:
            note += f" ({len(baseline)} known finding(s) ignored)"
        return EXIT_OK, [], note
    return (EXIT_FINDINGS, offenders,
            f"{len(offenders)} new finding(s) at or above `{fail_on}`")
