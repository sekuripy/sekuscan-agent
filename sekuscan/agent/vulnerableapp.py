# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Turn a SekuScan report into OWASP VulnerableApp's scanner input.

VulnerableApp grades a scanner at its own `/scanner/benchmark` endpoint. This
module writes the body that endpoint takes, from `report.json` alone:

    sekuscan-agent vulnerableapp-findings report/report.json > findings.json
    curl -X POST -H 'Content-Type: application/json' --data @findings.json \
      http://127.0.0.1:9090/VulnerableApp/scanner/benchmark

Rules, so the score is VulnerableApp's and not ours:

* Only issues the report calls a vulnerability are sent. Hardening notes and
  unconfirmed candidates are not.
* Every finding carries its CWE, and VulnerableApp's matcher decides.
* Where VulnerableApp's type names are finer than ours, the type is picked
  from our own evidence (the finding's variant or proof), never from the
  answer key. Where our evidence cannot separate two of their types, both
  are sent, which costs an unmatched row instead of guessing.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

#: VulnerableApp's vulnerability type -> the SekuScan classes that can claim it.
THEIR_TYPES = {   'REFLECTED_XSS': ['xss'],
    'PERSISTENT_XSS': ['xss'],
    'PATH_TRAVERSAL': ['traversal'],
    'ERROR_BASED_SQL_INJECTION': ['sqli'],
    'UNION_BASED_SQL_INJECTION': ['sqli'],
    'BLIND_SQL_INJECTION': ['sqli'],
    'COMMAND_INJECTION': ['command'],
    'LDAP_INJECTION': ['ldap'],
    'XXE': ['xxe'],
    'SIMPLE_SSRF': ['ssrf'],
    'OPEN_REDIRECT_3XX_STATUS_CODE': ['open_redirect'],
    'WEB_CACHE_POISONING': ['cache_poisoning'],
    'HEADER_INJECTION': ['cache_poisoning'],
    'UNRESTRICTED_FILE_UPLOAD': ['file_upload'],
    'WEAK_CRYPTOGRAPHIC_HASH': ['secrets'],
    'INSECURE_CRYPTOGRAPHIC_STORAGE': ['secrets'],
    'USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM': ['secrets'],
    'CLIENT_SIDE_VULNERABLE_JWT': ['session'],
    'PLAINTEXT_PASSWORD_STORAGE': ['secrets'],
    'SERVER_SIDE_VULNERABLE_JWT': ['session'],
    'INSECURE_CONFIGURATION_JWT': ['session'],
    'PREDICTABLE_SESSION_ID': ['session_id'],
    'OBSCURED_PREDICTABLE_SESSION_ID': ['session_id'],
    'INSECURE_DIRECT_OBJECT_REFERENCE': ['authz'],
    'PREDICTABLE_PASSWORD_RESET_TOKEN': ['password_reset'],
    'INSECURE_PASSWORD_RESET_LINK': ['password_reset'],
    'PASSWORD_RESET_TOKEN_WITHOUT_EXPIRY': ['password_reset'],
    'MISSING_LOGOUT_INVALIDATION': ['session'],
    'WEAK_PASSWORD_HASHING': ['credential_storage'],
    'INSECURE_DESERIALIZATION': ['deserialization'],
    'WEAK_RANDOM_NUMBER_GENERATION': ['otp'],
    'NO_LOGIN_RATE_LIMITING': ['otp'],
    'REUSABLE_PASSWORD_RESET_TOKEN': ['otp'],
    'IMPROPER_AUTHORIZATION': ['deserialization']}

#: Per SekuScan class, the finding variant -> VulnerableApp type names. A class
#: listed here is decided only by this table, and a variant it does not name
#: sends no type (for example cookie flags, which none of their types cover).
VARIANT_TYPES = {   'file_upload': {   'stored_upload_rendered': ('PERSISTENT_XSS',),
                       'stored_upload_active': (   'UNRESTRICTED_FILE_UPLOAD',
                                                   'PERSISTENT_XSS'),
                       'upload_path_traversal': ('PATH_TRAVERSAL',),
                       'unrestricted_upload': ('UNRESTRICTED_FILE_UPLOAD',),
                       'extension_mismatch': ('UNRESTRICTED_FILE_UPLOAD',),
                       'upload_no_size_limit': ('UNCONTROLLED_RESOURCE_CONSUMPTION',),
                       'upload_name_xss': ('REFLECTED_XSS',),
                       'upload_name_xss_client_rendered': ('REFLECTED_XSS',)},
    'secrets': {   'weak_password_digest': ('WEAK_CRYPTOGRAPHIC_HASH',),
                   'reversible_password_storage': ('INSECURE_CRYPTOGRAPHIC_STORAGE',),
                   'legacy_cipher_password': ('USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM',),
                   'credential_reuse_confirmed': ('PLAINTEXT_PASSWORD_STORAGE',),
                   'credential_reuse_authenticated': ('PLAINTEXT_PASSWORD_STORAGE',),
                   'unencrypted_credential_storage': (   'PLAINTEXT_PASSWORD_STORAGE',
                                                         'INSECURE_CRYPTOGRAPHIC_STORAGE')},
    'session': {   'jwt_published_secret': ('CLIENT_SIDE_VULNERABLE_JWT',),
                   'jwt_alg_none': ('CLIENT_SIDE_VULNERABLE_JWT',),
                   'jwt_weak': (   'CLIENT_SIDE_VULNERABLE_JWT',
                                   'INSECURE_CONFIGURATION_JWT'),
                   'jwt_alg_none_confirmed': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_null_byte_confirmed': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_empty_token_confirmed': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_signature_unverified': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_jwk_header_injection': (   'HEADER_INJECTION',
                                                   'SERVER_SIDE_VULNERABLE_JWT'),
                   'jwt_key_confusion': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_kid_null_key_confirmed': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_jku_callback': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'jwt_claim_tamper_candidate': ('SERVER_SIDE_VULNERABLE_JWT',),
                   'fixation': ('SESSION_FIXATION',),
                   'logout_invalidation': ('MISSING_LOGOUT_INVALIDATION',)},
    'password_reset': {   'predictable_token': ('PREDICTABLE_PASSWORD_RESET_TOKEN',),
                          'short_token': ('PREDICTABLE_PASSWORD_RESET_TOKEN',),
                          'derived_token': ('PREDICTABLE_PASSWORD_RESET_TOKEN',),
                          'cleartext_reset_link': ('INSECURE_PASSWORD_RESET_LINK',),
                          'token_exposed_via_referrer': (   'PASSWORD_RESET_TOKEN_EXPOSED_VIA_REFERRER',),
                          'account_existence_disclosed': ('USERNAME_ENUMERATION',),
                          'token_without_expiry': (   'PASSWORD_RESET_TOKEN_WITHOUT_EXPIRY',)},
    'credential_storage': {'weak_hash': ('WEAK_PASSWORD_HASHING',)},
    'deserialization': {   'parser_error': ('INSECURE_DESERIALIZATION',),
                           'field_reflect': ('INSECURE_DESERIALIZATION',),
                           'status_code': ('INSECURE_DESERIALIZATION',),
                           'polymorphic_type': ('INSECURE_DESERIALIZATION',),
                           'json_field_reflect': ('INSECURE_DESERIALIZATION',),
                           'serialized_privilege_escalation': (   'IMPROPER_AUTHORIZATION',)},
    'otp': {   'short_code': ('WEAK_RANDOM_NUMBER_GENERATION',),
               'predictable_code': ('WEAK_RANDOM_NUMBER_GENERATION',),
               'issuance_unlimited': ('NO_LOGIN_RATE_LIMITING',),
               'code_reusable': ('REUSABLE_PASSWORD_RESET_TOKEN',),
               'code_without_expiry': ('PASSWORD_RESET_TOKEN_WITHOUT_EXPIRY',)},
    'session_id': {   'predictable_token': ('PREDICTABLE_SESSION_ID',),
                      'derived_token': ('OBSCURED_PREDICTABLE_SESSION_ID',)}}


def path_of(url: str) -> str:
    """The URL path, context path included: VulnerableApp strips it itself."""
    try:
        return urllib.parse.urlparse(url).path or "/"
    except ValueError:
        return url


def _types_for_class(vuln_class: str) -> list[str]:
    return [name for name, classes in THEIR_TYPES.items() if vuln_class in classes]


def submitted_types(issue: dict[str, Any]) -> list[str]:
    """VulnerableApp type names for one of our issues, from our own evidence.

        xss    a stored signal      -> PERSISTENT_XSS, else REFLECTED_XSS
        sqli   an error signature   -> ERROR_BASED_SQL_INJECTION
               a UNION proof        -> UNION_BASED_SQL_INJECTION
               boolean or timing    -> BLIND_SQL_INJECTION

    Every variant on the issue is read, in sorted order, so the same report
    always gives the same answer.
    """
    vuln_class = str(issue.get("vuln_class") or "")
    candidates = _types_for_class(vuln_class)
    if not candidates:
        return []
    blob = " ".join(str(issue.get(key) or "") for key in
                    ("title", "summary", "proof", "decisive_proof")).lower()
    variants = {str(s.get("variant") or "").lower()
                for s in (issue.get("signals") or [])}
    if vuln_class == "xss":
        return ["PERSISTENT_XSS"] if ("stored" in variants or "stored" in blob) else ["REFLECTED_XSS"]
    if issue.get("variant"):
        variants.add(str(issue["variant"]).lower())
    table = VARIANT_TYPES.get(vuln_class)
    if table is not None:
        out: list[str] = []
        for name in sorted(variants):
            for kind in table.get(name, ()):
                if kind not in out:
                    out.append(kind)
        return out
    if vuln_class == "sqli":
        # the variant first: one issue collects every finding on its URL
        if "error_observed" in variants:
            return ["ERROR_BASED_SQL_INJECTION"]
        if "union" in blob:
            return ["UNION_BASED_SQL_INJECTION"]
        if "error" in blob:
            return ["ERROR_BASED_SQL_INJECTION"]
        if "boolean" in blob or "timing" in blob or "blind" in blob:
            return ["BLIND_SQL_INJECTION"]
    return candidates


def findings_from(report: dict[str, Any],
                  include_candidates: bool = False) -> list[dict[str, Any]]:
    """The report's vulnerabilities, one row per (path, type, CWE, method)."""
    out: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for issue in (report.get("issues") or []):
        if not include_candidates and issue.get("kind") != "finding":
            continue
        if issue.get("bucket") and issue["bucket"] != "vulnerability":
            continue
        cwe = issue.get("cwe")
        types = submitted_types(issue)
        if not cwe and not types:
            continue
        steps = list(issue.get("replay") or [])
        # An issue on several routes lists them all in `locations`.
        if not issue.get("path") and issue.get("locations"):
            known_methods = {}
            for replay in steps:
                known_methods[path_of(replay.get("url") or "")] = str(
                    replay.get("method") or "GET").upper()
            for location in issue.get("locations") or []:
                if not location:
                    continue
                if any((s.get("url") or "") == location for s in steps):
                    continue
                steps.append({"step": "request", "url": location,
                              "method": known_methods.get(path_of(location), "GET")})
        for step in steps or [{}]:
            url = step.get("url") or issue.get("target") or ""
            if not url:
                continue
            method = str(step.get("method") or "GET").upper()
            for kind in (types or [None]):
                key = (path_of(url), kind, cwe, method)
                if key in seen:
                    continue
                seen.add(key)
                row = {"url": key[0], "cwe": cwe, "method": method,
                       "wascId": issue.get("wasc_id")}
                if kind:
                    row["type"] = kind
                out.append(row)
    return out


def benchmark_body(report: dict[str, Any]) -> dict[str, Any]:
    """What `POST /scanner/benchmark` takes."""
    return {"tool": "sekuscan", "scanType": "DAST", "findings": findings_from(report)}


def main(report_path: str) -> int:
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    print(json.dumps(benchmark_body(report), indent=2))
    return 0
