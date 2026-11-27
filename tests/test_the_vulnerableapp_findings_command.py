# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""`sekuscan-agent vulnerableapp-findings` turns report.json into the body
the target application's `/scanner/benchmark` takes: vulnerabilities only, each
with its CWE, and a type picked from our own evidence."""

from __future__ import annotations

from tests import pytest_style
import json
import os
import tempfile

from sekuscan.agent import cli, vulnerableapp

BASE = "http://127.0.0.1:9090/the target application"
REPORT = {"issues": [
    {"kind": "finding", "bucket": "vulnerability", "vuln_class": "sqli", "cwe": 89,
     "title": "SQL error from `id`", "signals": [{"variant": "error_observed"}],
     "replay": [{"url": BASE + "/ErrorBasedSQLInjectionVulnerability/LEVEL_1?id=1", "method": "GET"}]},
    {"kind": "finding", "bucket": "vulnerability", "vuln_class": "xss", "cwe": 79,
     "title": "Stored script", "signals": [{"variant": "stored"}],
     "replay": [{"url": BASE + "/PersistentXSSInHTMLTagVulnerability/LEVEL_1", "method": "POST"}]},
    {"kind": "finding", "bucket": "vulnerability", "vuln_class": "open_redirect", "cwe": 601,
     "locations": [BASE + "/Open/LEVEL_1", BASE + "/Open/LEVEL_2"]},
    {"kind": "finding", "bucket": "hardening", "vuln_class": "headers", "cwe": 693,
     "replay": [{"url": BASE + "/"}]},
    {"kind": "candidate", "bucket": "vulnerability", "vuln_class": "sqli", "cwe": 89,
     "replay": [{"url": BASE + "/Unconfirmed/LEVEL_1"}]},
]}


def test_only_vulnerabilities_go_each_with_its_cwe_and_our_type():
    rows = vulnerableapp.findings_from(REPORT)
    assert {(r["url"], r.get("type"), r["cwe"], r["method"]) for r in rows} == {
        ("/the target application/ErrorBasedSQLInjectionVulnerability/LEVEL_1", "ERROR_BASED_SQL_INJECTION", 89, "GET"),
        ("/the target application/PersistentXSSInHTMLTagVulnerability/LEVEL_1", "PERSISTENT_XSS", 79, "POST"),
        ("/the target application/Open/LEVEL_1", "OPEN_REDIRECT_3XX_STATUS_CODE", 601, "GET"),
        ("/the target application/Open/LEVEL_2", "OPEN_REDIRECT_3XX_STATUS_CODE", 601, "GET"),
    }


def test_the_same_report_always_gives_the_same_rows():
    assert vulnerableapp.findings_from(REPORT) == vulnerableapp.findings_from(json.loads(json.dumps(REPORT)))


def test_the_command_prints_the_benchmark_body():
    import contextlib
    import io
    path = os.path.join(tempfile.mkdtemp(), "report.json")
    with open(path, "w") as fh:
        json.dump(REPORT, fh)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert cli._argparse_main(["vulnerableapp-findings", path]) == 0
    body = json.loads(out.getvalue())
    assert body["tool"] == "sekuscan" and body["scanType"] == "DAST"
    assert body["findings"] == vulnerableapp.findings_from(REPORT)


TestTheVulnerableappFindingsCommand = pytest_style.collect(
    globals(), "TestTheVulnerableappFindingsCommand", __doc__)
