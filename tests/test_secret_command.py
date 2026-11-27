# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""`cmd:` credential indirection - the external-secrets integration (M4).

Every secret manager worth naming ships a CLI that prints one secret to
stdout, so one indirection covers all of them with no vendor SDK. The tests
that matter here are the failure modes: a vault that is down must STOP the
run, never quietly hand back "no credential".
"""

import os
import shlex
import subprocess
import sys

from tests import pytest_style

from sekuscan.agent import ci


def _cmd(script):
    """A `cmd:` value that runs THIS interpreter - no shell, no fixtures."""
    return "cmd:%s -c %s" % (_quote(sys.executable), _quote(script))


def _quote(text):
    """One argument, quoted the way the platform's command line reads it."""
    if os.name == "nt":
        return subprocess.list2cmdline([text])
    return shlex.quote(text)


def test_a_plain_value_is_returned_unchanged():
    assert ci.resolve_secret("hunter2") == "hunter2"
    assert ci.resolve_secret(None) is None
    assert ci.resolve_secret("") == ""


def test_a_command_value_is_fetched():
    assert ci.resolve_secret(_cmd("print('s3cret')")) == "s3cret"


def test_only_one_trailing_newline_is_stripped():
    """A password may legitimately start or end with a space; `.strip()`
    would turn a working credential into a login failure that looks like
    wrong credentials."""
    assert ci.resolve_secret(_cmd(r"print('  pad  ')")) == "  pad  "


def test_a_failing_command_raises_rather_than_returning_nothing():
    """The whole point. A scan that proceeds unauthenticated reports a clean
    bill of health for everything behind the login."""
    try:
        ci.resolve_secret(_cmd("import sys; sys.exit(3)"))
    except ci.SecretResolutionError as exc:
        assert "exit 3" in str(exc)
    else:
        raise AssertionError("a failing vault command must not be survivable")


def test_a_missing_command_raises():
    try:
        ci.resolve_secret("cmd:sekuscan-no-such-vault-cli-xyz --get")
    except ci.SecretResolutionError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("a missing vault CLI must not be survivable")


def test_an_empty_result_raises():
    try:
        ci.resolve_secret(_cmd("pass"))
    except ci.SecretResolutionError as exc:
        assert "produced nothing" in str(exc)
    else:
        raise AssertionError("an empty secret must not be survivable")


def test_stderr_is_reported_but_stdout_is_not():
    """On failure stdout may still hold a partial secret, and this message
    reaches logs."""
    try:
        ci.resolve_secret(_cmd(
            "import sys; print('PARTIAL-SECRET'); "
            "print('vault sealed', file=sys.stderr); sys.exit(1)"))
    except ci.SecretResolutionError as exc:
        assert "vault sealed" in str(exc)
        assert "PARTIAL-SECRET" not in str(exc)
    else:
        raise AssertionError("expected failure")


def test_no_shell_is_used():
    """An operator supplies the command, but a vault path interpolated into
    it by a pipeline is data. Under `shell=True` this would write a file."""
    marker = "cmd:%s -c %s; touch /tmp/sekuscan-shell-escape-canary" % (
        sys.executable, _quote("print('x')"))
    try:
        ci.resolve_secret(marker)
    except ci.SecretResolutionError:
        pass
    assert not os.path.exists("/tmp/sekuscan-shell-escape-canary")


def test_the_whole_precedence_resolves_it_not_just_one_source():
    """Flag, auth-file and environment must behave identically - a vault
    reference is a credential value, not a fourth source."""
    os.environ["SEKUSCAN_PASSWORD"] = _cmd("print('from-env')")
    try:
        assert ci.resolve_auth(None, None, None, None).password == "from-env"
    finally:
        del os.environ["SEKUSCAN_PASSWORD"]
    assert ci.resolve_auth(
        None, _cmd("print('from-flag')"), None, None).password == "from-flag"


def test_the_second_identity_resolves_too():
    """An access-control check compares two identities; one silently failing
    to authenticate inverts the comparison rather than failing it."""
    got = ci.resolve_secondary_auth(None, _cmd("print('second-pw')"), None)
    assert got.password == "second-pw"


def test_a_bearer_header_value_resolves_but_the_name_does_not():
    got = ci.resolve_auth(None, None, None, None,
                          headers=["Authorization=" + _cmd("print('Bearer t')")])
    assert got.headers == ["Authorization=Bearer t"]
    # `cmd:` in a NAME is a header called `cmd:`, not an instruction
    plain = ci.resolve_auth(None, None, None, None, headers=["X-A=b"])
    assert plain.headers == ["X-A=b"]


# pytest-style module-level functions; `unittest discover` (what
# `bin/sekuscan-test` runs) collects TestCase methods and nothing else.
# See `tests/pytest_style.py`. This must stay at the BOTTOM: collect()
# reads globals at the moment it runs, so a test defined below it would
# never be collected.
TestSecretCommand = pytest_style.collect(globals(), "TestSecretCommand", __doc__)
